// Copyright (C) 2026 DiamaneOS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The fsvmd services (`fsvmd_launcher --slot <slot>`, started by init from fsvmd.rc): one service per slot, one
//! probe, six served volumes and four OBB images, each with a user of its own from the vendor's OEM range
//! (config.fs). vold asks a free slot's service over `/dev/socket/fsvmd_<slot>` for one fsvmd, and the service
//! starts it. init runs the service as its slot's user without capabilities, and the fsvmd it starts inherits exactly
//! that, so vold changes no ids and needs neither setuid nor setgid, no fsvmd runs as the system user, and no two
//! share a user: one fsvmd cannot signal or trace another. The service is a binary and an SELinux domain of its own
//! (`fsvmd_launcher`), and each fsvmd enters `fsvmd` (or `fsvmd_obb`) on exec, so a fsvmd cannot signal or trace the
//! service either.
//!
//! One request per connection, one SOCK_SEQPACKET message: `FSVMD1\0`, one digit whose bits say which descriptors
//! follow (1: descriptor 3, the disk or OBB file, 2: descriptor 4, /dev/fuse, 4: descriptor 5, the pipe to vold) and
//! `\0`, then fsvmd's arguments, each ended by `\0`. The descriptors come in SCM_RIGHTS in that order. Answers, one
//! message each: `P <pid>` once fsvmd runs, `X <status>` when it ended (its exit code, or 128 plus the signal), or
//! `E <errno>` when it could not be started. vold may send `T` (stop), `K` (kill) or `W` (write back now). When
//! vold closes the connection, for example because vold itself ended, its fsvmd is asked to stop and killed 3 s
//! later. The service signals only its own child, through a pidfd, so a pid that was reused can never be hit. A slot
//! runs one fsvmd at a time, and refuses a second request with `E EBUSY` (vold then asks the next slot). The OBB
//! slots run `fsvmd_obb` and take only OBB requests, the probe slot only probes, the volume slots only volumes.

use anyhow::{bail, ensure, Context, Result};
use log::{info, warn};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The fsvmd binary the service runs for each request, and the one for OBB images (its own domain, no card access,
/// outside the VM memory pool).
pub const FSVMD: &str = "/system_ext/bin/fsvmd";
pub const FSVMD_OBB: &str = "/system_ext/bin/fsvmd_obb";
const SOCKET_ENV: &str = "ANDROID_SOCKET_fsvmd";
const MAGIC: &[u8] = b"FSVMD1";
const MAX_REQUEST: usize = 4096;
const MAX_ARGS: usize = 32;
/// One fsvmd per slot (run_on's `max_children`): vold allows one probe, 6 served volumes and 4 OBB images at a time,
/// one slot each.
const MAX_CHILDREN: usize = 1;
/// The slots, as fsvmd.rc and config.fs name them.
pub const SLOTS: &[&str] = &["probe", "0", "1", "2", "3", "4", "5", "obb_0", "obb_1", "obb_2", "obb_3"];
/// After vold went away, fsvmd gets this long for its orderly stop (it writes back in up to 1.8 s) before a kill.
const VOLD_GONE_GRACE: Duration = Duration::from_secs(3);
/// vold sends its request right after connecting.
const REQUEST_WITHIN: Duration = Duration::from_secs(5);


/// Which requests a slot takes (checked in `handle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Probe,
    Volume,
    Obb,
    /// The host tests: anything.
    #[allow(dead_code)]
    Any,
}

pub fn slot_kind(slot: &str) -> Result<SlotKind> {
    ensure!(SLOTS.contains(&slot), "unknown slot {slot}");
    Ok(if slot == "probe" {
        SlotKind::Probe
    } else if slot.starts_with("obb_") {
        SlotKind::Obb
    } else {
        SlotKind::Volume
    })
}

/// Runs a slot's service on init's socket, for ever: requests from root (vold) only. The service runs as its slot's
/// own user (fsvmd.rc), never as root or the system user.
pub fn run(slot: &str) -> Result<()> {
    let kind = slot_kind(slot)?;
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    ensure!(uid != 0 && uid != 1000, "the fsvmd_{slot} service runs as uid {uid}, not its slot's own user");
    let env = format!("{SOCKET_ENV}_{slot}");
    let fd: RawFd = std::env::var(&env).context("no socket from init")?.parse().context("socket from init")?;
    let exe = if kind == SlotKind::Obb { FSVMD_OBB } else { FSVMD };
    // SAFETY: init created this socket for the service, and nothing else in this process uses it.
    run_on(unsafe { OwnedFd::from_raw_fd(fd) }, exe, kind, 0, MAX_CHILDREN)
}

/// Accepts requests of `kind` on `listener` from `allowed_uid` and runs `exe` for each, at most `max_children` at a
/// time.
pub fn run_on(listener: OwnedFd, exe: &'static str, kind: SlotKind, allowed_uid: u32, max_children: usize) -> Result<()> {
    let limit = Limit::new(max_children);
    let fd = listener.as_raw_fd();
    // SAFETY: F_SETFD only changes the descriptor flags of the socket.
    ensure!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0, "F_SETFD on the socket");
    // init listens on the stream and seqpacket sockets it creates. Listening again only sets the backlog, so the
    // service does not depend on that.
    // SAFETY: listen on the socket this process owns.
    ensure!(unsafe { libc::listen(fd, 16) } == 0, "listen: {}", std::io::Error::last_os_error());
    // fsvmd children are reaped here, through their pidfds. SIGCHLD ignored would reap them behind its back.
    // SAFETY: restores the default disposition of SIGCHLD, before any child exists.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    info!("fsvmd service ready");
    loop {
        // SAFETY: accept4 on the listening socket this process owns, without the peer's address.
        let c = unsafe {
            libc::accept4(listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC)
        };
        if c < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                warn!("accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
            continue;
        }
        // SAFETY: accept4 returned a new descriptor that nothing else owns.
        let conn = unsafe { OwnedFd::from_raw_fd(c) };
        // SELinux lets only vold connect (fsvmd.te). vold runs as root, so anything else is refused here too.
        match peer_uid(&conn) {
            Ok(uid) if uid == allowed_uid => {}
            Ok(uid) => {
                warn!("request from uid {uid} refused");
                continue;
            }
            Err(e) => {
                warn!("request refused: {e:?}");
                continue;
            }
        }
        let limit = limit.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(conn, exe, kind, &limit) {
                warn!("request: {e:?}");
            }
        });
    }
}

fn peer_uid(conn: &OwnedFd) -> Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED writes at most `len` bytes into `cred`.
    let r = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    ensure!(r == 0, "SO_PEERCRED: {}", std::io::Error::last_os_error());
    Ok(cred.uid)
}

/// The running children of one service and how many it may run.
#[derive(Clone)]
pub struct Limit {
    running: Arc<AtomicUsize>,
    max: usize,
}

impl Limit {
    pub fn new(max: usize) -> Self {
        Limit { running: Arc::new(AtomicUsize::new(0)), max }
    }
}

/// Keeps the count of running children, released when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(limit: &Limit) -> Option<Slot> {
        if limit.running.fetch_add(1, Ordering::SeqCst) >= limit.max {
            limit.running.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(limit.running.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves one connection: one request, then the child's life. `exe` is FSVMD or FSVMD_OBB, except in the host test.
pub fn handle(conn: OwnedFd, exe: &str, kind: SlotKind, limit: &Limit) -> Result<()> {
    ensure!(wait_readable(&conn, REQUEST_WITHIN)?, "no request");
    let (data, fds) = receive(&conn)?;
    let (mask, argv) = match parse(&data, fds.len(), exe).and_then(|r| fits(kind, &r.1).map(|_| r)) {
        Ok(r) => r,
        Err(e) => {
            send(&conn, &format!("E {}", libc::EINVAL));
            return Err(e);
        }
    };
    let Some(_slot) = Slot::take(limit) else {
        send(&conn, &format!("E {}", libc::EBUSY));
        bail!("this slot runs a fsvmd already");
    };
    let pid = match spawn(&argv, mask, &fds) {
        Ok(pid) => pid,
        Err(e) => {
            send(&conn, &format!("E {}", e.raw_os_error().unwrap_or(libc::EIO)));
            bail!("fork: {e}");
        }
    };
    // The child has its copies. Ours go, so that the child alone holds the disk, FUSE and the pipe.
    drop(fds);
    info!("fsvmd {pid} started: {}", argv.get(1).map(|a| a.to_string_lossy()).unwrap_or_default());
    supervise(&conn, pid)
}

fn wait_readable(fd: &OwnedFd, within: Duration) -> Result<bool> {
    let mut p = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    loop {
        // SAFETY: poll on one pollfd of a descriptor this process owns.
        let r = unsafe { libc::poll(&mut p, 1, within.as_millis() as libc::c_int) };
        if r >= 0 {
            return Ok(r == 1 && p.revents & libc::POLLIN != 0);
        }
        let e = std::io::Error::last_os_error();
        ensure!(e.raw_os_error() == Some(libc::EINTR), "poll: {e}");
    }
}

/// Reads the request and takes every descriptor that came with it, so each one is closed whatever is refused later.
fn receive(conn: &OwnedFd) -> Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut data = vec![0u8; MAX_REQUEST];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE((3 * std::mem::size_of::<RawFd>()) as libc::c_uint) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    // SAFETY: an all-zero msghdr is valid, its pointers are set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: recvmsg writes into `data` and `control` within the lengths given in `msg`.
    let n = unsafe { libc::recvmsg(conn.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
    ensure!(n >= 0, "recvmsg: {}", std::io::Error::last_os_error());
    let mut fds = Vec::new();
    // SAFETY: the CMSG_* walk stays inside the control buffer recvmsg filled, as msg_controllen says.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let p = libc::CMSG_DATA(c) as *const RawFd;
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(p.add(i).read_unaligned()));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    ensure!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0, "request or descriptors cut off");
    data.truncate(n as usize);
    Ok((data, fds))
}

/// Checks a request: the descriptor bits must match the descriptors, and the arguments go to fsvmd unchanged (fsvmd
/// checks them itself). Returns the bits and fsvmd's argv.
pub fn parse(data: &[u8], fds: usize, exe: &str) -> Result<(u8, Vec<CString>)> {
    ensure!(data.last() == Some(&0), "request not ended by NUL");
    let fields: Vec<&[u8]> = data[..data.len() - 1].split(|b| *b == 0).collect();
    ensure!(fields.len() >= 2 && fields[0] == MAGIC, "not a request");
    ensure!(fields[1].len() == 1 && (b'0'..=b'7').contains(&fields[1][0]), "descriptor bits");
    let mask = fields[1][0] - b'0';
    ensure!(mask.count_ones() as usize == fds, "{fds} descriptors for bits {mask}");
    let args = &fields[2..];
    ensure!(!args.is_empty() && args.len() <= MAX_ARGS, "{} arguments", args.len());
    ensure!(!args.iter().any(|a| *a == b"--launcher" || *a == b"--slot"), "a request for the service itself");
    // An OBB image is served by fsvmd_obb from an OBB slot, everything else by fsvmd.
    ensure!(!(exe == FSVMD && args[0] == b"--obb"), "an OBB request on a card slot");
    ensure!(!(exe == FSVMD_OBB && args[0] != b"--obb"), "a card request on an OBB slot");
    let mut argv = vec![CString::new(exe)?];
    for a in args {
        argv.push(CString::new(*a)?);
    }
    Ok((mask, argv))
}

/// Whether a request fits the slot: probes on the probe slot, volumes on the volume slots, OBB images on the OBB slots.
pub fn fits(kind: SlotKind, argv: &[CString]) -> Result<()> {
    let first = argv.get(1).map(|a| a.as_bytes()).unwrap_or_default();
    let ok = match kind {
        SlotKind::Any => true,
        // A format of a card's volume in its VM runs where probes run: one at a time, under vold's lock.
        SlotKind::Probe => first == b"--probe" || first == b"--format",
        SlotKind::Obb => first == b"--obb",
        SlotKind::Volume => first != b"--probe" && first != b"--obb" && first != b"--format",
    };
    ensure!(ok, "a {} request on a {kind:?} slot", String::from_utf8_lossy(first));
    Ok(())
}

/// Forks and runs `argv` with the descriptors in the slots `mask` names as 3, 4 and 5, and no others above 2.
fn spawn(argv: &[CString], mask: u8, fds: &[OwnedFd]) -> std::io::Result<libc::pid_t> {
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let mut slots: [RawFd; 3] = [-1; 3];
    let mut it = fds.iter();
    for (i, s) in slots.iter_mut().enumerate() {
        if mask & (1 << i) != 0 {
            *s = it.next().map(|f| f.as_raw_fd()).unwrap_or(-1);
        }
    }
    // SAFETY: the child only calls async-signal-safe functions on data prepared before the fork (in_child).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: this is the child of the fork above.
        unsafe { in_child(&slots, &ptrs) }
    }
    Ok(pid)
}

/// In the forked child: fcntl, dup2, close, close_range, execv and _exit only.
unsafe fn in_child(slots: &[RawFd; 3], argv: &[*const libc::c_char]) -> ! {
    let mut high: [RawFd; 3] = [-1; 3];
    for i in 0..3 {
        if slots[i] >= 0 {
            high[i] = libc::fcntl(slots[i], libc::F_DUPFD, 10);
            if high[i] < 0 {
                libc::_exit(127);
            }
        }
    }
    for i in 0..3 {
        let target = 3 + i as RawFd;
        if high[i] >= 0 {
            // dup2 leaves the new descriptor without close-on-exec.
            if libc::dup2(high[i], target) < 0 {
                libc::_exit(127);
            }
        } else {
            libc::close(target);
        }
    }
    if libc::syscall(libc::SYS_close_range, 6 as libc::c_uint, libc::c_uint::MAX, 0 as libc::c_uint) != 0 {
        // A kernel without close_range: every descriptor up to the limit, one by one.
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let top = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 { rl.rlim_cur.min(1 << 16) as RawFd } else { 1024 };
        for fd in 6..top {
            libc::close(fd);
        }
    }
    libc::execv(argv[0], argv.as_ptr());
    libc::_exit(127)
}

fn send(conn: &OwnedFd, text: &str) {
    // SAFETY: send reads `text` within its length. A vold that is gone gets nothing, and no SIGPIPE.
    unsafe { libc::send(conn.as_raw_fd(), text.as_ptr().cast(), text.len(), libc::MSG_NOSIGNAL) };
}

fn signal(pidfd: &OwnedFd, sig: libc::c_int) {
    // SAFETY: pidfd_send_signal on a pidfd of this process's own child, not reaped yet.
    unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), sig, std::ptr::null::<libc::siginfo_t>(), 0)
    };
}

/// Passes vold's stop and kill to the child, kills it when vold goes away, and reports how it ended.
fn supervise(conn: &OwnedFd, pid: libc::pid_t) -> Result<()> {
    // SAFETY: `pid` is this process's own child and not reaped yet, so it names that child.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
    if raw < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: as above, the pid still names the unreaped child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reap(pid);
        send(conn, &format!("E {}", e.raw_os_error().unwrap_or(libc::EIO)));
        bail!("pidfd_open: {e}");
    }
    // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    send(conn, &format!("P {pid}"));
    let mut vold_gone = false;
    // When vold is gone: a stop request (fsvmd writes its volume back), and a kill if it is still there after
    // VOLD_GONE_GRACE.
    let mut kill_at: Option<std::time::Instant> = None;
    loop {
        let mut p = [
            libc::pollfd { fd: pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: if vold_gone { -1 } else { conn.as_raw_fd() }, events: libc::POLLIN, revents: 0 },
        ];
        let timeout = match kill_at {
            None => -1,
            Some(t) => {
                let left = t.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    signal(&pidfd, libc::SIGKILL);
                    kill_at = None;
                    continue;
                }
                left.as_millis().max(1) as libc::c_int
            }
        };
        // SAFETY: poll on two pollfds of descriptors this process owns.
        if unsafe { libc::poll(p.as_mut_ptr(), 2, timeout) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // Never leave the child running unwatched or unreaped.
            signal(&pidfd, libc::SIGKILL);
            let status = reap(pid);
            send(conn, &format!("X {status}"));
            bail!("poll: {e}");
        }
        if p[0].revents != 0 {
            break;
        }
        if p[1].revents == 0 {
            continue;
        }
        let mut b = [0u8; 8];
        // SAFETY: recv writes at most b.len() bytes into `b`.
        let n = unsafe { libc::recv(conn.as_raw_fd(), b.as_mut_ptr().cast(), b.len(), libc::MSG_DONTWAIT) };
        if n > 0 {
            match b[0] {
                b'T' => signal(&pidfd, libc::SIGTERM),
                b'K' => signal(&pidfd, libc::SIGKILL),
                // Write back now: the volume goes (vold stops several volumes of a disk together).
                b'W' => signal(&pidfd, libc::SIGUSR1),
                _ => {}
            }
        } else if n == 0 || p[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            info!("vold closed the connection of fsvmd {pid}, stopping it");
            signal(&pidfd, libc::SIGTERM);
            kill_at = Some(std::time::Instant::now() + VOLD_GONE_GRACE);
            vold_gone = true;
        }
    }
    let status = reap(pid);
    info!("fsvmd {pid} ended: {status}");
    send(conn, &format!("X {status}"));
    Ok(())
}

/// Reaps the child: its exit code, or 128 plus the signal that ended it.
fn reap(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: waitpid on this process's own child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 255;
        }
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        255
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn pair() -> (OwnedFd, OwnedFd) {
        let mut sv = [0; 2];
        // SAFETY: socketpair writes two new descriptors into `sv`.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) }, 0);
        // SAFETY: both are new descriptors nothing else owns.
        unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) }
    }

    fn pipe() -> (std::fs::File, OwnedFd) {
        let mut p = [0; 2];
        // SAFETY: pipe2 writes two new descriptors into `p`.
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both are new descriptors nothing else owns.
        unsafe { (std::fs::File::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) }
    }

    /// Sends a request like vold's (fs/Fsvm.cpp Spawn).
    fn request(s: &OwnedFd, mask: u8, args: &[&str], fds: &[RawFd]) {
        let mut m = MAGIC.to_vec();
        m.push(0);
        m.push(b'0' + mask);
        m.push(0);
        for a in args {
            m.extend_from_slice(a.as_bytes());
            m.push(0);
        }
        let mut iov = libc::iovec { iov_base: m.as_mut_ptr().cast(), iov_len: m.len() };
        let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as libc::c_uint) } as usize;
        let mut control = vec![0u64; space.div_ceil(8).max(1)];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as libc::c_uint) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c) as *mut RawFd, fds.len());
            }
        }
        assert_eq!(unsafe { libc::sendmsg(s.as_raw_fd(), &msg, 0) }, m.len() as isize);
    }

    fn answer(s: &OwnedFd) -> String {
        let mut b = [0u8; 64];
        let n = unsafe { libc::recv(s.as_raw_fd(), b.as_mut_ptr().cast(), b.len(), 0) };
        assert!(n >= 0);
        String::from_utf8_lossy(&b[..n as usize]).into_owned()
    }

    fn run_service(conn: OwnedFd) -> std::thread::JoinHandle<Result<()>> {
        std::thread::spawn(move || handle(conn, "/bin/sh", SlotKind::Any, &Limit::new(8)))
    }

    #[test]
    fn runs_with_exactly_the_descriptors_given() {
        let (vold, svc) = pair();
        let t = run_service(svc);
        let (mut rd, wr) = pipe();
        // Descriptor 5 is the pipe. 3 and 4 are not open, and nothing above 5 is (the test runner has some).
        let script = "echo ok >&5; for n in 3 4 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
                      [ -e /proc/$$/fd/$n ] && echo open $n >&5; done; true";
        request(&vold, 4, &["-c", script], &[wr.as_raw_fd()]);
        drop(wr);
        assert!(answer(&vold).starts_with("P "));
        let mut out = String::new();
        rd.read_to_string(&mut out).unwrap();
        assert_eq!(out, "ok\n");
        assert_eq!(answer(&vold), "X 0");
        t.join().unwrap().unwrap();
    }

    #[test]
    fn exit_codes_and_kill() {
        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 0, &["-c", "exit 3"], &[]);
        assert!(answer(&vold).starts_with("P "));
        assert_eq!(answer(&vold), "X 3");
        t.join().unwrap().unwrap();

        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 0, &["-c", "exec sleep 30"], &[]);
        assert!(answer(&vold).starts_with("P "));
        unsafe { libc::send(vold.as_raw_fd(), b"K".as_ptr().cast(), 1, 0) };
        assert_eq!(answer(&vold), format!("X {}", 128 + libc::SIGKILL));
        t.join().unwrap().unwrap();

        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 0, &["-c", "exec sleep 30"], &[]);
        assert!(answer(&vold).starts_with("P "));
        unsafe { libc::send(vold.as_raw_fd(), b"T".as_ptr().cast(), 1, 0) };
        assert_eq!(answer(&vold), format!("X {}", 128 + libc::SIGTERM));
        t.join().unwrap().unwrap();
    }

    #[test]
    fn vold_gone_kills_the_child() {
        // A child that ignores the stop request is killed after the grace time.
        let (vold, svc) = pair();
        let t = run_service(svc);
        let (rd, wr) = pipe();
        request(&vold, 4, &["-c", "trap '' TERM; echo ready >&5; exec sleep 30"], &[wr.as_raw_fd()]);
        drop(wr);
        assert!(answer(&vold).starts_with("P "));
        // Only once the child ignores SIGTERM.
        let mut rd = std::io::BufReader::new(rd);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut rd, &mut line).unwrap();
        assert_eq!(line, "ready\n");
        let start = std::time::Instant::now();
        drop(vold);
        t.join().unwrap().unwrap();
        // The child held the pipe's write end, so EOF means it is gone.
        let mut out = Vec::new();
        rd.read_to_end(&mut out).unwrap();
        assert!(start.elapsed() >= VOLD_GONE_GRACE && start.elapsed() < Duration::from_secs(6));
    }

    #[test]
    fn vold_gone_stops_the_child_first() {
        // A child that writes back on SIGTERM gets to do it: the stop request comes first.
        let (vold, svc) = pair();
        let t = run_service(svc);
        let (rd, wr) = pipe();
        request(&vold, 4, &["-c", "trap 'echo stopped >&5; exit 0' TERM; echo ready >&5; sleep 30 5>&- & wait"], &[wr.as_raw_fd()]);
        drop(wr);
        assert!(answer(&vold).starts_with("P "));
        // Only once the child's handler is in place.
        let mut rd = std::io::BufReader::new(rd);
        let mut out = String::new();
        std::io::BufRead::read_line(&mut rd, &mut out).unwrap();
        assert_eq!(out, "ready\n");
        drop(vold);
        t.join().unwrap().unwrap();
        out.clear();
        rd.read_to_string(&mut out).unwrap();
        assert_eq!(out, "stopped\n");
    }

    /// The service listens itself: a socket that was bound but never listened on still takes vold's connection.
    #[test]
    fn run_listens_and_serves() {
        let dir = std::env::temp_dir().join(format!("fsvmd-launcher-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("sock");
        let _ = std::fs::remove_file(&path);
        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: a new socket, bound to a path of our own.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in cpath.as_bytes().iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        assert_eq!(unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) }, 0);
        let listener = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        std::thread::spawn(move || run_on(listener, "/bin/sh", SlotKind::Any, me, 1));
        let mut vold = None;
        for _ in 0..50 {
            let c = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
            if unsafe { libc::connect(c, (&addr as *const libc::sockaddr_un).cast(), len) } == 0 {
                vold = Some(unsafe { OwnedFd::from_raw_fd(c) });
                break;
            }
            unsafe { libc::close(c) };
            std::thread::sleep(Duration::from_millis(20));
        }
        let vold = vold.expect("the service never listened");
        request(&vold, 0, &["-c", "sleep 1"], &[]);
        assert!(answer(&vold).starts_with("P "));
        // One fsvmd per slot: a second request while the first runs is refused, so vold asks the next slot.
        let mut second = None;
        for _ in 0..50 {
            let c = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
            if unsafe { libc::connect(c, (&addr as *const libc::sockaddr_un).cast(), len) } == 0 {
                second = Some(unsafe { OwnedFd::from_raw_fd(c) });
                break;
            }
            unsafe { libc::close(c) };
        }
        let second = second.expect("second connection");
        request(&second, 0, &["-c", "exit 0"], &[]);
        assert_eq!(answer(&second), format!("E {}", libc::EBUSY));
        assert_eq!(answer(&vold), "X 0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refused_requests() {
        let (_, wr) = pipe();
        // Bits that do not match the descriptors, before anything runs.
        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 1, &["-c", "true"], &[]);
        assert_eq!(answer(&vold), format!("E {}", libc::EINVAL));
        assert!(t.join().unwrap().is_err());
        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 0, &["-c", "true"], &[wr.as_raw_fd()]);
        assert_eq!(answer(&vold), format!("E {}", libc::EINVAL));
        assert!(t.join().unwrap().is_err());
        // The service itself is never started again.
        let (vold, svc) = pair();
        let t = run_service(svc);
        request(&vold, 0, &["--launcher"], &[]);
        assert_eq!(answer(&vold), format!("E {}", libc::EINVAL));
        assert!(t.join().unwrap().is_err());
        assert!(parse(b"FSVMD1\x000\x00--probe", 0, FSVMD).is_err());
        assert!(parse(b"FSVMD2\x000\x00--probe\x00", 0, FSVMD).is_err());
        assert!(parse(b"FSVMD1\x008\x00--probe\x00", 0, FSVMD).is_err());
        assert!(parse(b"FSVMD1\x000\x00", 0, FSVMD).is_err());
        let (mask, argv) = parse(b"FSVMD1\x005\x00--probe\x00--disk-bytes\x00512\x00", 2, FSVMD).unwrap();
        assert_eq!(mask, 5);
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[0].to_str().unwrap(), FSVMD);
        // OBB images run fsvmd_obb on an OBB slot, never fsvmd, and an OBB slot runs nothing else.
        assert!(parse(b"FSVMD1\x005\x00--obb\x00--volume\x00obb:1\x00", 2, FSVMD).is_err());
        let (_, argv) = parse(b"FSVMD1\x005\x00--obb\x00--volume\x00obb:1\x00", 2, FSVMD_OBB).unwrap();
        assert_eq!(argv[0].to_str().unwrap(), FSVMD_OBB);
        assert!(parse(b"FSVMD1\x005\x00--volume\x00public:179,1\x00", 2, FSVMD_OBB).is_err());
        assert!(parse(b"FSVMD1\x000\x00--slot\x00probe\x00", 0, FSVMD).is_err());
        // Each slot takes its own kind of request.
        let argv = |a: &[&str]| -> Vec<CString> {
            std::iter::once(FSVMD).chain(a.iter().copied()).map(|s| CString::new(s).unwrap()).collect()
        };
        assert!(fits(SlotKind::Probe, &argv(&["--probe"])).is_ok());
        assert!(fits(SlotKind::Probe, &argv(&["--volume", "x"])).is_err());
        assert!(fits(SlotKind::Probe, &argv(&["--format", "exfat"])).is_ok());
        assert!(fits(SlotKind::Volume, &argv(&["--format", "exfat"])).is_err());
        assert!(fits(SlotKind::Volume, &argv(&["--volume", "x"])).is_ok());
        assert!(fits(SlotKind::Volume, &argv(&["--probe"])).is_err());
        assert!(fits(SlotKind::Volume, &argv(&["--obb"])).is_err());
        assert!(fits(SlotKind::Obb, &argv(&["--obb"])).is_ok());
        assert!(fits(SlotKind::Obb, &argv(&["--probe"])).is_err());
        assert_eq!(slot_kind("probe").unwrap(), SlotKind::Probe);
        assert_eq!(slot_kind("3").unwrap(), SlotKind::Volume);
        assert_eq!(slot_kind("obb_2").unwrap(), SlotKind::Obb);
        assert!(slot_kind("6").is_err() && slot_kind("../x").is_err());
        // No request at all.
        let (vold, svc) = pair();
        drop(vold);
        assert!(handle(svc, "/bin/sh", SlotKind::Any, &Limit::new(8)).is_err());
    }
}
