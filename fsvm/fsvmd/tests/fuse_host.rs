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

//! fsvmd's FUSE side against the host's real FUSE driver: a mount with exactly vold's options (fs/Fsvm.cpp Mount)
//! in a user and mount namespace of its own, served by fsvmd's FsvmFs through fs::serve_fuse, with an in-memory
//! filesystem VM on the other end of a socket pair. Files are written, read back, listed, renamed and removed
//! through the kernel, in requests of the most one protocol READ or WRITE carries.
//!
//! Every earlier test spoke the protocol only. The first real mount (user set 20261118-user-766dae2a84) ended its
//! FUSE loop right after INIT: the kernel was told max_write 1 MiB and refused the loop's 128 KiB reads with EINVAL.
//! This test fails that way on the old code.
//!
//! The thread serving FUSE runs under fsvmd's seccomp filter (fsvmd/src/seccomp.rs), with calls outside its list
//! reported to a supervisor thread (SECCOMP_RET_USER_NOTIF) and let through: the test fails and names them, so the
//! list covers the FUSE and protocol path. `--trace` runs with an empty list and prints every call made.
//!
//! No test harness: the namespaces need a process of one thread, so main() starts itself again inside them. Without
//! user namespaces or /dev/fuse on the host it prints SKIPPED and exits 0, and the build log shows it.

#[allow(dead_code)]
#[path = "../src/fs.rs"]
mod fs;
#[allow(dead_code)]
#[path = "../src/seccomp.rs"]
mod seccomp;

use fsvm_proto::{encode_attr, encode_dir_page, Attr, Client, Deadlines, Kind, StreamTransport, MAX_IO, RSP_MAGIC};
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

const CHILD: &str = "FSVMD_FUSE_TEST_CHILD";
const ROOT_GUEST: u64 = 1;

fn main() {
    if std::env::var_os(CHILD).is_some() {
        std::process::exit(match child() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("fsvmd_fuse_test: FAIL: {e}");
                1
            }
        });
    }
    if !std::path::Path::new("/dev/fuse").exists() {
        println!("fsvmd_fuse_test: SKIPPED: no /dev/fuse on this host");
        return;
    }
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("0 {uid} 1");
    let gid_map = format!("0 {gid} 1");
    let mut cmd = Command::new(std::env::current_exe().expect("own path"));
    cmd.env(CHILD, "1");
    cmd.args(std::env::args().skip(1));
    // SAFETY: the closure runs in the forked child before exec and only makes system calls on memory prepared
    // before the fork.
    unsafe {
        cmd.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            write_proc(c"/proc/self/uid_map", uid_map.as_bytes())?;
            write_proc(c"/proc/self/setgroups", b"deny")?;
            write_proc(c"/proc/self/gid_map", gid_map.as_bytes())?;
            Ok(())
        });
    }
    match cmd.status() {
        Ok(s) if s.success() => println!("fsvmd_fuse_test: PASS"),
        Ok(s) => {
            eprintln!("fsvmd_fuse_test: FAIL ({s})");
            std::process::exit(1);
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EINVAL) | Some(libc::ENOSPC)) => {
            println!("fsvmd_fuse_test: SKIPPED: no user namespace on this host ({e})");
        }
        Err(e) => {
            eprintln!("fsvmd_fuse_test: FAIL: starting the child: {e}");
            std::process::exit(1);
        }
    }
}

fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> std::io::Result<()> {
    // SAFETY: plain system calls on a valid path and buffer.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        let e = std::io::Error::last_os_error();
        libc::close(fd);
        if n != data.len() as isize {
            return Err(e);
        }
    }
    Ok(())
}

fn check(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

struct NoRestart;

impl fs::Session for NoRestart {
    fn restart(&mut self) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        anyhow::bail!("the test VM does not restart")
    }
    fn stop_vm(&mut self, _within: Duration) {}
}

fn child() -> Result<(), String> {
    let mnt = std::env::temp_dir().join(format!("fsvmd-fuse-test-{}", std::process::id()));
    std::fs::create_dir_all(&mnt).map_err(|e| format!("mount point: {e}"))?;
    let r = mounted(&mnt);
    let _ = std::fs::remove_dir(&mnt);
    r
}

fn mounted(mnt: &std::path::Path) -> Result<(), String> {
    let target = CString::new(mnt.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: plain system calls on valid strings.
    unsafe {
        if libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
            return Err(format!("private mounts: {}", std::io::Error::last_os_error()));
        }
    }
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").map_err(|e| format!("/dev/fuse: {e}"))?;
    use std::os::fd::AsRawFd;
    // vold's options and flags for a card (fs/Fsvm.cpp Mount), group 0 here.
    let opts = CString::new(format!(
        "fd={},rootmode=40000,default_permissions,allow_other,user_id=0,group_id=0,max_read=131072",
        dev.as_raw_fd()
    ))
    .unwrap();
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOATIME;
    // SAFETY: plain system call on valid strings.
    if unsafe { libc::mount(c"/dev/fuse".as_ptr(), target.as_ptr(), c"fuse".as_ptr(), flags, opts.as_ptr().cast()) } != 0 {
        return Err(format!("mounting FUSE: {}", std::io::Error::last_os_error()));
    }

    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    std::thread::spawn(move || FakeVm::new().serve(vm_end));
    let client = Client::new(StreamTransport(our_end), Deadlines::default());
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, false, 0, false, false, Box::new(NoRestart));
    let (done_tx, done_rx) = mpsc::channel();
    let trace = std::env::args().any(|a| a == "--trace");
    // The listener goes over an atomic, not a channel: with an empty list (--trace) every system call of the FUSE
    // thread waits for the supervisor, which must not need one of them to start.
    let listener_fd = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));
    let lfd = listener_fd.clone();
    std::thread::spawn(move || {
        // fsvmd's filter on this thread only, everything outside the list reported to the supervisor.
        let list: &[(libc::c_long, &str)] = if trace { &[] } else { seccomp::ALLOWED };
        let filter = seccomp::build_with(std::process::id(), &[], seccomp::RET_USER_NOTIF, list);
        match seccomp::install(&filter, seccomp::SECCOMP_FILTER_FLAG_NEW_LISTENER) {
            Ok(fd) => lfd.store(fd as i32, std::sync::atomic::Ordering::SeqCst),
            Err(_) => {
                lfd.store(-1, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        }
        let _ = done_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
    });
    let listener = loop {
        match listener_fd.load(std::sync::atomic::Ordering::SeqCst) {
            0 => std::thread::sleep(Duration::from_millis(5)),
            -1 => return Err("seccomp: the filter could not be installed".into()),
            fd => break fd,
        }
    };
    let seen = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<i64, u32>::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let supervisor = {
        let (seen, stop) = (seen.clone(), stop.clone());
        std::thread::spawn(move || supervise(listener, &seen, &stop))
    };

    let r = exercise(mnt, &done_rx);
    // SAFETY: plain system call on a valid string.
    let umounted = unsafe { libc::umount2(target.as_ptr(), 0) } == 0;
    r?;
    check(umounted, &format!("unmount: {}", std::io::Error::last_os_error()))?;
    // The loop ends when the mount goes: the read on /dev/fuse fails with ENODEV, never anything earlier.
    let end = done_rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "the FUSE loop did not end after the unmount")?;
    check(end.contains("code: 19"), &format!("the FUSE loop ended with {end}, not ENODEV after the unmount"))?;
    println!("fsvmd_fuse_test: loop ended after the unmount: {end}");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = supervisor.join();
    let seen = seen.lock().unwrap();
    let names: Vec<String> = seen.iter().map(|(nr, n)| format!("{} x{n}", syscall_name(*nr))).collect();
    if trace {
        println!("fsvmd_fuse_test: TRACE {} calls: {}", names.len(), names.join(", "));
        return Ok(());
    }
    check(seen.is_empty(), &format!("calls outside fsvmd's seccomp list: {}", names.join(", ")))?;
    println!("fsvmd_fuse_test: the FUSE thread kept to fsvmd's seccomp list");
    Ok(())
}

#[repr(C)]
#[allow(dead_code)]
struct NotifData {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}
#[repr(C)]
#[allow(dead_code)]
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    data: NotifData,
}
#[repr(C)]
#[allow(dead_code)]
struct NotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}
const NOTIF_RECV: u64 = 0xC050_2100; // SECCOMP_IOCTL_NOTIF_RECV
const NOTIF_SEND: u64 = 0xC018_2101; // SECCOMP_IOCTL_NOTIF_SEND
const FLAG_CONTINUE: u32 = 1; // SECCOMP_USER_NOTIF_FLAG_CONTINUE

type Seen = std::sync::Mutex<std::collections::BTreeMap<i64, u32>>;

/// Records every call the filter reported and lets it run (the test checks the list, it does not enforce it).
fn supervise(listener: i32, seen: &Seen, stop: &std::sync::atomic::AtomicBool) {
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let mut p = libc::pollfd { fd: listener, events: libc::POLLIN, revents: 0 };
        // SAFETY: poll on one pollfd of the listener this process owns.
        if unsafe { libc::poll(&mut p, 1, 200) } != 1 {
            continue;
        }
        // SAFETY: the kernel fills a zeroed struct seccomp_notif.
        let mut n: Notif = unsafe { std::mem::zeroed() };
        // SAFETY: NOTIF_RECV writes one struct seccomp_notif into `n`.
        if unsafe { libc::ioctl(listener, NOTIF_RECV as _, &mut n) } != 0 {
            continue;
        }
        *seen.lock().unwrap().entry(n.data.nr as i64).or_default() += 1;
        let r = NotifResp { id: n.id, val: 0, error: 0, flags: FLAG_CONTINUE };
        // SAFETY: NOTIF_SEND reads one struct seccomp_notif_resp.
        unsafe { libc::ioctl(listener, NOTIF_SEND as _, &r) };
    }
}

/// Names for the calls a trace shows (the host's numbers).
fn syscall_name(nr: i64) -> String {
    let known: &[(libc::c_long, &str)] = &[
        (libc::SYS_read, "read"),
        (libc::SYS_write, "write"),
        (libc::SYS_readv, "readv"),
        (libc::SYS_writev, "writev"),
        (libc::SYS_pread64, "pread64"),
        (libc::SYS_pwrite64, "pwrite64"),
        (libc::SYS_close, "close"),
        (libc::SYS_futex, "futex"),
        (libc::SYS_mmap, "mmap"),
        (libc::SYS_munmap, "munmap"),
        (libc::SYS_mremap, "mremap"),
        (libc::SYS_madvise, "madvise"),
        (libc::SYS_mprotect, "mprotect"),
        (libc::SYS_brk, "brk"),
        (libc::SYS_poll, "poll"),
        (libc::SYS_ppoll, "ppoll"),
        (libc::SYS_sendto, "sendto"),
        (libc::SYS_recvfrom, "recvfrom"),
        (libc::SYS_sendmsg, "sendmsg"),
        (libc::SYS_recvmsg, "recvmsg"),
        (libc::SYS_setsockopt, "setsockopt"),
        (libc::SYS_getsockopt, "getsockopt"),
        (libc::SYS_clock_gettime, "clock_gettime"),
        (libc::SYS_clock_nanosleep, "clock_nanosleep"),
        (libc::SYS_nanosleep, "nanosleep"),
        (libc::SYS_sigaltstack, "sigaltstack"),
        (libc::SYS_rt_sigprocmask, "rt_sigprocmask"),
        (libc::SYS_rt_sigaction, "rt_sigaction"),
        (libc::SYS_exit, "exit"),
        (libc::SYS_exit_group, "exit_group"),
        (libc::SYS_gettid, "gettid"),
        (libc::SYS_getpid, "getpid"),
        (libc::SYS_sched_yield, "sched_yield"),
        (libc::SYS_getrandom, "getrandom"),
        (libc::SYS_fcntl, "fcntl"),
        (libc::SYS_ioctl, "ioctl"),
        (libc::SYS_openat, "openat"),
        (libc::SYS_fstat, "fstat"),
        (libc::SYS_statx, "statx"),
        (libc::SYS_newfstatat, "newfstatat"),
        (libc::SYS_lseek, "lseek"),
        (libc::SYS_dup, "dup"),
        (libc::SYS_dup3, "dup3"),
        (libc::SYS_prctl, "prctl"),
        (libc::SYS_set_robust_list, "set_robust_list"),
        (334, "rseq"),
        (libc::SYS_clone, "clone"),
        (435, "clone3"),
        (libc::SYS_socket, "socket"),
        (libc::SYS_connect, "connect"),
        (libc::SYS_getcpu, "getcpu"),
        (libc::SYS_sched_getaffinity, "sched_getaffinity"),
        (libc::SYS_prlimit64, "prlimit64"),
    ];
    known.iter().find(|(n, _)| *n as i64 == nr).map(|(_, s)| s.to_string()).unwrap_or_else(|| format!("#{nr}"))
}


fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32 % 31) as u8 ^ seed).collect()
}

fn exercise(mnt: &std::path::Path, done: &mpsc::Receiver<String>) -> Result<(), String> {
    let md = std::fs::metadata(mnt).map_err(|e| format!("stat of the root: {e}"))?;
    check(md.is_dir(), "the root is not a directory")?;
    // The loop must still run after INIT and the first calls (the old code ended here).
    std::thread::sleep(Duration::from_millis(300));
    if let Ok(end) = done.try_recv() {
        return Err(format!("the FUSE loop ended right after INIT: {end}"));
    }

    // 5 protocol WRITEs and more: the kernel splits by max_write, the VM takes at most MAX_IO per call.
    let big = pattern(5 * MAX_IO as usize + 4321, 7);
    let file = mnt.join("big.bin");
    {
        let mut f = std::fs::File::create(&file).map_err(|e| format!("create: {e}"))?;
        f.write_all(&big).map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    }
    let back = std::fs::read(&file).map_err(|e| format!("read: {e}"))?;
    check(back == big, "the file read back differs")?;
    // A read across request boundaries from an odd offset.
    {
        let mut f = std::fs::File::open(&file).map_err(|e| format!("open: {e}"))?;
        f.seek(SeekFrom::Start(200_001)).map_err(|e| e.to_string())?;
        let mut part = vec![0u8; 300_000];
        f.read_exact(&mut part).map_err(|e| format!("read at an offset: {e}"))?;
        check(part[..] == big[200_001..500_001], "the read at an offset differs")?;
    }
    check(std::fs::metadata(&file).map_err(|e| e.to_string())?.len() == big.len() as u64, "file size")?;

    std::fs::create_dir(mnt.join("DCIM")).map_err(|e| format!("mkdir: {e}"))?;
    let mut names: Vec<String> = std::fs::read_dir(mnt)
        .map_err(|e| format!("readdir: {e}"))?
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    check(names == ["DCIM", "big.bin"], &format!("listing {names:?}"))?;

    std::fs::rename(&file, mnt.join("DCIM/moved.bin")).map_err(|e| format!("rename: {e}"))?;
    check(std::fs::read(mnt.join("DCIM/moved.bin")).map_err(|e| e.to_string())? == big, "after rename")?;
    std::fs::remove_file(mnt.join("DCIM/moved.bin")).map_err(|e| format!("unlink: {e}"))?;
    std::fs::remove_dir(mnt.join("DCIM")).map_err(|e| format!("rmdir: {e}"))?;
    check(std::fs::read_dir(mnt).map_err(|e| e.to_string())?.next().is_none(), "the volume is not empty at the end")?;

    let path = CString::new(mnt.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: statvfs fills the struct it is given.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    check(unsafe { libc::statvfs(path.as_ptr(), &mut st) } == 0, "statvfs")?;
    check(st.f_bsize == 4096 && st.f_blocks == 1 << 20, "statvfs values")?;
    Ok(())
}

/// An honest filesystem VM in memory, speaking the protocol as guest/fsvm_guest.c does.
struct FakeVm {
    nodes: HashMap<u64, FakeNode>,
    handles: HashMap<u64, u64>,
    next: u64,
}

struct FakeNode {
    kind: Kind,
    parent: u64,
    name: Vec<u8>,
    data: Vec<u8>,
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl FakeVm {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT_GUEST, FakeNode { kind: Kind::Dir, parent: ROOT_GUEST, name: Vec::new(), data: Vec::new() });
        FakeVm { nodes, handles: HashMap::new(), next: 100 }
    }

    fn attr(&self, id: u64) -> Vec<u8> {
        let n = &self.nodes[&id];
        encode_attr(&Attr { node: id, kind: n.kind, size: n.data.len() as u64, mtime_s: 1_700_000_000, mtime_ns: 0 })
            .to_vec()
    }

    fn child(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.nodes.iter().find(|(&id, n)| id != ROOT_GUEST && n.parent == parent && n.name == name).map(|(&id, _)| id)
    }

    fn serve(mut self, mut s: UnixStream) {
        loop {
            let mut h = [0u8; 48];
            if s.read_exact(&mut h).is_err() {
                return;
            }
            let (op, flags, id) = (u16::from_le_bytes([h[4], h[5]]), u16::from_le_bytes([h[6], h[7]]), le32(&h, 8));
            let (name_len, node, node2, arg, len, name2_len) =
                (le32(&h, 12) as usize, le64(&h, 16), le64(&h, 24), le64(&h, 32), le32(&h, 40), le32(&h, 44) as usize);
            let mut name = vec![0u8; name_len];
            let mut name2 = vec![0u8; name2_len];
            let mut data = vec![0u8; if op == 6 { len as usize } else { 0 }];
            if s.read_exact(&mut name).is_err() || s.read_exact(&mut name2).is_err() || s.read_exact(&mut data).is_err() {
                return;
            }
            let target = if node2 != 0 && matches!(op, 3 | 5 | 6 | 15) { self.handles.get(&node2).copied().unwrap_or(0) } else { node };
            let r = self.handle(op, flags, target, node2, arg, len, &name, &name2, &data);
            let (status, payload) = match r {
                Ok(p) => (0i32, p),
                Err(e) => (-e, Vec::new()),
            };
            let mut out = Vec::with_capacity(16 + payload.len());
            out.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&status.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&payload);
            if s.write_all(&out).is_err() {
                return;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle(
        &mut self,
        op: u16,
        flags: u16,
        node: u64,
        node2: u64,
        arg: u64,
        len: u32,
        name: &[u8],
        name2: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let exists = |vm: &FakeVm, id: u64| if vm.nodes.contains_key(&id) { Ok(()) } else { Err(libc::ESTALE) };
        match op {
            // GETATTR, LOOKUP
            3 => exists(self, node).map(|_| self.attr(node)),
            2 => self.child(node, name).map(|id| self.attr(id)).ok_or(libc::ENOENT),
            // READDIR: everything in one page.
            4 => {
                exists(self, node)?;
                let kids: Vec<(Vec<u8>, Attr)> = self
                    .nodes
                    .iter()
                    .filter(|(&id, n)| n.parent == node && id != ROOT_GUEST)
                    .map(|(&id, n)| (n.name.clone(), Attr { node: id, kind: n.kind, size: n.data.len() as u64, mtime_s: 0, mtime_ns: 0 }))
                    .collect();
                let entries: Vec<(&[u8], Attr)> = kids.iter().map(|(n, a)| (&n[..], *a)).collect();
                Ok(if arg == 0 { encode_dir_page(0, &entries) } else { encode_dir_page(0, &[]) })
            }
            // READ
            5 => {
                exists(self, node)?;
                assert!(len <= MAX_IO, "fsvmd asked for {len} bytes");
                let d = &self.nodes[&node].data;
                let start = (arg as usize).min(d.len());
                let end = (start + len as usize).min(d.len());
                Ok(d[start..end].to_vec())
            }
            // WRITE
            6 => {
                exists(self, node)?;
                assert!(data.len() <= MAX_IO as usize, "fsvmd wrote {} bytes", data.len());
                let d = &mut self.nodes.get_mut(&node).unwrap().data;
                let end = arg as usize + data.len();
                if d.len() < end {
                    d.resize(end, 0);
                }
                d[arg as usize..end].copy_from_slice(data);
                let mut p = (data.len() as u32).to_le_bytes().to_vec();
                p.extend_from_slice(&[0; 4]);
                Ok(p)
            }
            // CREATE, MKDIR
            7 | 8 => {
                exists(self, node)?;
                if let Some(id) = self.child(node, name) {
                    return if op == 7 && flags & 1 == 0 { Ok(self.attr(id)) } else { Err(libc::EEXIST) };
                }
                let id = self.next;
                self.next += 1;
                let kind = if op == 7 { Kind::File } else { Kind::Dir };
                self.nodes.insert(id, FakeNode { kind, parent: node, name: name.to_vec(), data: Vec::new() });
                Ok(self.attr(id))
            }
            // UNLINK, RMDIR
            9 | 10 => {
                let id = self.child(node, name).ok_or(libc::ENOENT)?;
                if op == 10 && self.nodes.values().any(|n| n.parent == id) {
                    return Err(libc::ENOTEMPTY);
                }
                self.nodes.remove(&id);
                Ok(Vec::new())
            }
            // RENAME
            11 => {
                let id = self.child(node, name).ok_or(libc::ENOENT)?;
                exists(self, node2)?;
                if let Some(old) = self.child(node2, name2) {
                    self.nodes.remove(&old);
                }
                let n = self.nodes.get_mut(&id).unwrap();
                n.parent = node2;
                n.name = name2.to_vec();
                Ok(Vec::new())
            }
            // TRUNCATE, SET_MTIME
            12 => {
                exists(self, node)?;
                self.nodes.get_mut(&node).unwrap().data.resize(arg as usize, 0);
                Ok(self.attr(node))
            }
            13 => exists(self, node).map(|_| self.attr(node)),
            // STATFS: 4 GiB in 4 KiB blocks.
            14 => {
                let mut p = Vec::new();
                for v in [1u64 << 20, 1 << 19, 1 << 19] {
                    p.extend_from_slice(&v.to_le_bytes());
                }
                p.extend_from_slice(&4096u32.to_le_bytes());
                p.extend_from_slice(&[0; 4]);
                Ok(p)
            }
            // FSYNC, FORGET, UNMOUNT
            15 | 16 | 19 => Ok(Vec::new()),
            // DIRTY
            20 => Ok(0u64.to_le_bytes().to_vec()),
            // OPEN, CLOSE
            21 => {
                exists(self, node)?;
                let h = self.next;
                self.next += 1;
                self.handles.insert(h, node);
                Ok(h.to_le_bytes().to_vec())
            }
            22 => {
                self.handles.remove(&node2);
                Ok(Vec::new())
            }
            _ => Err(libc::EINVAL),
        }
    }
}
