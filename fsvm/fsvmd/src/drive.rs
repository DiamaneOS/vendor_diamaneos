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

//! One drive's fsvmd (`fsvmd --drive`): one VM serves every public partition of one SD card or USB drive. vold sets up
//! a device-mapper range per partition and hands them over at the start, and each is a disk of the VM, all given at
//! the VM's start (a protected VM's disks are fixed). Each partition then has a FUSE mount, a session with a server of
//! its own in the VM (the guest runs one per disk, guest/disks.c) and its own check, repair and read-only state:
//!
//! - A partition's broken session gets a new session in the same VM (PartSession::restart). The VM is started again
//!   only once it ended, never while it runs, so the other partitions keep their sessions and their writable state.
//! - A partition whose sessions keep breaking gives up alone (fs::Session::give_up): its pipe closes, vold unmounts it
//!   and reports it as not opened, the others keep serving.
//! - A format or repair of a partition runs in this drive's VM, never in one that serves another drive.
//!
//! vold's requests come over descriptor 3 (drive_msg.rs). The VM starts with the first request that needs it and
//! stops when vold closes the socket (no partition served any more, an eject, a removal) or stops fsvmd. vold's write
//! back request (SIGUSR1) writes every partition back at once, its stop (SIGTERM) does that in the time left and ends.

use crate::drive_msg::{self, DiskSpec, Request};
use crate::{fs, tell, vm, MountSpec, Pipe, VmClient};
use anyhow::{anyhow, ensure, Context, Result};
use fsvm_proto::layout;
use log::{error, info, warn};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// DETACH answers: written back and unmounted clean, not written back, never served (vold system/vold
/// fs/FsvmDrive.cpp).
const CLEAN: i32 = 0;
const NEVER_SERVED: i32 = 1;
const NOT_WRITTEN_BACK: i32 = crate::EXIT_NOT_WRITTEN_BACK;

/// How long a DETACH waits for its partition's write back: the orderly stop's own time and a little more, so that
/// vold (kSyncMs, 26 s) always gets an answer. A detach that is not orderly (a mount vold gave up on) waits briefly:
/// a bring-up still running ends by itself.
const DETACH_ORDERLY: Duration = Duration::from_secs(23);
const DETACH_QUICK: Duration = Duration::from_millis(2500);
/// A stop (SIGTERM, vold gone) gives every partition this long to write back, together.
const STOP_WAIT: Duration = Duration::from_secs(2);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The drive's disks and its VM.
struct Drive {
    /// The partitions' ranges, vda first. fsvmd never reads them itself: only its VM manager and crosvm do.
    disks: Vec<File>,
    specs: Mutex<Vec<DiskSpec>>,
    block_size: u32,
    writable: bool,
    vm: Mutex<Option<Arc<vm::Vm>>>,
    /// The listing memory of all partitions together (fs::Listings): one card's.
    listings: Arc<fs::Listings>,
}

impl Drive {
    /// The VM's memory: all partitions' needs together (layout::drive_memory_mib).
    fn memory(&self) -> u32 {
        let parts: Vec<(u32, u64)> = lock(&self.specs).iter().map(|s| (s.fs, s.meta_bytes)).collect();
        layout::drive_memory_mib(&parts)
    }

    /// A new session with the server of disk `k`, before `deadline` less `keep`. A VM that runs is used as it is: its
    /// server of disk `k` is replaced, the other disks' servers go on. Only when no VM runs (the first request, or the
    /// VM ended) a new one starts, with every disk of the drive. A VM refused at its start for want of memory ends
    /// with NoRoom (vold waits for room).
    fn session(&self, k: usize, deadline: Instant, keep: Duration) -> Result<VmClient> {
        self.session_with_vm(k, deadline, keep).map(|(_, client)| client)
    }

    fn session_with_vm(&self, k: usize, deadline: Instant, keep: Duration) -> Result<(Arc<vm::Vm>, VmClient)> {
        self.session_with_retry(k, deadline, keep, &mut crate::reconnect::DeadVmRetry::default())
    }

    fn session_with_retry(
        &self,
        k: usize,
        deadline: Instant,
        keep: Duration,
        retry: &mut crate::reconnect::DeadVmRetry,
    ) -> Result<(Arc<vm::Vm>, VmClient)> {
        let mut current = loop {
            crate::left(deadline)?;
            match self.vm.try_lock() {
                Ok(current) => break current,
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
            }
        };
        if let Some(vm) = current.as_ref() {
            if !vm.ended() {
                let vm = vm.clone();
                drop(current);
                let connected = crate::connect_disk(&vm, k as u32, deadline, keep);
                if connected.is_err() && retry.after_connect_failure(vm.ended(), deadline) {
                    warn!("the drive's VM ended while its session connected, starting a replacement");
                    drop(vm);
                    return self.session_with_retry(k, deadline, keep, retry);
                }
                return connected.map(|client| (vm, client));
            }
            warn!("the drive's VM ended, starting a new one with all its disks");
            *current = None;
        }
        let memory = self.memory();
        info!("starting the drive's VM with {} disks and {memory} MiB", self.disks.len());
        // As for a volume of its own (main.rs Served): a large VM refused for its pieces is refused again, so one try,
        // then the smallest serving VM, where a check that needs more memory cannot finish (its partition stays
        // read-only with its notice).
        let tries = if memory > layout::MIN_SERVE_MIB { 1 } else { 3 };
        let (vm, client) =
            match crate::start_vm(&self.disks, self.writable, memory, deadline, keep, tries, k as u32) {
                Ok(started) => started,
                Err(e) if memory > layout::MIN_SERVE_MIB => {
                    warn!("the drive's VM of {memory} MiB did not start ({e:?}), starting it with {} MiB", layout::MIN_SERVE_MIB);
                    crate::start_vm(&self.disks, self.writable, layout::MIN_SERVE_MIB, deadline, keep, 1, k as u32)?
                }
                Err(e) => return Err(e),
            };
        let vm = Arc::new(vm);
        *current = Some(vm.clone());
        Ok((vm, client))
    }

    /// Stops the VM and waits for its end, so that its memory and the ranges are free before fsvmd ends.
    fn stop_vm(&self) {
        if let Some(vm) = lock(&self.vm).take() {
            vm.stop_and_wait(crate::PROBE_VM_END);
        }
    }

    /// A failed format is inconclusive even after stopping the writer. Leave siblings alone.
    fn confirm_format_writer_stopped(&self, slots: &Mutex<Slots>, writer: &Arc<vm::Vm>) -> bool {
        let s = lock(slots);
        if s.parts.iter().any(Option::is_some) || s.repairs.iter().any(Option::is_some) {
            return false;
        }
        drop(s);
        let mut current = lock(&self.vm);
        if !current.as_ref().is_some_and(|vm| Arc::ptr_eq(vm, writer))
            || !writer.stop_and_wait(crate::PROBE_VM_END)
        {
            return false;
        }
        *current = None;
        true
    }
}

/// One partition as served now: from vold's ATTACH until its DETACH.
struct Part {
    pipe: Pipe,
    /// The orderly stop of its filesystem, once it serves. With `detached`, under this lock: either the DETACH finds
    /// the closer, or the serving thread finds the DETACH.
    closer: Mutex<(Option<fs::Closer>, bool)>,
    result: Mutex<Option<i32>>,
    done: Condvar,
}

impl Part {
    fn finish(&self, status: i32) {
        let mut r = lock(&self.result);
        if r.is_none() {
            *r = Some(status);
        }
        self.done.notify_all();
    }

    fn wait(&self, within: Duration) -> Option<i32> {
        let r = lock(&self.result);
        let (r, _) = self.done.wait_timeout_while(r, within, |r| r.is_none()).unwrap_or_else(|p| p.into_inner());
        *r
    }

    fn serving(&self) -> bool {
        lock(&self.result).is_none()
    }

    /// The partition ended: vold's Watch sees its pipe close.
    fn close_pipe(&self) {
        lock(&self.pipe).take();
    }
}

fn status_of(c: fs::Closed) -> i32 {
    if c == fs::Closed::Clean {
        CLEAN
    } else {
        NOT_WRITTEN_BACK
    }
}

/// A partition's sessions in the drive's VM.
struct PartSession {
    drive: Arc<Drive>,
    k: usize,
    mount: MountSpec,
    volume: String,
    pipe: Pipe,
}

impl PartSession {
    fn bring_up(&mut self, deadline: Instant) -> Result<(VmClient, fsvm_proto::Hello)> {
        crate::left(deadline)?;
        let client = self.drive.session(self.k, deadline, crate::SERVE_KEEP)?;
        crate::mount_on(client, &self.mount, deadline)
    }
}

impl fs::Session for PartSession {
    fn restart(&mut self, deadline: Instant) -> Result<(VmClient, fsvm_proto::Hello)> {
        info!("volume {}: a new session in the drive's VM", self.volume);
        self.bring_up(deadline)
    }

    /// The drive's VM serves the other partitions on: only this session ends (fs::Closer shuts it down).
    fn stop_vm(&mut self, _within: Duration) {}

    fn give_up(&mut self) {
        error!("volume {}: no new session, it is not served any more (the drive's other volumes are)", self.volume);
        lock(&self.pipe).take();
    }
}

struct Slots {
    parts: Vec<Option<Arc<Part>>>,
    /// A repair running on the disk, and whether vold cancelled it.
    repairs: Vec<Option<Arc<AtomicBool>>>,
    modes: Vec<drive_msg::AttachmentMode>,
}

impl Slots {
    fn busy(&self, k: usize) -> bool {
        self.parts[k].as_ref().is_some_and(|p| p.serving()) || self.repairs[k].is_some()
    }
}

/// Serves partition `k` from the drive's VM until vold detaches it.
#[allow(clippy::too_many_arguments)]
fn serve_part(
    drive: Arc<Drive>,
    part: Arc<Part>,
    k: usize,
    gid: u32,
    owner_uid: u32,
    read_only: bool,
    fs_kind: u32,
    volume: String,
    fuse_dev: File,
) {
    let bytes = lock(&drive.specs)[k].bytes;
    let mount = MountSpec {
        obb: false,
        read_only,
        disk_bytes: bytes,
        block_size: drive.block_size,
        // The partition alone, as a disk of its own: its filesystem starts at the disk's first sector.
        partition: 0,
        start: 0,
        length: bytes / 512,
        fs: fs_kind,
    };
    let listings = drive.listings.clone();
    let mut session = PartSession { drive, k, mount, volume: volume.clone(), pipe: part.pipe.clone() };
    let (client, hello) = match session.bring_up(Instant::now() + crate::SERVE_BUDGET) {
        Ok(up) => up,
        Err(e) => {
            error!("volume {volume}: not served: {e:?}");
            // N: the VM was refused at its start for want of memory, and vold waits for room.
            let no_room = e.chain().any(|c| c.is::<crate::NoRoom>());
            if no_room {
                let _ = tell(&part.pipe, b"N");
            }
            part.finish(if no_room { crate::EXIT_NO_ROOM } else { NEVER_SERVED });
            part.close_pipe();
            return;
        }
    };
    let pipe = part.pipe.clone();
    let filesystem =
        match crate::start_serving(
            client,
            hello,
            read_only,
            gid,
            owner_uid,
            false,
            &volume,
            Box::new(session),
            &pipe,
            listings,
        ) {
            Ok(f) => f,
            Err(e) => {
                error!("volume {volume}: not served: {e:?}");
                part.finish(NEVER_SERVED);
                part.close_pipe();
                return;
            }
        };
    let closer = filesystem.closer();
    {
        let mut c = lock(&part.closer);
        if c.1 {
            // vold gave up on this mount before it was served: unmounted at once.
            drop(c);
            part.finish(status_of(closer.close(Duration::from_millis(300), Duration::from_millis(1500))));
            part.close_pipe();
            return;
        }
        c.0 = Some(closer.clone());
    }
    let r = fs::serve_fuse(fuse_dev, filesystem);
    info!("volume {volume}: FUSE loop ended: {r:?}");
    // vold unmounted the volume: everything is written back and the filesystem unmounted in the VM (marked clean).
    // When vold's DETACH or a stop came first, they record how it went.
    match closer.close(crate::CLOSE_LOCK_WAIT, crate::CLOSE_MAX) {
        fs::Closed::InProgress => {}
        c => part.finish(status_of(c)),
    }
    part.close_pipe();
}

/// Repairs partition `k` in the drive's VM with no time limit, and writes `OK` to `pipe` when it is clean now.
fn repair_part(drive: Arc<Drive>, slots: Arc<Mutex<Slots>>, k: usize, fs_kind: u32, cancelled: Arc<AtomicBool>, mut pipe: File) {
    let bytes = lock(&drive.specs)[k].bytes;
    let deadline = Instant::now() + crate::SERVE_BUDGET;
    let result = drive.session(k, deadline, crate::PROBE_KEEP).and_then(|client| {
        info!("repairing disk {k} in the drive's VM, no time limit");
        crate::repair_on(client, bytes, drive.block_size, (0, 0, bytes / 512), fs_kind, deadline)
    });
    match result {
        Ok(crate::Repair::Done) if !cancelled.load(Ordering::SeqCst) => {
            lock(&slots).modes[k].repaired();
            info!("disk {k} repaired in the drive's VM");
            let _ = pipe.write_all(b"OK\n");
        }
        Ok(r) => warn!("disk {k} was not repaired ({r:?}), it stays read-only"),
        Err(e) => warn!("disk {k} was not repaired: {e:?}"),
    }
}

/// How a format of a partition went (the FORMAT answer, drive_msg.rs).
enum Formatted {
    /// Formatted and read back: the new filesystem's probe text.
    Done(String),
    /// The format tool succeeded, the new filesystem could not be read back (vold reads the disk again).
    Unverified,
    /// The format could have written data. The reply carries any affirmative writer exit.
    Uncertain(i32),
}

fn format_failure_reply(drive: &Drive, slots: &Mutex<Slots>, writer: &Arc<vm::Vm>, error: i32) -> i32 {
    if drive.confirm_format_writer_stopped(slots, writer) {
        drive_msg::FORMAT_UNCERTAIN_STOPPED
    } else if error == drive_msg::FORMAT_UNCERTAIN || error == libc::EAGAIN {
        // EAGAIN on the drive protocol is reserved for admission failure before dispatch.
        drive_msg::FORMAT_UNCERTAIN
    } else if error > 0 && error < 4000 {
        error
    } else {
        libc::EIO
    }
}

/// Formats partition `k` in the drive's VM and reads its new filesystem.
fn format_part(drive: &Drive, slots: &Mutex<Slots>, k: usize, fs_kind: u32) -> Result<Formatted> {
    let deadline = Instant::now() + crate::FORMAT_BUDGET;
    let (vm, mut client) = drive.session_with_vm(k, deadline, crate::FORMAT_KEEP)?;
    let budget = crate::left(deadline)?.saturating_sub(Duration::from_secs(3));
    match client.format(fs_kind, budget) {
        Ok(()) => {}
        Err(fsvm_proto::client::CallError::Errno(e)) => {
            warn!("disk {k}: the formatter returned errno {e}");
            return Ok(Formatted::Uncertain(format_failure_reply(drive, slots, &vm, e)));
        }
        Err(e) => {
            error!("disk {k}: the format request broke off: {e:?}");
            return Ok(Formatted::Uncertain(format_failure_reply(drive, slots, &vm, drive_msg::FORMAT_UNCERTAIN)));
        }
    }
    let bytes = lock(&drive.specs)[k].bytes;
    let l = match client.layout(bytes, drive.block_size) {
        Ok(l) => l,
        Err(e) => {
            warn!("disk {k} formatted, its new filesystem was not read back: {e:?}");
            return Ok(Formatted::Unverified);
        }
    };
    let _ = client.transport_mut().0.shutdown(std::net::Shutdown::Both);
    info!("disk {k} formatted in the drive's VM as {}", if fs_kind == fsvm_proto::FS_EXFAT { "exfat" } else { "vfat" });
    // The next VM of this drive is sized for the new filesystem.
    if let Some(p) = l.parts.first() {
        let mut specs = lock(&drive.specs);
        specs[k].fs = p.fs_kind;
        specs[k].meta_bytes = p.meta_bytes;
    }
    Ok(Formatted::Done(layout::probe_text(&l)))
}

/// Receives one request from vold: its bytes and descriptors, or None when vold closed the socket.
fn receive(ctl: RawFd) -> Result<Option<(Vec<u8>, Vec<File>)>> {
    let mut data = vec![0u8; drive_msg::MAX_REQUEST + 1];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    // SAFETY: CMSG_SPACE only computes a size.
    let space = unsafe { libc::CMSG_SPACE((drive_msg::MAX_FDS * std::mem::size_of::<RawFd>()) as libc::c_uint) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    // SAFETY: an all-zero msghdr is valid, its pointers are set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    let n = loop {
        // SAFETY: recvmsg writes into `data` and `control` within the lengths given in `msg`.
        let n = unsafe { libc::recvmsg(ctl, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break n;
        }
    };
    ensure!(n >= 0, "receiving from vold: {}", std::io::Error::last_os_error());
    let mut fds = Vec::new();
    // SAFETY: the CMSG_* walk stays inside the control buffer recvmsg filled, as msg_controllen says.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let p = libc::CMSG_DATA(c) as *const RawFd;
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(File::from_raw_fd(p.add(i).read_unaligned()));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    ensure!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0, "a request or its descriptors cut off");
    if n == 0 && fds.is_empty() {
        return Ok(None);
    }
    data.truncate(n as usize);
    Ok(Some((data, fds)))
}

fn send(ctl: RawFd, text: &str) {
    // SAFETY: send reads `text` within its length. A vold that is gone gets nothing, and no SIGPIPE.
    unsafe { libc::send(ctl, text.as_ptr().cast(), text.len(), libc::MSG_NOSIGNAL) };
}

/// The drive's disks, the first request: one block device per --disk, writable unless the drive is read-only.
fn take_disks(fds: Vec<File>, writable: bool) -> Result<Vec<File>> {
    let want = if writable { libc::O_RDWR } else { libc::O_RDONLY };
    for (k, f) in fds.iter().enumerate() {
        ensure!(f.metadata()?.file_type().is_block_device(), "disk {k} is not a block device");
        ensure!(crate::access_mode(f)? == want, "disk {k} is not opened as the drive is (writable {writable})");
    }
    Ok(fds)
}

/// Ends every partition: each writes back within `max`, together, then the VM stops and fsvmd exits, with
/// EXIT_NOT_WRITTEN_BACK when a partition could not be written back.
fn stop_all(drive: &Drive, slots: &Mutex<Slots>, lock_wait: Duration, max: Duration) -> ! {
    let parts: Vec<Arc<Part>> = lock(slots).parts.iter().flatten().cloned().collect();
    let threads: Vec<_> = parts
        .iter()
        .map(|p| {
            let p = p.clone();
            std::thread::spawn(move || {
                let closer = {
                    let mut c = lock(&p.closer);
                    c.1 = true;
                    c.0.clone()
                };
                if let Some(closer) = closer {
                    match closer.close(lock_wait, max) {
                        fs::Closed::InProgress => {}
                        c => p.finish(status_of(c)),
                    }
                }
            })
        })
        .collect();
    for t in threads {
        let _ = t.join();
    }
    let mut code = 0;
    for p in &parts {
        match p.wait(STOP_WAIT) {
            Some(NOT_WRITTEN_BACK) => code = NOT_WRITTEN_BACK,
            // Served, and its write back did not end in time.
            None if lock(&p.closer).0.is_some() => code = NOT_WRITTEN_BACK,
            _ => {}
        }
    }
    drive.stop_vm();
    std::process::exit(code)
}

/// Runs the fsvmd of drive `name` on vold's socket `ctl` (descriptor 3) for the partitions `specs`, until vold closes
/// it.
pub fn run(name: &str, specs: &[DiskSpec], block_size: u32, writable: bool, ctl: File) -> Result<()> {
    let fd = ctl.as_raw_fd();
    // DISKS first, with one range per partition.
    let (data, fds) = receive(fd)?.context("vold closed the socket before the disks came")?;
    let (id, first) = drive_msg::parse(&data, fds.len(), 0).map_err(|e| anyhow!("vold's first request: {e}"))?;
    let disks = match first {
        Request::Disks { count } if count == specs.len() => match take_disks(fds, writable) {
            Ok(d) => d,
            Err(e) => {
                send(fd, &drive_msg::answer(id, &first, libc::EINVAL));
                return Err(e);
            }
        },
        _ => {
            send(fd, &drive_msg::answer(id, &first, libc::EINVAL));
            return Err(anyhow!("{} disks given for {} partitions", fds.len(), specs.len()));
        }
    };
    send(fd, &drive_msg::answer(id, &first, 0));
    info!("drive {name} with {} partitions, writable {writable}", specs.len());
    let drive = Arc::new(Drive {
        disks,
        specs: Mutex::new(specs.to_vec()),
        block_size,
        writable,
        vm: Mutex::new(None),
        listings: Default::default(),
    });
    let slots = Arc::new(Mutex::new(Slots { parts: vec![None; specs.len()], repairs: vec![None; specs.len()], modes: vec![drive_msg::AttachmentMode::default(); specs.len()] }));

    // vold's stop (T) ends everything in the time left, its write back request (W) writes every partition back now and
    // leaves the rest to its DETACHes.
    let mut signals = crate::stop_signals()?;
    {
        let (drive, slots) = (drive.clone(), slots.clone());
        std::thread::spawn(move || loop {
            let mut b = [0u8; 1];
            if signals.read(&mut b).unwrap_or(0) != 1 {
                return;
            }
            let (lock_wait, max) = crate::stop_times(b[0]);
            if b[0] != b'W' {
                stop_all(&drive, &slots, lock_wait, max);
            }
            for p in lock(&slots).parts.iter().flatten().cloned() {
                std::thread::spawn(move || {
                    let closer = lock(&p.closer).0.clone();
                    if let Some(closer) = closer {
                        match closer.close(lock_wait, max) {
                            fs::Closed::InProgress => {}
                            c => p.finish(status_of(c)),
                        }
                    }
                });
            }
        });
    }

    loop {
        let Some((data, fds)) = receive(fd)? else {
            info!("vold closed the drive's socket, stopping");
            stop_all(&drive, &slots, Duration::from_millis(300), Duration::from_millis(1500));
        };
        let (id, req) = match drive_msg::parse(&data, fds.len(), specs.len()) {
            Ok(r) => r,
            Err(e) => {
                // vold is the only peer: a request it cannot have meant ends the drive, as a malformed one would.
                error!("refusing vold's request: {e}");
                stop_all(&drive, &slots, Duration::from_millis(300), Duration::from_millis(1500));
            }
        };
        let answer = handle(&drive, &slots, id, &req, fds, writable);
        send(fd, &answer);
    }
}

/// One request of vold's, `id`, answered.
fn handle(drive: &Arc<Drive>, slots: &Arc<Mutex<Slots>>, id: u32, req: &Request, mut fds: Vec<File>, writable: bool) -> String {
    let value = match req {
        Request::Disks { .. } => libc::EINVAL,
        Request::Attach { disk, gid, owner_uid, read_only, fs, volume } => {
            let k = *disk;
            let pipe_file = fds.pop();
            let fuse_dev = fds.pop();
            match (fuse_dev, pipe_file) {
                (Some(fuse_dev), Some(pipe_file))
                    if fuse_dev.metadata().is_ok_and(|m| m.file_type().is_char_device())
                        && pipe_file.metadata().is_ok_and(|m| m.file_type().is_fifo()) =>
                {
                    let mut s = lock(slots);
                    if s.busy(k) {
                        libc::EBUSY
                    } else {
                        let part = Arc::new(Part {
                            pipe: Arc::new(Mutex::new(Some(pipe_file))),
                            closer: Mutex::new((None, false)),
                            result: Mutex::new(None),
                            done: Condvar::new(),
                        });
                        s.parts[k] = Some(part.clone());
                        let read_only = s.modes[k].attach(*read_only, writable);
                        drop(s);
                        let drive = drive.clone();
                        let (gid, owner_uid, fs, volume) = (*gid, *owner_uid, *fs, volume.clone());
                        info!("volume {volume}: serving disk {k} of the drive");
                        std::thread::spawn(move || {
                            serve_part(drive, part, k, gid, owner_uid, read_only, fs, volume, fuse_dev)
                        });
                        0
                    }
                }
                _ => libc::EINVAL,
            }
        }
        Request::Detach { disk, orderly } => {
            let k = *disk;
            let part = lock(slots).parts[k].clone();
            match part {
                None => NEVER_SERVED,
                Some(p) => {
                    let closer = {
                        let mut c = lock(&p.closer);
                        c.1 = true;
                        c.0.clone()
                    };
                    let (lock_wait, max) = if *orderly {
                        (crate::CLOSE_LOCK_WAIT, crate::CLOSE_MAX)
                    } else {
                        (Duration::from_millis(300), Duration::from_millis(1500))
                    };
                    if let Some(closer) = closer {
                        match closer.close(lock_wait, max) {
                            fs::Closed::InProgress => {}
                            c => p.finish(status_of(c)),
                        }
                    }
                    let status = p.wait(if *orderly { DETACH_ORDERLY } else { DETACH_QUICK });
                    p.close_pipe();
                    let mut s = lock(slots);
                    if s.parts[k].as_ref().is_some_and(|q| Arc::ptr_eq(q, &p)) {
                        s.parts[k] = None;
                    }
                    status.unwrap_or(NOT_WRITTEN_BACK)
                }
            }
        }
        Request::Format { disk, fs } => {
            let k = *disk;
            if lock(slots).busy(k) {
                libc::EBUSY
            } else {
                match format_part(drive, slots, k, *fs) {
                    Ok(Formatted::Done(text)) => {
                        lock(slots).modes[k].repaired();
                        return format!("{}\n{text}", drive_msg::answer(id, req, 0));
                    }
                    Ok(Formatted::Unverified) => drive_msg::FORMAT_UNVERIFIED,
                    Ok(Formatted::Uncertain(reply)) => reply,
                    Err(e) => {
                        error!("disk {k} not formatted: {e:?}");
                        if e.chain().any(|c| c.is::<crate::NoRoom>()) {
                            libc::EAGAIN
                        } else {
                            libc::EIO
                        }
                    }
                }
            }
        }
        Request::Repair { disk } => {
            let k = *disk;
            let mut s = lock(slots);
            match fds.pop() {
                Some(pipe) if pipe.metadata().is_ok_and(|m| m.file_type().is_fifo()) && !s.busy(k) => {
                    let cancelled = Arc::new(AtomicBool::new(false));
                    s.repairs[k] = Some(cancelled.clone());
                    drop(s);
                    let fs_kind = lock(&drive.specs)[k].fs;
                    let (drive, slots) = (drive.clone(), slots.clone());
                    std::thread::spawn(move || {
                        repair_part(drive, slots.clone(), k, fs_kind, cancelled, pipe);
                        lock(&slots).repairs[k] = None;
                    });
                    0
                }
                Some(_) if s.busy(k) => libc::EBUSY,
                _ => libc::EINVAL,
            }
        }
        Request::Cancel { disk } => {
            let k = *disk;
            if let Some(cancelled) = lock(slots).repairs[k].clone() {
                cancelled.store(true, Ordering::SeqCst);
                // A new session with the disk makes the VM end the server that repairs it, with its checker: the
                // volume keeps its dirty mark. Not waited for here.
                let drive = drive.clone();
                std::thread::spawn(move || {
                    if let Err(e) = drive.session(k, Instant::now() + Duration::from_secs(15), Duration::ZERO) {
                        warn!("ending the repair of disk {k}: {e:?}");
                    }
                });
            }
            0
        }
    };
    drive_msg::answer(id, req, value)
}
