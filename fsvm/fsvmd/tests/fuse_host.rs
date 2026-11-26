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
//! A FUSE loop that announced a max_write larger than its reads was refused by the kernel with EINVAL right after
//! INIT: this test fails on that.
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
#[path = "../src/reconnect.rs"]
mod reconnect;
#[allow(dead_code)]
#[path = "../src/seccomp.rs"]
mod seccomp;

use fsvm_proto::{Client, Deadlines, Kind, StreamTransport, MAX_IO};
mod fake_vm;
use fake_vm::{FakeVm, FakeNode, CheckPlan};
mod cleanup_dispatch;
use std::ffi::CString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

const CHILD: &str = "FSVMD_FUSE_TEST_CHILD";
const ROOT_GUEST: u64 = 1;

struct TestLog;
impl log::Log for TestLog {
    fn enabled(&self, metadata: &log::Metadata) -> bool { metadata.level() <= log::Level::Warn }
    fn log(&self, record: &log::Record) { if self.enabled(record.metadata()) { eprintln!("{}", record.args()); } }
    fn flush(&self) {}
}
static TEST_LOG: TestLog = TestLog;

fn main() {
    if std::env::args().any(|a| a == "--review-1b-rrr-cleanup") {
        std::process::exit(match cleanup_dispatch::run_rereview() { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } });
    }
    if std::env::var_os("FSVMD_TEST_LOG").is_some() {
        let _ = log::set_logger(&TEST_LOG);
        log::set_max_level(log::LevelFilter::Warn);
    }
    if std::env::args().any(|a| a == "--review-1b-rr-cleanup") {
        std::process::exit(match cleanup_dispatch::run() { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } });
    }
    if std::env::args().any(|a| a == "--review-1b-rr-dir") {
        std::process::exit(match directory_timestamp_cases() { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } });
    }
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
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
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
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, false, false, 0, false, false, Box::new(NoRestart));
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
    if std::env::args().any(|a| a == "--review-1b-r") {
        return review_1b_r();
    }
    review_1b_r()?;
    directory_timestamp_cases()?;
    cleanup_dispatch::run()?;
    checked(mnt, &target, false)?;
    println!("fsvmd_fuse_test: a dirty volume: read-only while checked, writable after the switch, vold told W");
    checked(mnt, &target, true)?;
    println!("fsvmd_fuse_test: the switch's answer lost: the new VM's clean mount makes the volume writable, vold told W");
    two_partitions(mnt)?;
    println!("fsvmd_fuse_test: two partitions of a drive: one gives up alone, the other serves on and stops clean");
    reconnect(mnt, &target, true)?;
    println!("fsvmd_fuse_test: a file open across a new VM: its I/O fails, the replacement under its name untouched, \
              the kernel's cache dropped, the eject says not written back");
    reconnect(mnt, &target, false)?;
    println!("fsvmd_fuse_test: a new VM after reads only: the eject stays clean");
    read_only_asked(mnt, &target)?;
    println!("fsvmd_fuse_test: a volume asked read-only: no check, no switch, never writable, vold told r");
    slow_lookups(mnt, &target)?;
    println!("fsvmd_fuse_test: a path looked up again on a slow VM: the request ends within its time");
    no_handle_left(mnt, &target)?;
    println!("fsvmd_fuse_test: the VM out of handles: the app's open gets EMFILE");
    unlinked_open_file()?;
    println!("fsvmd_fuse_test: an open, unlinked file keeps its kind");
    listings_of_a_drive()?;
    println!("fsvmd_fuse_test: the listings of a drive's partitions share one card's memory");
    obb_read(mnt, &target)?;
    println!("fsvmd_fuse_test: an OBB image, mounted read-only: its files open and read");
    Ok(())
}

/// A new VM after a broken session: one whose volume holds `files`, mounted clean and writable, with `deadlines`.
struct RestartWith {
    files: Vec<(String, Vec<u8>)>,
    lookup_delay: Duration,
    deadlines: Deadlines,
}

impl fs::Session for RestartWith {
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        let (vm_end, our_end) = UnixStream::pair()?;
        let files: Vec<(&str, &[u8])> = self.files.iter().map(|(n, d)| (n.as_str(), &d[..])).collect();
        let mut vm = FakeVm::with_files(&files);
        vm.lookup_delay = self.lookup_delay;
        std::thread::spawn(move || vm.serve(vm_end));
        let hello = fsvm_proto::Hello { fs_kind: fsvm_proto::FS_VFAT, read_only: false, was_dirty: false, check_pending: false, root: ROOT_GUEST };
        Ok((Client::new(StreamTransport(our_end), self.deadlines), hello))
    }
    fn stop_vm(&mut self, _within: Duration) {}
}

/// A volume served at `target` from a FakeVm, with the end of its VM's socket (to break the session), its stop and
/// the end of its FUSE loop.
struct Served {
    vm_side: UnixStream,
    closer: fs::Closer,
    end: mpsc::Receiver<String>,
}

fn serve_at(target: &CString, vm: FakeVm, deadlines: Deadlines, asked_ro: bool, session: Box<dyn fs::Session>) -> Result<Served, String> {
    let dev = fuse_mount(target)?;
    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    let vm_side = vm_end.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || vm.serve(vm_end));
    let client = Client::new(StreamTransport(our_end), deadlines);
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, asked_ro, asked_ro, 0, false, false, session);
    let closer = filesystem.closer();
    let (end_tx, end) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = end_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
    });
    Ok(Served { vm_side, closer, end })
}

/// Unmounts, waits for the FUSE loop's end and stops the volume orderly.
fn unserve(target: &CString, s: Served) -> Result<fs::Closed, String> {
    // SAFETY: plain system call on a valid string.
    check(unsafe { libc::umount2(target.as_ptr(), 0) } == 0, &format!("unmount: {}", std::io::Error::last_os_error()))?;
    s.end.recv_timeout(Duration::from_secs(10)).map_err(|_| "the FUSE loop did not end after the unmount")?;
    Ok(s.closer.close(Duration::from_secs(1), Duration::from_secs(5)))
}

fn errno_of<T: std::fmt::Debug>(r: &std::io::Result<T>) -> Option<i32> {
    r.as_ref().err().and_then(|e| e.raw_os_error())
}

/// Review 1b H3 and M2: a file stays open while its VM is replaced and a different file holds its name in the new
/// one. Its reads and writes must fail rather than reach that other file, which keeps its contents. The kernel must
/// drop what it cached of the name at once, not after its 5 s, and a new open reaches the new file. With `change`,
/// the old VM had acknowledged writes, so the eject must not report the volume as written back.
fn reconnect(mnt: &std::path::Path, target: &CString, change: bool) -> Result<(), String> {
    use std::os::unix::fs::FileExt;
    let replacement = b"REPLACEMENT-FILE".to_vec();
    let session = RestartWith {
        files: vec![("a.txt".into(), replacement.clone()), ("sub/keep".into(), Vec::new())],
        lookup_delay: Duration::ZERO,
        deadlines: Deadlines::default(),
    };
    let first: &[u8] = b"ORIGINAL";
    let vm = if change { FakeVm::new() } else { FakeVm::with_files(&[("a.txt", first), ("sub/keep", &b""[..])]) };
    let served = serve_at(target, vm, Deadlines::default(), false, Box::new(session))?;
    let file = mnt.join("a.txt");
    let r = (|| -> Result<(), String> {
        if change {
            std::fs::write(&file, first).map_err(|e| format!("a write before the break: {e}"))?;
        }
        let f = std::fs::OpenOptions::new().read(true).write(change).open(&file).map_err(|e| format!("open: {e}"))?;
        // A process working in a directory of the volume (a shell's cd): the directory stays reachable after the new
        // VM, whose directories keep their inodes.
        let sub = mnt.join("sub");
        std::fs::create_dir_all(&sub).map_err(|e| format!("mkdir sub: {e}"))?;
        std::env::set_current_dir(&sub).map_err(|e| format!("cd sub: {e}"))?;
        check(std::fs::metadata(&file).map_err(|e| e.to_string())?.len() == first.len() as u64, "size before the break")?;
        // The VM ends: the next call breaks the session and a new VM comes up, with another a.txt.
        let _ = served.vm_side.shutdown(std::net::Shutdown::Both);
        let mut buf = [0u8; 64];
        // The kernel reads ahead, and after that read failed it reads the page once more: both must fail.
        let during = f.read_at(&mut buf, 0).map(|n| String::from_utf8_lossy(&buf[..n]).into_owned());
        check(errno_of(&during) == Some(libc::EIO), &format!("a read as the VM went: {during:?}"))?;
        let after = f.read_at(&mut buf, 0).map(|n| String::from_utf8_lossy(&buf[..n]).into_owned());
        check(errno_of(&after) == Some(libc::EIO), &format!("a read through the old descriptor after the new VM: {after:?}"))?;
        if change {
            let w = f.write_at(b"XX", 0);
            check(errno_of(&w) == Some(libc::EIO), &format!("a write through the old descriptor after the new VM: {w:?}"))?;
            let sync = f.sync_all();
            check(errno_of(&sync) == Some(libc::EIO), &format!("fsync of the old descriptor: {sync:?}"))?;
        }
        let cwd = std::env::current_dir();
        std::env::set_current_dir("/").map_err(|e| format!("cd /: {e}"))?;
        check(cwd.is_ok(), &format!("the working directory on the volume after the new VM: {cwd:?}"))?;
        // The kernel cached a.txt's size for 5 s: the new VM's must show at once.
        let t = std::time::Instant::now();
        let size = loop {
            let size = std::fs::metadata(&file).map_err(|e| e.to_string())?.len();
            if size == replacement.len() as u64 || t.elapsed() > Duration::from_millis(1500) {
                break size;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        check(size == replacement.len() as u64, &format!("the kernel still shows the old size {size} after {:?}", t.elapsed()))?;
        let now = std::fs::read(&file).map_err(|e| format!("a new open after the new VM: {e}"))?;
        check(now == replacement, &format!("the file under the name now: {:?}", String::from_utf8_lossy(&now)))?;
        // The name's file written through a new open, a whole page, which the kernel keeps cached: the old
        // descriptor must not see it either. The kernel shares cached pages within an inode, so the new file must not
        // get the old descriptor's inode.
        let newer = pattern(8192, 3);
        std::fs::write(&file, &newer).map_err(|e| format!("a write through a new open: {e}"))?;
        let mut buf = [0u8; 64];
        let old = f.read_at(&mut buf, 0).map(|n| String::from_utf8_lossy(&buf[..n]).into_owned());
        let old = old.map(|t| t.chars().take(16).collect::<String>());
        check(errno_of(&old) == Some(libc::EIO), &format!("a read through the old descriptor after a new open wrote: {old:?}"))?;
        drop(f);
        Ok(())
    })();
    let closed = unserve(target, served);
    r?;
    let closed = closed?;
    let want = if change { fs::Closed::NotWrittenBack } else { fs::Closed::Clean };
    check(closed == want, &format!("the eject after the new VM: {closed:?}, not {want:?}"))
}

/// Review 1b M1: a volume vold asked read-only whose VM answers its mount with a check pending. It must stay
/// read-only: no check, no switch (which would make it writable), and vold is told r, not R.
fn read_only_asked(mnt: &std::path::Path, target: &CString) -> Result<(), String> {
    let hello = |read_only, check_pending| fsvm_proto::Hello { fs_kind: fsvm_proto::FS_VFAT, read_only, was_dirty: check_pending, check_pending, root: ROOT_GUEST };
    check(fs::ready_letter(true, &hello(true, false)) == b'r', "asked read-only: vold must hear r")?;
    check(fs::ready_letter(true, &hello(true, true)) == b'r', "asked read-only, a check pending: vold must hear r")?;
    check(fs::ready_letter(false, &hello(false, false)) == b'R', "served writable: R")?;
    check(fs::ready_letter(false, &hello(true, true)) == b'c', "checking: c")?;
    check(fs::ready_letter(false, &hello(true, false)) == b'r', "write-protected: r")?;
    let dev = fuse_mount(target)?;
    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    let switched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut vm = FakeVm::new();
    vm.check = Some(CheckPlan { polls: 0, lose_switch: false, switch_delay: Duration::ZERO, switched: switched.clone() });
    std::thread::spawn(move || vm.serve(vm_end));
    let client = Client::new(StreamTransport(our_end), Deadlines::default());
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, true, true, 0, false, true, Box::new(CleanRestart));
    let (told_tx, told_rx) = mpsc::channel::<u8>();
    let told_tx = std::sync::Mutex::new(told_tx);
    filesystem.spawn_checker(Box::new(move |what: u8| {
        let _ = told_tx.lock().unwrap().send(what);
    }));
    let closer = filesystem.closer();
    let (end_tx, end_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = end_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
    });
    let r = (|| -> Result<(), String> {
        let file = mnt.join("ro.txt");
        // An honest check takes two polls of a second: well within this.
        let told = told_rx.recv_timeout(Duration::from_secs(4)).ok();
        check(told.is_none(), &format!("vold was told {:?} for a volume asked read-only", told.map(|c| c as char)))?;
        check(!switched.load(std::sync::atomic::Ordering::SeqCst), "the switch to writable was asked of the VM")?;
        let w = std::fs::write(&file, b"no");
        check(errno_of(&w) == Some(libc::EROFS), &format!("a write to a volume asked read-only: {w:?}"))?;
        Ok(())
    })();
    // SAFETY: plain system call on a valid string.
    let umounted = unsafe { libc::umount2(target.as_ptr(), 0) } == 0;
    let ended = end_rx.recv_timeout(Duration::from_secs(10)).is_ok();
    let _ = closer.close(Duration::from_secs(1), Duration::from_secs(5));
    r?;
    check(umounted && ended, "unmount")
}

/// Review 1b M6: a deep directory's path looked up again inside one request, one slow LOOKUP after another, after a
/// new VM took over. The request must end within its time (Deadlines::operation, 2 s here), not after every lookup's
/// own deadline. (A file of the old VM is not looked up by fsvmd again: its inode answers ESTALE and the kernel looks
/// each name up in a request of its own.)
fn slow_lookups(mnt: &std::path::Path, target: &CString) -> Result<(), String> {
    let deep = "d0/d1/d2/d3/d4/d5/d6/d7/f.txt";
    let second = Duration::from_secs(1);
    let deadlines =
        Deadlines { hello: second, meta: second, mutate: second, io: second, mount: second, listing: 2 * second, operation: 2 * second };
    let session = RestartWith { files: vec![(deep.into(), b"deep".to_vec())], lookup_delay: Duration::from_millis(300), deadlines };
    let served = serve_at(target, FakeVm::with_files(&[(deep, &b"deep"[..])]), deadlines, false, Box::new(session))?;
    let r = (|| -> Result<(), String> {
        let dir = mnt.join("d0/d1/d2/d3/d4/d5/d6/d7");
        check(std::fs::read(mnt.join(deep)).map_err(|e| e.to_string())? == b"deep", "read before the break")?;
        check(std::fs::read_dir(&dir).map_err(|e| e.to_string())?.count() == 1, "listing before the break")?;
        let _ = served.vm_side.shutdown(std::net::Shutdown::Both);
        // The kernel knows the path: OPENDIR reaches fsvmd for the deep directory, whose eight names fsvmd looks up
        // again in the new VM at 300 ms each (the session breaks in this request or in the file's release before).
        let t = std::time::Instant::now();
        let listing = std::fs::read_dir(&dir).map(|l| l.count());
        let took = t.elapsed();
        check(took < Duration::from_millis(2600), &format!("the request took {took:?}: {listing:?}"))?;
        check(errno_of(&listing) == Some(libc::EIO), &format!("a request past its time: {listing:?}"))?;
        Ok(())
    })();
    let closed = unserve(target, served);
    r?;
    closed.map(|_| ())
}

/// Review 1b L2: the VM has no handle left. The app's open gets EMFILE (too many open files), not EIO.
fn no_handle_left(mnt: &std::path::Path, target: &CString) -> Result<(), String> {
    let mut vm = FakeVm::with_files(&[("e.txt", &b"e"[..])]);
    vm.max_handles = 2;
    let served = serve_at(target, vm, Deadlines::default(), false, Box::new(NoRestart))?;
    let r = (|| -> Result<(), String> {
        let file = mnt.join("e.txt");
        let a = std::fs::File::open(&file).map_err(|e| format!("first open: {e}"))?;
        let b = std::fs::File::open(&file).map_err(|e| format!("second open: {e}"))?;
        let c = std::fs::File::open(&file);
        check(errno_of(&c) == Some(libc::EMFILE), &format!("an open beyond the VM's handles: {c:?}"))?;
        drop((a, b));
        std::fs::File::open(&file).map_err(|e| format!("an open after two closed: {e}"))?;
        Ok(())
    })();
    let closed = unserve(target, served);
    r?;
    closed.map(|_| ())
}

fn ctx() -> fuse::filesystem::Context {
    fuse::filesystem::Context { uid: 0, gid: 0, pid: 1 }
}

/// Review 1b M7: a file opened, then unlinked, while the VM answers GETATTR through its handle with a directory. The
/// open file must keep its kind: EIO, never a directory's attributes for an inode opened as a file.
fn unlinked_open_file() -> Result<(), String> {
    use fuse::filesystem::FileSystem;
    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::new();
    vm.handle_attr_dir = true;
    std::thread::spawn(move || vm.serve(vm_end));
    let client = Client::new(StreamTransport(our_end), Deadlines::default());
    let f = fs::FsvmFs::new(client, ROOT_GUEST, false, false, 0, false, false, Box::new(NoRestart));
    let (entry, h, _) = f.create(ctx(), 1, c"x", 0o600, libc::O_RDWR as u32, 0, None).map_err(|e| format!("create: {e}"))?;
    let h = h.ok_or("create gave no handle")?;
    f.unlink(ctx(), 1, c"x").map_err(|e| format!("unlink: {e}"))?;
    let got = f.getattr(ctx(), entry.inode, Some(h));
    let mode = got.as_ref().map(|(st, _)| st.st_mode & libc::S_IFMT).ok();
    check(errno_of(&got) == Some(libc::EIO), &format!("getattr of the open, unlinked file: {got:?}, file type {mode:?}"))
}

/// Review 1b L1: the partitions of one drive hold MAX_OPEN_LISTING_BYTES of open listings together, not each.
fn listings_of_a_drive() -> Result<(), String> {
    use fuse::filesystem::FileSystem;
    // A directory of 12000 names of 200 bytes: about 3 MiB of a listing's 4.
    let many = || {
        let mut vm = FakeVm::new();
        for i in 0..12000u64 {
            let name = format!("{i:0200}").into_bytes();
            vm.nodes.insert(1000 + i, FakeNode { kind: Kind::File, parent: ROOT_GUEST, name, data: Vec::new() });
        }
        vm
    };
    let card = std::sync::Arc::new(fs::Listings::default());
    let part = |vm: FakeVm| -> Result<fs::FsvmFs, String> {
        let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
        std::thread::spawn(move || vm.serve(vm_end));
        let client = Client::new(StreamTransport(our_end), Deadlines::default());
        Ok(fs::FsvmFs::new(client, ROOT_GUEST, false, false, 0, false, false, Box::new(NoRestart)).with_listings(card.clone()))
    };
    let parts = [part(many())?, part(many())?];
    let mut open = 0usize;
    for p in &parts {
        loop {
            match p.opendir(ctx(), 1, 0) {
                Ok(_) => open += 1,
                Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => break,
                Err(e) => return Err(format!("opendir: {e}")),
            }
            check(open <= 20, "listings without end")?;
        }
    }
    let each = 12000 * (200 + fsvm_proto::LISTING_ENTRY_COST);
    check(open * each <= fsvm_proto::MAX_OPEN_LISTING_BYTES, &format!("{open} listings of {each} bytes open on one drive"))?;
    check(card.used() == open * each, &format!("{} bytes counted for {open} listings", card.used()))?;
    // A partition that goes gives its listings' memory back.
    drop(parts);
    check(card.used() == 0, &format!("{} bytes still counted after the partitions went", card.used()))
}

/// A drive's partition (fsvmd drive.rs PartSession): no new session after a broken one, and giving up ends only this
/// partition, never the process.
struct GivesUp(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl fs::Session for GivesUp {
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        anyhow::bail!("no new session for this partition")
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Two partitions of one drive, each with its own FUSE mount and session, in one process: the first one's session
/// breaks for good, it answers EIO and its orderly stop says it was not written back, while the second keeps
/// writing and reading and stops clean.
fn two_partitions(mnt: &std::path::Path) -> Result<(), String> {
    let dirs = [mnt.with_extension("a"), mnt.with_extension("b")];
    let mut serving = Vec::new();
    for dir in &dirs {
        std::fs::create_dir_all(dir).map_err(|e| format!("mount point: {e}"))?;
        let target = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
        let dev = fuse_mount(&target)?;
        let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
        let vm_side = vm_end.try_clone().map_err(|e| e.to_string())?;
        std::thread::spawn(move || FakeVm::new().serve(vm_end));
        let gave_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client = Client::new(StreamTransport(our_end), Deadlines::default());
        let filesystem =
            fs::FsvmFs::new(client, ROOT_GUEST, false, false, 0, false, false, Box::new(GivesUp(gave_up.clone())));
        let closer = filesystem.closer();
        let (end_tx, end_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = end_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
        });
        serving.push((target, vm_side, gave_up, closer, end_rx));
    }
    let r = (|| -> Result<(), String> {
        for dir in &dirs {
            std::fs::write(dir.join("p.txt"), dir.as_os_str().as_encoded_bytes())
                .map_err(|e| format!("a write before the break: {e}"))?;
        }
        // The first partition's session ends (its server in the drive's VM is gone) and no new one comes.
        let _ = serving[0].1.shutdown(std::net::Shutdown::Both);
        let gone = std::fs::metadata(dirs[0].join("never-looked-up"));
        check(gone.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::EIO), &format!("the broken partition: {gone:?}"))?;
        check(serving[0].2.load(std::sync::atomic::Ordering::SeqCst), "the broken partition did not give up")?;
        let again = std::fs::read(dirs[0].join("p.txt"));
        check(again.is_err(), "the partition that gave up still serves")?;
        // The second one is untouched: writable, and reads back what it wrote.
        check(!serving[1].2.load(std::sync::atomic::Ordering::SeqCst), "the other partition gave up too")?;
        std::fs::write(dirs[1].join("after.txt"), b"still writable").map_err(|e| format!("the other partition: {e}"))?;
        check(std::fs::read(dirs[1].join("after.txt")).map_err(|e| e.to_string())? == b"still writable", "read back")?;
        check(std::fs::read(dirs[1].join("p.txt")).map_err(|e| e.to_string())? == dirs[1].as_os_str().as_encoded_bytes(), "read back")?;
        Ok(())
    })();
    let mut stops = Vec::new();
    for (target, _, _, closer, end_rx) in &serving {
        // SAFETY: plain system call on a valid string.
        let umounted = unsafe { libc::umount2(target.as_ptr(), 0) } == 0;
        let ended = end_rx.recv_timeout(Duration::from_secs(10)).is_ok();
        stops.push((umounted, ended, closer.close(Duration::from_secs(1), Duration::from_secs(5))));
    }
    for dir in &dirs {
        let _ = std::fs::remove_dir(dir);
    }
    r?;
    check(stops.iter().all(|s| s.0 && s.1), &format!("unmounts and FUSE loop ends: {stops:?}"))?;
    check(stops[0].2 == fs::Closed::NotWrittenBack, &format!("the partition that gave up stopped {:?}", stops[0].2))?;
    check(stops[1].2 == fs::Closed::Clean, &format!("the other partition stopped {:?}", stops[1].2))?;
    Ok(())
}

/// Review 1b, after M1: an app's OBB image as vold mounts it (FUSE read-only, fsvmd_obb read-only as asked). A read
/// must never answer EROFS: its files open for reading and read back, only writes are refused.
fn obb_read(mnt: &std::path::Path, target: &CString) -> Result<(), String> {
    let dev = fuse_mount_flags(target, libc::MS_RDONLY)?;
    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    let vm = FakeVm::with_files(&[("HELLO.TXT", &b"hello from the obb"[..]), ("dir/inner.bin", &b"inner"[..])]);
    std::thread::spawn(move || vm.serve(vm_end));
    let client = Client::new(StreamTransport(our_end), Deadlines::default());
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, true, true, 0, true, false, Box::new(NoRestart));
    let closer = filesystem.closer();
    let (end_tx, end_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = end_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
    });
    let r = (|| -> Result<(), String> {
        let hello = std::fs::read(mnt.join("HELLO.TXT"));
        check(hello.as_deref().ok() == Some(&b"hello from the obb"[..]), &format!("reading a file of the OBB: {hello:?}"))?;
        let inner = std::fs::read(mnt.join("dir/inner.bin"));
        check(inner.as_deref().ok() == Some(&b"inner"[..]), &format!("reading a file in a folder of the OBB: {inner:?}"))?;
        let w = std::fs::OpenOptions::new().write(true).open(mnt.join("HELLO.TXT"));
        check(errno_of(&w) == Some(libc::EROFS), &format!("an open for writing: {w:?}"))?;
        Ok(())
    })();
    // SAFETY: plain system call on a valid string.
    let umounted = unsafe { libc::umount2(target.as_ptr(), 0) } == 0;
    let ended = end_rx.recv_timeout(Duration::from_secs(10)).is_ok();
    let _ = closer.close(Duration::from_secs(1), Duration::from_secs(5));
    r?;
    check(umounted && ended, "unmount")
}

/// Mounts FUSE at `target` with vold's options, as `mounted` does.
fn fuse_mount(target: &CString) -> Result<std::fs::File, String> {
    fuse_mount_flags(target, 0)
}

/// The same with extra mount flags (an OBB: MS_RDONLY, vold fs/Fsvm.cpp MountFuse).
fn fuse_mount_flags(target: &CString, extra: libc::c_ulong) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    let dev = std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").map_err(|e| format!("/dev/fuse: {e}"))?;
    let opts = CString::new(format!(
        "fd={},rootmode=40000,default_permissions,allow_other,user_id=0,group_id=0,max_read=131072",
        dev.as_raw_fd()
    ))
    .unwrap();
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOATIME | extra;
    // SAFETY: plain system call on valid strings.
    if unsafe { libc::mount(c"/dev/fuse".as_ptr(), target.as_ptr(), c"fuse".as_ptr(), flags, opts.as_ptr().cast()) } != 0 {
        return Err(format!("mounting FUSE: {}", std::io::Error::last_os_error()));
    }
    Ok(dev)
}

/// A new VM after a broken session: an honest one that mounted the volume clean and writable.
struct CleanRestart;

impl fs::Session for CleanRestart {
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        let (vm_end, our_end) = UnixStream::pair()?;
        std::thread::spawn(move || FakeVm::new().serve(vm_end));
        let hello = fsvm_proto::Hello {
            fs_kind: fsvm_proto::FS_VFAT,
            read_only: false,
            was_dirty: false,
            check_pending: false,
            root: ROOT_GUEST,
        };
        Ok((Client::new(StreamTransport(our_end), Deadlines::default()), hello))
    }
    fn stop_vm(&mut self, _within: Duration) {}
}

/// The check after the mount (fs::FsvmFs::spawn_checker) for a volume the VM found dirty: writes are refused while it
/// runs, vold hears W once the switch made it writable, and writes work then. `lose_switch`: the VM goes away during
/// the switch (its answer lost, as when it is killed after marking the volume clean), and the new VM's clean mount
/// must make the volume writable (review M5 of 2026-11-19: the read-only flag was a latch).
fn checked(mnt: &std::path::Path, target: &CString, lose_switch: bool) -> Result<(), String> {
    let dev = fuse_mount(target)?;
    let (vm_end, our_end) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::new();
    vm.check = Some(CheckPlan { polls: 0, lose_switch, switch_delay: Duration::ZERO, switched: Default::default() });
    std::thread::spawn(move || vm.serve(vm_end));
    let client = Client::new(StreamTransport(our_end), Deadlines::default());
    let filesystem = fs::FsvmFs::new(client, ROOT_GUEST, false, true, 0, false, true, Box::new(CleanRestart));
    let (told_tx, told_rx) = mpsc::channel::<u8>();
    let told_tx = std::sync::Mutex::new(told_tx);
    filesystem.spawn_checker(Box::new(move |what: u8| {
        let _ = told_tx.lock().unwrap().send(what);
    }));
    let closer = filesystem.closer();
    let (end_tx, end_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = end_tx.send(format!("{:?}", fs::serve_fuse(dev, filesystem)));
    });
    let file = mnt.join("checked.txt");
    let early = std::fs::write(&file, b"too early");
    check(early.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::EROFS), &format!("a write while checking: {early:?}"))?;
    let told = told_rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "vold was told nothing within 10 s")?;
    check(told == b'W', &format!("vold was told {:?}, not W", told as char))?;
    std::fs::write(&file, b"after the check").map_err(|e| format!("a write after the switch: {e}"))?;
    check(std::fs::read(&file).map_err(|e| e.to_string())? == b"after the check", "read back after the switch")?;
    std::fs::remove_file(&file).map_err(|e| e.to_string())?;
    // SAFETY: plain system call on a valid string.
    check(unsafe { libc::umount2(target.as_ptr(), 0) } == 0, "unmount after the check")?;
    end_rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "the FUSE loop did not end after the unmount")?;
    let expected = if lose_switch { fs::Closed::NotWrittenBack } else { fs::Closed::Clean };
    check(closer.close(Duration::from_secs(1), Duration::from_secs(5)) == expected, "orderly stop")?;
    // Nothing more for vold, and the Checker went with the volume.
    check(told_rx.recv_timeout(Duration::from_millis(1500)).is_err(), "vold was told more after the stop")?;
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

/// Mid-call VM replacement must never turn an old inode into a handle or mutation of its replacement.
fn interrupted_file(op: u16) -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem, SetattrValid};
    let ctx = || Context { uid: 0, gid: 0, pid: 1 };
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"ORIGINAL")]);
    vm.lose_op = Some(op);
    std::thread::spawn(move || vm.serve(b));
    let deadlines = Deadlines::default();
    let session = RestartWith { files: vec![("a.txt".into(), b"REPLACEMENT".to_vec())], lookup_delay: Duration::ZERO, deadlines };
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), ROOT_GUEST, false, false, 0, false, false, Box::new(session));
    let ino = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let result = if op == 21 {
        f.open(ctx(), ino, 0).map(|_| ())
    } else if op == 3 {
        f.getattr(ctx(), ino, None).map(|_| ())
    } else {
        // SAFETY: every stat64 field is valid as zero.
        let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
        attr.st_size = 1;
        attr.st_mtime = 1_700_000_100;
        let valid = if op == 12 { SetattrValid::SIZE } else { SetattrValid::MTIME };
        f.setattr(ctx(), ino, attr, None, valid).map(|_| ())
    };
    check(errno_of(&result) == Some(libc::EIO), &format!("op {op} crossed the restart: {result:?}"))?;
    let new = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?;
    check(new.inode != ino, "the replacement reused the interrupted file's inode")?;
    check(new.attr.st_size == 11, "a replay truncated the replacement")?;
    Ok(())
}

struct SlowRestart;

impl fs::Session for SlowRestart {
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        std::thread::sleep(Duration::from_millis(900).min(_deadline.saturating_duration_since(std::time::Instant::now())));
        anyhow::bail!("the mount handshake did not finish")
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) {}
}

fn restart_budget() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem};
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut vm = FakeVm::new();
        vm.lookup_delay = Duration::from_millis(200);
        vm.lose_op = Some(2);
        // Delay the broken reply so that recovery begins late in the request.
        std::thread::sleep(Duration::from_millis(250));
        vm.serve(b);
    });
    let deadlines = Deadlines { meta: Duration::from_millis(400), operation: Duration::from_millis(500), ..Default::default() };
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), ROOT_GUEST, false, false, 0, false, false, Box::new(SlowRestart));
    let start = std::time::Instant::now();
    let r = f.lookup(Context { uid: 0, gid: 0, pid: 1 }, 1, c"a");
    let took = start.elapsed();
    check(r.is_err(), "the broken request succeeded")?;
    check(took < Duration::from_millis(650), &format!("a 500 ms request held for {took:?} during restart"))
}

fn interrupted_checker() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem};
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"only reads")]);
    vm.check = Some(CheckPlan { polls: 0, lose_switch: true, switch_delay: Duration::ZERO, switched: Default::default() });
    std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), ROOT_GUEST, false, true, 0, false, true, Box::new(CleanRestart));
    f.lookup(Context { uid: 0, gid: 0, pid: 1 }, 1, c"a.txt").map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel();
    f.spawn_checker(Box::new(move |b| { let _ = tx.send(b); }));
    check(rx.recv_timeout(Duration::from_secs(6)) == Ok(b'W'), "the checker did not recover")?;
    let closed = f.closer().close(Duration::from_secs(1), Duration::from_secs(3));
    check(closed == fs::Closed::NotWrittenBack, &format!("eject after an interrupted repair with app reads only: {closed:?}"))
}

fn descriptor_setattr() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem, SetattrValid};
    let ctx = || Context { uid: 0, gid: 0, pid: 1 };
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    std::thread::spawn(move || FakeVm::with_files(&[("a.txt", b"ORIGINAL")]).serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), ROOT_GUEST, false, false, 0, false, false, Box::new(NoRestart));
    let ino = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let h = f.open(ctx(), ino, libc::O_RDWR as u32).map_err(|e| e.to_string())?.0.unwrap();
    f.unlink(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?;
    // SAFETY: every stat64 field is valid as zero.
    let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 3;
    attr.st_mtime = 1_700_000_100;
    let result = f.setattr(ctx(), ino, attr, Some(h), SetattrValid::SIZE | SetattrValid::MTIME);
    check(result.as_ref().is_ok_and(|(a, _)| a.st_size == 3), &format!("ftruncate of an unlinked open file: {result:?}"))
}

/// Queueing behind the checker consumes the same request budget.
fn queued_request() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let switched = Arc::new(AtomicBool::new(false));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::new();
    vm.check = Some(CheckPlan { polls: 1, lose_switch: false, switch_delay: Duration::from_millis(900), switched: switched.clone() });
    std::thread::spawn(move || vm.serve(b));
    let deadlines = Deadlines { operation: Duration::from_millis(200), ..Default::default() };
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), ROOT_GUEST, false, true, 0, false, true, Box::new(NoRestart));
    let (tx, rx) = mpsc::channel();
    f.spawn_checker(Box::new(move |b| { let _ = tx.send(b); }));
    let wait_until = std::time::Instant::now() + Duration::from_secs(3);
    while !switched.load(Ordering::SeqCst) && std::time::Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(1));
    }
    check(switched.load(Ordering::SeqCst), "the checker never started its switch")?;
    let start = std::time::Instant::now();
    let result = f.getattr(Context { uid: 0, gid: 0, pid: 1 }, 1, None);
    let took = start.elapsed();
    check(errno_of(&result) == Some(libc::EIO), "the queued request did not fail")?;
    check(took < Duration::from_millis(350), &format!("a 200 ms queued request waited {took:?}"))?;
    check(rx.recv_timeout(Duration::from_secs(3)) == Ok(b'W'), "the checker never completed")?;
    f.closer().close(Duration::from_secs(1), Duration::from_secs(3));
    Ok(())
}

/// Expired VM-call time must not discard the kernel's reference and handle cleanup.
fn queued_cleanup() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let ctx = || Context { uid: 0, gid: 0, pid: 1 };
    let switched = Arc::new(AtomicBool::new(false));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"cleanup")]);
    vm.check = Some(CheckPlan { polls: 1, lose_switch: false, switch_delay: Duration::from_millis(900), switched: switched.clone() });
    std::thread::spawn(move || vm.serve(b));
    let short = Duration::from_millis(50);
    let deadlines = Deadlines { meta: short, mutate: short, io: short, operation: Duration::from_millis(200), ..Default::default() };
    let card = Arc::new(fs::Listings::default());
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), ROOT_GUEST, false, true, 0, false, true, Box::new(NoRestart)).with_listings(card.clone());
    let ino = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let file = f.open(ctx(), ino, 0).map_err(|e| e.to_string())?.0.unwrap();
    let dir = f.opendir(ctx(), 1, 0).map_err(|e| e.to_string())?.0.unwrap();
    check(card.used() > 0, "the fixture did not hold listing memory")?;
    let (tx, rx) = mpsc::channel();
    f.spawn_checker(Box::new(move |b| { let _ = tx.send(b); }));
    let wait_until = std::time::Instant::now() + Duration::from_secs(3);
    while !switched.load(Ordering::SeqCst) && std::time::Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(1));
    }
    check(switched.load(Ordering::SeqCst), "the checker never started")?;
    let release_dir = f.releasedir(ctx(), 1, 0, dir);
    f.forget(ctx(), ino, 1);
    let release_file = f.release(ctx(), ino, 0, file, false, false, None);
    check(rx.recv_timeout(Duration::from_secs(3)) == Ok(b'W'), "the checker never completed")?;
    let next = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let old_file = f.fsync(ctx(), ino, false, file);
    let used = card.used();
    check(release_dir.is_ok() && release_file.is_ok() && used == 0 && next != ino && errno_of(&old_file) == Some(libc::EBADF),
        &format!("cleanup lost: releasedir {release_dir:?}, release {release_file:?}, listing {used}, inode {ino}->{next}, old handle {old_file:?}"))?;
    f.closer().close(Duration::from_secs(1), Duration::from_secs(3));
    Ok(())
}

/// A handle keeps its file kind after unlink, including every attribute-changing reply.
fn descriptor_kind(op: u16) -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem, SetattrValid};
    let ctx = || Context { uid: 0, gid: 0, pid: 1 };
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"ORIGINAL")]);
    vm.wrong_attr_op = Some(op);
    std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), ROOT_GUEST, false, false, 0, false, false, Box::new(NoRestart));
    let ino = f.lookup(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let h = f.open(ctx(), ino, libc::O_RDWR as u32).map_err(|e| e.to_string())?.0.unwrap();
    f.unlink(ctx(), 1, c"a.txt").map_err(|e| e.to_string())?;
    // SAFETY: every stat64 field is valid as zero.
    let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
    attr.st_size = 3;
    attr.st_mtime = 1_700_000_100;
    let valid = if op == 12 { SetattrValid::SIZE } else { SetattrValid::MTIME };
    let result = f.setattr(ctx(), ino, attr, Some(h), valid);
    check(errno_of(&result) == Some(libc::EIO), &format!("op {op} changed an unlinked open file's kind: {result:?}"))
}

/// A VM that ends during connect gets one new attempt, without restarting the request clock.
fn dead_vm_connection_retry() -> Result<(), String> {
    use std::time::Instant;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut retry = reconnect::DeadVmRetry::default();
    check(!retry.after_connect_failure(false, deadline), "a live VM's failed connection was retried")?;
    check(retry.after_connect_failure(true, deadline), "the VM ended during connect but no replacement was tried")?;
    check(!retry.after_connect_failure(true, deadline), "more than one replacement connection was tried")?;
    let mut expired = reconnect::DeadVmRetry::default();
    check(!expired.after_connect_failure(true, Instant::now()), "an expired request got a new connection budget")
}

fn review_1b_r() -> Result<(), String> {
    let cases: Vec<(&str, Result<(), String>)> = vec![
        ("mid-open", interrupted_file(21)),
        ("mid-getattr", interrupted_file(3)),
        ("mid-truncate", interrupted_file(12)),
        ("mid-mtime", interrupted_file(13)),
        ("descriptor-setattr", descriptor_setattr()),
        ("descriptor-truncate-kind", descriptor_kind(12)),
        ("descriptor-mtime-kind", descriptor_kind(13)),
        ("restart-budget", restart_budget()),
        ("dead-vm-connect", dead_vm_connection_retry()),
        ("queue-budget", queued_request()),
        ("cleanup-after-queue", queued_cleanup()),
        ("checker-lost-changes", interrupted_checker()),
    ];
    let mut failed = Vec::new();
    for (name, result) in cases {
        match result {
            Ok(()) => println!("review-1b-r {name} PASS"),
            Err(why) => { println!("review-1b-r {name} FAIL: {why}"); failed.push(name); }
        }
    }
    check(failed.is_empty(), &format!("review-1b-r failures: {failed:?}"))
}


struct DirectoryRestart(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl fs::Session for DirectoryRestart {
    fn restart(&mut self, _deadline: std::time::Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, fsvm_proto::Hello)> {
        let (a, b) = UnixStream::pair()?;
        let mut vm = FakeVm::with_files(&[("dir/new", b"replacement")]);
        vm.mtime_counter = Some(self.0.clone());
        std::thread::spawn(move || vm.serve(b));
        Ok((Client::new(StreamTransport(a), Deadlines::default()), fsvm_proto::Hello {
            fs_kind: fsvm_proto::FS_VFAT, read_only: false, was_dirty: false, check_pending: false, root: 1,
        }))
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) {}
}

fn directory_timestamp_cases() -> Result<(), String> {
    use fuse::filesystem::{Context, FileSystem, SetattrValid};
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    let mut failures = Vec::new();
    for op in [3, 13] {
        let ctx = || Context { uid: 0, gid: 0, pid: 1 };
        let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
        let mut vm = FakeVm::with_files(&[("dir/old", b"original")]);
        vm.lose_op = Some(op);
        std::thread::spawn(move || vm.serve(b));
        let mutations = Arc::new(AtomicUsize::new(0));
        let fs = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), 1,
            false, false, 0, false, false, Box::new(DirectoryRestart(mutations.clone())));
        let ino = fs.lookup(ctx(), 1, c"dir").map_err(|e| e.to_string())?.inode;
        // SAFETY: all stat64 fields accept zero.
        let mut attr: libc::stat64 = unsafe { std::mem::zeroed() };
        attr.st_mtime = 1_700_000_100;
        let result = fs.setattr(ctx(), ino, attr, None, SetattrValid::MTIME);
        let count = mutations.load(Ordering::SeqCst);
        let continued = fs.getattr(ctx(), ino, None).is_ok() && fs.lookup(ctx(), 1, c"dir").ok().map(|e| e.inode) == Some(ino);
        let _ = fs.closer().close(Duration::from_secs(1), Duration::from_secs(2));
        if errno_of(&result) == Some(libc::EIO) && count == 0 && continued {
            println!("review-1b-rr directory-op-{op} PASS, new-generation mutations {count}");
        } else {
            failures.push(format!("op{op}: result {result:?}, replacement mutations {count}, lookup continuity {continued}"));
        }
    }
    check(failures.is_empty(), &format!("directory timestamp replay: {failures:?}"))
}
