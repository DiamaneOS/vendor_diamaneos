// Copyright (C) 2026 DiamaneOS
// SPDX-License-Identifier: Apache-2.0

//! The production single-worker FUSE loop, with record sockets as its kernel endpoint and a counted protocol peer.

use crate::fake_vm::{CheckPlan, FakeVm};
use crate::fs;
use fuse::filesystem::{Context, FileSystem};
use fsvm_proto::{Client, Deadlines, Hello, StreamTransport};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc};
use std::time::{Duration, Instant};

fn check(ok: bool, message: impl Into<String>) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}

struct Session(Arc<AtomicBool>);
impl fs::Session for Session {
    fn restart(&mut self, _deadline: Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)> {
        anyhow::bail!("this counted session cannot restart")
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) { self.0.store(true, Ordering::SeqCst); }
}

fn context() -> Context { Context { uid: 0, gid: 0, pid: std::process::id() as libc::pid_t } }

fn records() -> Result<(File, File), String> {
    let mut fds = [-1; 2];
    // SAFETY: the socket pair writes two owned descriptors into the array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: both descriptors are valid, distinct, and transferred once.
    let a = unsafe { File::from_raw_fd(fds[0]) };
    let b = unsafe { File::from_raw_fd(fds[1]) };
    let timeout = libc::timeval { tv_sec: 4, tv_usec: 0 };
    // SAFETY: a valid timeval is passed with its exact length.
    check(unsafe { libc::setsockopt(a.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO,
        (&timeout as *const libc::timeval).cast(), std::mem::size_of_val(&timeout) as libc::socklen_t) } == 0,
        "record socket timeout")?;
    Ok((a, b))
}

fn send(peer: &mut File, opcode: u32, unique: u64, ino: u64, body: &[u8]) -> Result<(), String> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(40u32 + body.len() as u32).to_le_bytes());
    packet.extend_from_slice(&opcode.to_le_bytes());
    packet.extend_from_slice(&unique.to_le_bytes());
    packet.extend_from_slice(&ino.to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(&std::process::id().to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(body);
    peer.write_all(&packet).map_err(|e| e.to_string())
}

fn receive(peer: &mut File) -> Result<(u64, i32, Vec<u8>), String> {
    loop {
        let mut packet = vec![0; 8192];
        let n = peer.read(&mut packet).map_err(|e| e.to_string())?;
        check(n >= 16, "short FUSE reply")?;
        packet.truncate(n);
        let id = u64::from_le_bytes(packet[8..16].try_into().unwrap());
        if id == 0 { continue; }
        let error = i32::from_le_bytes(packet[4..8].try_into().unwrap());
        return Ok((id, error, packet[16..].to_vec()));
    }
}

fn release_body(handle: u64) -> Vec<u8> {
    let mut body = handle.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 16]);
    body
}

fn wait_for(mut predicate: impl FnMut() -> bool, within: Duration) -> bool {
    let end = Instant::now() + within;
    while !predicate() {
        if Instant::now() >= end { return false; }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

fn dispatch(first: usize) -> Result<(), String> {
    let live = Arc::new(AtomicUsize::new(0));
    let closes = Arc::new(AtomicUsize::new(0));
    let forgets = Arc::new(AtomicUsize::new(0));
    let gave_up = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(AtomicBool::new(false));
    let switching = Arc::new(AtomicBool::new(false));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"cleanup")]);
    vm.max_handles = 1;
    vm.live_handles = Some(live.clone());
    vm.close_counter = Some(closes.clone());
    vm.forget_counter = Some(forgets.clone());
    vm.switch_gate = Some(gate.clone());
    vm.check = Some(CheckPlan { polls: 1, lose_switch: false, switch_delay: Duration::from_millis(900), switched: switching.clone() });
    let guest = std::thread::spawn(move || vm.serve(b));
    let deadlines = Deadlines { meta: Duration::from_millis(100), mutate: Duration::from_millis(100),
        operation: Duration::from_millis(200), ..Default::default() };
    let card = Arc::new(fs::Listings::default());
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), 1, false, true, 0, false, true,
        Box::new(Session(gave_up.clone()))).with_listings(card.clone());
    let ino = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let handle = f.open(context(), ino, 0).map_err(|e| e.to_string())?.0.unwrap();
    let dir = f.opendir(context(), 1, 0).map_err(|e| e.to_string())?.0.unwrap();
    check(live.load(Ordering::SeqCst) == 1 && card.used() > 0, "fixture holds no resources")?;
    let closer = f.closer();
    let (done_tx, done) = mpsc::channel();
    f.spawn_checker(Box::new(move |state| { let _ = done_tx.send(state); }));
    let (mut peer, endpoint) = records()?;
    let worker = std::thread::spawn(move || fs::serve_fuse(endpoint, f));
    let mut init = vec![0; 64];
    init[..4].copy_from_slice(&7u32.to_le_bytes());
    init[4..8].copy_from_slice(&31u32.to_le_bytes());
    send(&mut peer, 26, 1, 0, &init)?;
    let init_reply = receive(&mut peer)?;
    check(init_reply.0 == 1 && init_reply.1 == 0, "FUSE INIT failed")?;
    gate.store(true, Ordering::SeqCst);
    check(wait_for(|| switching.load(Ordering::SeqCst), Duration::from_secs(3)), "checker did not switch")?;
    let start = Instant::now();
    for index in [first, (first + 1) % 3, (first + 2) % 3] {
        match index {
            0 => send(&mut peer, 18, 2, ino, &release_body(handle))?,
            1 => send(&mut peer, 29, 3, 1, &release_body(dir))?,
            _ => send(&mut peer, 2, 4, ino, &1u64.to_le_bytes())?,
        }
    }
    send(&mut peer, 3, 5, 1, &[0; 16])?;
    send(&mut peer, 34, 6, 1, &[0; 8])?;
    let mut seen = Vec::new();
    for _ in 0..4 { seen.push(receive(&mut peer)?); }
    let took = start.elapsed();
    let cleanup_ok = seen.iter().filter(|(id, e, _)| (*id == 2 || *id == 3) && *e == 0).count() == 2;
    let request_timed = seen.iter().any(|(id, e, _)| *id == 5 && *e == -libc::EIO);
    let dispatched = seen.iter().any(|(id, e, _)| *id == 6 && *e == -libc::ENOSYS);
    let ahead_of_checker = done.try_recv().is_err();
    check(!ahead_of_checker || done.recv_timeout(Duration::from_secs(3)) == Ok(b'W'), "checker did not finish")?;
    let remote_closed = wait_for(|| live.load(Ordering::SeqCst) == 0 && card.used() == 0 && forgets.load(Ordering::SeqCst) == 1, Duration::from_millis(500));
    let actual_closes = closes.load(Ordering::SeqCst);
    // A fresh OPEN in the same one-slot peer proves capacity recovery rather than teardown.
    send(&mut peer, 1, 7, 1, b"a.txt\0")?;
    let entry = receive(&mut peer)?;
    let mut reopened = false;
    if entry.1 == 0 && entry.2.len() >= 8 {
        let new_ino = u64::from_le_bytes(entry.2[..8].try_into().unwrap());
        send(&mut peer, 14, 8, new_ino, &[0; 8])?;
        let open = receive(&mut peer)?;
        if open.1 == 0 && open.2.len() >= 8 {
            let new_handle = u64::from_le_bytes(open.2[..8].try_into().unwrap());
            reopened = new_ino != ino;
            send(&mut peer, 18, 9, new_ino, &release_body(new_handle))?;
            let _ = receive(&mut peer)?;
            wait_for(|| live.load(Ordering::SeqCst) == 0, Duration::from_secs(1));
        }
    }
    let healthy = !gave_up.load(Ordering::SeqCst);
    let _ = closer.close(Duration::from_secs(1), Duration::from_secs(2));
    // SAFETY: shutdown operates on the valid owned record socket.
    unsafe { libc::shutdown(peer.as_raw_fd(), libc::SHUT_RDWR); }
    drop(peer);
    let _ = worker.join();
    let _ = guest.join();
    check(cleanup_ok && request_timed && dispatched && ahead_of_checker && took < Duration::from_millis(500)
        && remote_closed && actual_closes == 1 && reopened && healthy,
        format!("cleanup first{first}: dispatch {took:?}, replies {:?}, before-check {ahead_of_checker}, guest closed {remote_closed}, CLOSE count {actual_closes}, capacity {reopened}, healthy {healthy}",
            seen.iter().map(|(id, e, _)| (*id, *e)).collect::<Vec<_>>()))?;
    println!("cleanup first{first} PASS, production worker {took:?}, guest handles0, acknowledged CLOSE1/FORGET1, same-session capacity restored");
    Ok(())
}

fn close_outcome(unanswered: bool) -> Result<(), String> {
    let live = Arc::new(AtomicUsize::new(0));
    let gave_up = Arc::new(AtomicBool::new(false));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"cleanup")]);
    vm.live_handles = Some(live.clone());
    vm.close_never_reply = unanswered;
    let guest = std::thread::spawn(move || vm.serve(b));
    let deadlines = if unanswered { Deadlines { meta: Duration::from_millis(50), operation: Duration::from_millis(200), ..Default::default() } } else { Deadlines::default() };
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), deadlines), 1, false, false, 0, false, false,
        Box::new(Session(gave_up.clone())));
    let ino = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let h = f.open(context(), ino, 0).map_err(|e| e.to_string())?.0.unwrap();
    f.release(context(), ino, 0, h, false, false, None).map_err(|e| e.to_string())?;
    let ended = wait_for(|| gave_up.load(Ordering::SeqCst) == unanswered && live.load(Ordering::SeqCst) == 0, Duration::from_millis(500));
    let _ = f.closer().close(Duration::from_secs(1), Duration::from_secs(1));
    drop(f);
    let _ = guest.join();
    check(ended, "unacknowledged CLOSE left the guest slot alive after host RELEASE")?;
    println!("cleanup CLOSE unanswered={unanswered} PASS, guest handles0, session ended={unanswered}");
    Ok(())
}

// Reused numeric handle IDs in a replacement session must not receive old CLOSE requests.
struct Replacement(Arc<AtomicUsize>);
impl fs::Session for Replacement {
    fn restart(&mut self, _deadline: Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)> {
        let (a, b) = UnixStream::pair()?;
        let mut vm = FakeVm::with_files(&[("a.txt", b"replacement")]);
        vm.close_counter = Some(self.0.clone());
        std::thread::spawn(move || vm.serve(b));
        Ok((Client::new(StreamTransport(a), Deadlines::default()), Hello { root: 1, read_only: false,
            check_pending: false, fs_kind: fsvm_proto::FS_VFAT, was_dirty: false }))
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) {}
}

fn generation_cleanup() -> Result<(), String> {
    let closes = Arc::new(AtomicUsize::new(0));
    let switching = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(AtomicBool::new(false));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let mut vm = FakeVm::with_files(&[("a.txt", b"old")]);
    vm.switch_gate = Some(gate.clone());
    vm.check = Some(CheckPlan { polls: 1, lose_switch: true, switch_delay: Duration::from_millis(900), switched: switching.clone() });
    let guest = std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), 1,
        false, true, 0, false, true, Box::new(Replacement(closes.clone())));
    let ino = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let h = f.open(context(), ino, 0).map_err(|e| e.to_string())?.0.unwrap();
    let (tx, rx) = mpsc::channel();
    f.spawn_checker(Box::new(move |state| { let _ = tx.send(state); }));
    gate.store(true, Ordering::SeqCst);
    check(wait_for(|| switching.load(Ordering::SeqCst), Duration::from_secs(3)), "lost-switch fixture")?;
    f.release(context(), ino, 0, h, false, false, None).map_err(|e| e.to_string())?;
    check(rx.recv_timeout(Duration::from_secs(3)) == Ok(b'W'), "replacement checker did not finish")?;
    let next = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let _ = f.getattr(context(), next, None).map_err(|e| e.to_string())?;
    let observed = closes.load(Ordering::SeqCst);
    let _ = f.closer().close(Duration::from_secs(1), Duration::from_secs(1));
    drop(f);
    let _ = guest.join();
    check(observed == 0, "old CLOSE crossed into replacement generation")?;
    println!("cleanup generation PASS, replacement CLOSE count0");
    Ok(())
}

pub fn run() -> Result<(), String> {
    let mut failures = Vec::new();
    for first in 0..3 { if let Err(e) = dispatch(first) { failures.push(e); } }
    for unanswered in [false, true] { if let Err(e) = close_outcome(unanswered) { failures.push(e); } }
    if let Err(e) = generation_cleanup() { failures.push(e); }
    check(failures.is_empty(), format!("cleanup custody/dispatch failures: {failures:?}"))
}

fn evicted_forget(errno: i32) -> Result<(), String> {
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let count = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let mut vm = FakeVm::with_files(&[("a.txt", b"survivor"), ("old.txt", b"old")]);
    vm.forget_errno = Some(errno);
    vm.forget_counter = Some(count.clone());
    let guest = std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), 1,
        false, false, 0, false, false, Box::new(Session(ended.clone())));
    let live = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let old = f.lookup(context(), 1, c"old.txt").map_err(|e| e.to_string())?.inode;
    f.forget(context(), old, 1);
    check(wait_for(|| count.load(Ordering::SeqCst) != 0, Duration::from_secs(2)), "no eviction FORGET")?;
    std::thread::sleep(Duration::from_millis(30));
    let result = f.getattr(context(), live, None);
    let healthy = result.is_ok() && !ended.load(Ordering::SeqCst);
    drop(f);
    guest.join().map_err(|_| "eviction guest panicked")?;
    check(healthy, format!("evicted FORGET {errno} ended a healthy session: {:?}", result.err()))?;
    println!("evicted FORGET {errno} PASS, unrelated inode remains usable");
    Ok(())
}

fn large_reclaim() -> Result<(), String> {
    const COUNT: usize = 10000;
    let count = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let mut vm = FakeVm::with_files(&[("a.txt", b"survivor")]);
    for index in 0..COUNT {
        vm.nodes.insert(1000 + index as u64, crate::fake_vm::FakeNode {
            kind: fsvm_proto::Kind::File, parent: 1, name: format!("cache{index}").into_bytes(), data: Vec::new(),
        });
    }
    vm.next = 1000 + COUNT as u64;
    vm.forget_counter = Some(count.clone());
    vm.first_forget_delay = Some(Duration::from_millis(800));
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let guest = std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), 1,
        false, false, 0, false, false, Box::new(Session(ended.clone())));
    let live = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let mut inodes = Vec::new();
    for index in 0..COUNT {
        let name = std::ffi::CString::new(format!("cache{index}")).unwrap();
        inodes.push(f.lookup(context(), 1, &name).map_err(|e| format!("lookup{index}: {e}"))?.inode);
    }
    f.forget(context(), inodes[0], 1);
    check(wait_for(|| count.load(Ordering::SeqCst) != 0, Duration::from_secs(2)), "reclaim did not start")?;
    for &ino in &inodes[1..] { f.forget(context(), ino, 1); }
    // Unknown duplicate cleanup must not turn into another admitted obligation.
    for _ in 0..10000 { f.forget(context(), inodes[0], 1); }
    let start = Instant::now();
    let result = f.getattr(context(), live, None);
    let foreground_before_drain = count.load(Ordering::SeqCst) < COUNT;
    let drained = wait_for(|| count.load(Ordering::SeqCst) == COUNT || ended.load(Ordering::SeqCst), Duration::from_secs(25));
    let healthy = result.is_ok() && !ended.load(Ordering::SeqCst);
    let complete = count.load(Ordering::SeqCst) == COUNT;
    let elapsed = start.elapsed();
    drop(f);
    guest.join().map_err(|_| "reclaim guest panicked")?;
    check(healthy && complete && drained && foreground_before_drain,
        format!("large reclaim: healthy{healthy} complete{complete} fair{foreground_before_drain} result{:?}", result.err()))?;
    println!("large reclaim PASS, {COUNT} legitimate lookups retired, foreground turn before drain, elapsed {elapsed:?}");
    Ok(())
}

fn slow_dirty_close() -> Result<(), String> {
    let closes = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    let mut vm = FakeVm::with_files(&[("a.txt", b"survivor")]);
    vm.close_counter = Some(closes.clone());
    vm.close_delay = Duration::from_millis(6100);
    let (a, b) = UnixStream::pair().map_err(|e| e.to_string())?;
    let guest = std::thread::spawn(move || vm.serve(b));
    let f = fs::FsvmFs::new(Client::new(StreamTransport(a), Deadlines::default()), 1,
        false, false, 0, false, false, Box::new(Session(ended.clone())));
    let live = f.lookup(context(), 1, c"a.txt").map_err(|e| e.to_string())?.inode;
    let (created, handle, _) = f.create(context(), 1, c"dirty", 0o600, libc::O_RDWR as u32, 0, None)
        .map_err(|e| e.to_string())?;
    f.release(context(), created.inode, 0, handle.unwrap(), false, false, None).map_err(|e| e.to_string())?;
    check(wait_for(|| closes.load(Ordering::SeqCst) == 1, Duration::from_secs(2)), "dirty CLOSE did not start")?;
    let result = f.getattr(context(), live, None);
    let healthy = result.is_ok() && !ended.load(Ordering::SeqCst);
    drop(f);
    guest.join().map_err(|_| "dirty guest panicked")?;
    check(healthy, format!("responsive dirty CLOSE over five seconds ended the session: {:?}", result.err()))?;
    println!("slow dirty CLOSE PASS, 6.1s reply and unrelated foreground I/O succeed in the same session");
    Ok(())
}

pub fn run_rereview() -> Result<(), String> {
    let mut failures = Vec::new();
    for errno in [libc::ESTALE, libc::ENOENT] {
        if let Err(e) = evicted_forget(errno) { failures.push(e); }
    }
    if let Err(e) = large_reclaim() { failures.push(e); }
    if let Err(e) = slow_dirty_close() { failures.push(e); }
    check(failures.is_empty(), format!("rereview cleanup failures: {failures:?}"))
}
