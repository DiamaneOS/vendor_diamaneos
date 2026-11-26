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

//! fsvmd's FUSE translation (fsvmd/src/fs.rs, compiled here as it is) against a scripted filesystem VM: a fuzzed
//! sequence of the calls Android's kernel makes, each answered by a VM thread on the other end of a socket pair from
//! a fuzzed reply script, with new VMs when a session breaks. What reaches the kernel is checked: attributes, modes and
//! owners as vold set them, sizes and times within the protocol's limits, reads and writes within what was asked,
//! listings of sound names, and Android's own inode numbers, each with one place in the tree and never reused.
//!
//! The script never brings a fourth broken session (fsvmd ends then, by design): the third new VM answers every
//! request with an errno.

use crate::fs::{FsvmFs, Session};
use crate::vm_replies::{assert_name, name_from, parse_request, quick_deadlines, reply, Input, Sent};
use fsvm_proto::{Client, Hello, StreamTransport, MAX_IO, MAX_FILE_SIZE, MTIME_MAX, MTIME_MIN, REQ_HEADER, RSP_MAGIC};
use fuse::filesystem::{
    Context, DirectoryIterator, Entry, FileSystem, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::{Arc, Mutex, Once};
use std::thread::JoinHandle;
use std::time::Duration;

const ROOT: u64 = 1;

/// FSVM_FUZZ_TRACE=1 prints every call, request and reply of a replayed input (the fuzzer never sets it).
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("FSVM_FUZZ_TRACE").is_some())
}
const UNKNOWN_INO: u64 = u64::MAX >> 1;
const UID: u32 = 10_042;
const GID: u32 = 1023;

/// The reply script, shared by every VM of one input.
struct Script {
    data: Vec<u8>,
    at: usize,
}

impl Script {
    fn take<T>(&mut self, f: impl FnOnce(&mut Input) -> T) -> T {
        let rest = self.data.get(self.at..).unwrap_or(&[]).to_vec();
        let mut i = Input::new(&rest);
        let v = f(&mut i);
        self.at += rest.len() - i.left();
        v
    }
}

type Threads = Arc<Mutex<Vec<JoinHandle<()>>>>;

fn read_request(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut b = vec![0u8; REQ_HEADER];
    s.read_exact(&mut b).ok()?;
    let le32 = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let mut rest = le32(&b, 12) + le32(&b, 44);
    if u16::from_le_bytes([b[4], b[5]]) == fsvm_proto::Op::Write as u16 {
        rest += le32(&b, 40);
    }
    // fsvmd never sends more than a name pair and one WRITE.
    assert!(rest <= 2 * 1020 + MAX_IO as usize, "request of {rest} bytes");
    let at = b.len();
    b.resize(at + rest, 0);
    s.read_exact(&mut b[at..]).ok()?;
    Some(b)
}

/// One VM: answers each request from the script, or (errno_only) with EIO, until the script closes it or fsvmd
/// drops its end.
fn vm(mut s: UnixStream, script: Arc<Mutex<Script>>, errno_only: bool) {
    while let Some(req) = read_request(&mut s) {
        let sent: Sent = parse_request(&req);
        if errno_only {
            let mut b = Vec::new();
            b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            b.extend_from_slice(&sent.id.to_le_bytes());
            b.extend_from_slice(&(-5i32).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            if s.write_all(&b).is_err() {
                return;
            }
            continue;
        }
        let mut close = false;
        let r = script.lock().unwrap().take(|i| reply(i, &sent, 0, &mut close));
        if tracing() {
            eprintln!("  vm: op {} id {} node {} node2 {} -> {} bytes{}", sent.op, sent.id, sent.node, sent.node2, r.len(),
                if close { ", closed" } else { "" });
        }
        if s.write_all(&r).is_err() || close {
            return;
        }
    }
}

fn spawn_vm(script: &Arc<Mutex<Script>>, threads: &Threads, errno_only: bool) -> UnixStream {
    let (a, b) = UnixStream::pair().expect("socket pair");
    let script = script.clone();
    threads.lock().unwrap().push(std::thread::spawn(move || vm(b, script, errno_only)));
    a
}

struct FuzzSession {
    script: Arc<Mutex<Script>>,
    threads: Threads,
    restarts: usize,
}

impl Session for FuzzSession {
    fn restart(&mut self) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)> {
        self.restarts += 1;
        let a = spawn_vm(&self.script, &self.threads, self.restarts >= 3);
        // What the new VM said at its mount, already checked by fsvm_proto in fsvmd (decode_hello): only sound values.
        let (flags, root) = self.script.lock().unwrap().take(|i| (i.u8(), i.u8() as u64 + 1));
        let hello = Hello { fs_kind: 2, read_only: flags & 5 != 0, was_dirty: flags & 2 != 0, check_pending: flags & 4 != 0, root };
        Ok((Client::new(StreamTransport(a), quick_deadlines()), hello))
    }

    fn stop_vm(&mut self, _within: Duration) {}
}

struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ZeroCopyWriter for Sink {
    fn write_from(&mut self, _f: &mut std::fs::File, _count: usize, _off: u64) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

struct Source(io::Cursor<Vec<u8>>);

impl Read for Source {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}

impl ZeroCopyReader for Source {
    fn read_to(&mut self, _f: &mut std::fs::File, _count: usize, _off: u64) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The tree as the kernel learnt it from the entries it got.
struct Model {
    nodes: HashMap<u64, (u64, Vec<u8>, bool, u64)>, // ino -> (parent, name, is_dir, lookups)
    /// Nodes whose name another node took (a name that came back as another kind): the kernel still holds their
    /// lookups, and the VM may name them again.
    unnamed: HashMap<u64, (u64, Vec<u8>, bool, u64)>,
    retired: HashSet<u64>,
    dir_mode: u32,
    file_mode: u32,
}

impl Model {
    fn assert_stat(&self, ino: u64, st: &libc::stat64) {
        assert_eq!(st.st_ino, ino, "attributes of another inode");
        assert!(st.st_uid == UID && st.st_gid == GID, "owner {}:{} from the card", st.st_uid, st.st_gid);
        let dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        let want = if dir { libc::S_IFDIR | self.dir_mode } else { libc::S_IFREG | self.file_mode };
        assert_eq!(st.st_mode, want, "mode {:o}", st.st_mode);
        assert!(st.st_size >= 0 && st.st_size as u64 <= MAX_FILE_SIZE, "size {}", st.st_size);
        assert!(!dir || st.st_size == 0, "directory with a size");
        assert!((MTIME_MIN..=MTIME_MAX).contains(&st.st_mtime), "mtime {}", st.st_mtime);
        assert!((0..1_000_000_000).contains(&st.st_mtime_nsec), "mtime ns {}", st.st_mtime_nsec);
        if let Some(n) = self.nodes.get(&ino) {
            assert_eq!(n.2, dir, "inode {ino} changed its kind");
        }
        if ino == ROOT {
            assert!(dir, "the root is not a directory");
        }
    }

    /// An entry for `name` in `parent`: Android's own inode number, never reused, with this one place in the tree.
    fn entry(&mut self, parent: u64, name: &[u8], e: &Entry) {
        let ino = e.inode;
        assert!(ino != 0 && ino != ROOT && ino != UNKNOWN_INO, "entry inode {ino}");
        assert!(!self.retired.contains(&ino), "inode {ino} reused after its node went");
        self.assert_stat(ino, &e.attr);
        let dir = e.attr.st_mode & libc::S_IFMT == libc::S_IFDIR;
        match self.nodes.get_mut(&ino) {
            Some(n) => {
                assert!(n.0 == parent && n.1 == name, "inode {ino} under a second name");
                n.3 += 1;
            }
            None => {
                // A name that held another kind of node keeps that inode, now without a name, and its lookups.
                let gone: Vec<u64> =
                    self.nodes.iter().filter(|(_, n)| n.0 == parent && n.1 == name).map(|(i, _)| *i).collect();
                for i in gone {
                    let n = self.nodes.remove(&i).unwrap();
                    self.unnamed.insert(i, n);
                }
                let lookups = match self.unnamed.remove(&ino) {
                    Some(n) => {
                        assert!(n.0 == parent && n.1 == name && n.2 == dir, "inode {ino} back under a second name");
                        n.3 + 1
                    }
                    None => 1,
                };
                self.nodes.insert(ino, (parent, name.to_vec(), dir, lookups));
            }
        }
    }

    fn drop_name(&mut self, parent: u64, name: &[u8]) {
        let gone: Vec<u64> = self.nodes.iter().filter(|(_, n)| n.0 == parent && n.1 == name).map(|(i, _)| *i).collect();
        for ino in gone {
            self.nodes.remove(&ino);
            self.retired.insert(ino);
        }
    }

    /// Whether `ino` is `dir` or below it: the kernel never moves a directory into itself.
    fn below(&self, mut ino: u64, dir: u64) -> bool {
        for _ in 0..=self.nodes.len() {
            if ino == dir {
                return true;
            }
            if ino == ROOT {
                return false;
            }
            match self.nodes.get(&ino) {
                Some(n) => ino = n.0,
                None => return false,
            }
        }
        true
    }

    fn pick(&self, i: &mut Input) -> u64 {
        let c = i.u8();
        if c < 16 || self.nodes.is_empty() {
            return if c & 1 == 0 { ROOT } else { i.u64() };
        }
        let mut keys: Vec<u64> = self.nodes.keys().copied().collect();
        keys.sort_unstable();
        keys[c as usize % keys.len()]
    }
}

fn ctx() -> Context {
    Context { uid: 0, gid: 0, pid: 1 }
}

fn cname(i: &mut Input) -> CString {
    CString::new(name_from(i)).unwrap_or_else(|_| CString::new("x").unwrap())
}

fn ignore_sigpipe() {
    static ONCE: Once = Once::new();
    // A VM that closed its end turns fsvmd's next write into EPIPE, as on the phone, where Rust's runtime ignores
    // SIGPIPE. libFuzzer's main does not, so it is ignored here.
    ONCE.call_once(|| unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    });
}

/// Runs one input and answers how many calls succeeded (the replay test checks that its seeds reach deep).
pub fn fs_session(data: &[u8]) -> usize {
    ignore_sigpipe();
    let mut i = Input::new(data);
    let ops_len = i.u16() as usize % 1024;
    let ops = i.bytes(ops_len).to_vec();
    let cfg = i.u8();
    let root_guest = i.u8() as u64 + 1;
    let (asked_ro, vm_ro, obb, check_pending) = (cfg & 1 != 0, cfg & 2 != 0, cfg & 4 != 0, cfg & 8 != 0);
    let script = Arc::new(Mutex::new(Script { data: i.rest().to_vec(), at: 0 }));
    let threads: Threads = Arc::new(Mutex::new(Vec::new()));
    let a = spawn_vm(&script, &threads, false);
    let session = FuzzSession { script: script.clone(), threads: threads.clone(), restarts: 0 };
    let client = Client::new(StreamTransport(a), quick_deadlines());
    let fs = FsvmFs::new(client, root_guest, asked_ro, vm_ro, GID, obb, check_pending, Box::new(session)).with_owner(UID);
    let mut m = Model {
        nodes: HashMap::new(),
        unnamed: HashMap::new(),
        retired: HashSet::new(),
        dir_mode: if obb { 0o550 } else { 0o770 },
        file_mode: if obb { 0o440 } else { 0o660 },
    };
    let mut handles: Vec<u64> = Vec::new();
    let mut dir_handles: HashMap<u64, u64> = HashMap::new();
    let mut oks = 0;
    let mut o = Input::new(&ops);
    while !o.is_empty() {
        let op = o.u8() % 20;
        let ino = m.pick(&mut o);
        let h = if handles.is_empty() || o.u8() < 32 { o.u64() } else { handles[o.u8() as usize % handles.len()] };
        if tracing() {
            eprintln!("call {op} ino {ino} handle {h}, model {:?}", m.nodes);
        }
        match op {
            0 => {
                let name = cname(&mut o);
                let r = fs.lookup(ctx(), ino, &name);
                if tracing() {
                    eprintln!("  lookup {name:?} in {ino}: {:?}", r.as_ref().map(|e| e.inode));
                }
                if let Ok(e) = r {
                    oks += 1;
                    assert!(m.nodes.get(&ino).map_or(true, |n| n.2), "a lookup in a file answered");
                    m.entry(ino, name.as_bytes(), &e);
                }
            }
            1 => {
                let hh = if o.u8() & 1 == 0 { None } else { Some(h) };
                if let Ok((st, _)) = fs.getattr(ctx(), ino, hh) {
                    oks += 1;
                    m.assert_stat(ino, &st);
                }
            }
            2 => {
                // SAFETY: every field of stat64 is valid as zero.
                let mut st: libc::stat64 = unsafe { std::mem::zeroed() };
                st.st_size = o.u64() as i64;
                st.st_mtime = o.u64() as i64;
                st.st_mtime_nsec = o.u32() as i64;
                let valid = SetattrValid::from_bits_truncate(o.u32());
                if let Ok((st, _)) = fs.setattr(ctx(), ino, st, Some(h), valid) {
                    m.assert_stat(ino, &st);
                }
            }
            3 => {
                if let Ok((Some(nh), _)) = fs.open(ctx(), ino, o.u32()) {
                    oks += 1;
                    handles.push(nh);
                }
            }
            4 => {
                let _ = fs.release(ctx(), ino, 0, h, false, false, None);
                handles.retain(|x| *x != h);
            }
            5 => {
                let size = if o.u8() & 1 == 0 { MAX_IO } else { o.u32() };
                let got = Rc::new(RefCell::new(Vec::new()));
                if let Ok(n) = fs.read(ctx(), ino, h, Sink(got.clone()), size, o.u64(), None, 0) {
                    oks += 1;
                    assert_eq!(n, got.borrow().len(), "read count is not the bytes given");
                    assert!(n <= size.min(MAX_IO) as usize, "{n} bytes read of {size}");
                }
            }
            6 => {
                let size = if o.u8() & 1 == 0 { o.u16() as u32 } else { o.u32() % (MAX_IO + 8) };
                let src = Source(io::Cursor::new(vec![0x5a; size as usize]));
                if let Ok(n) = fs.write(ctx(), ino, h, src, size, o.u64(), None, false, 0) {
                    oks += 1;
                    assert!(n <= size as usize && size <= MAX_IO, "{n} written of {size}");
                }
            }
            7 => {
                let _ = fs.flush(ctx(), ino, h, 0);
            }
            8 => {
                let _ = fs.fsync(ctx(), ino, o.u8() & 1 == 0, h);
            }
            9 => {
                let _ = fs.fsyncdir(ctx(), ino, o.u8() & 1 == 0, h);
            }
            10 => {
                let name = cname(&mut o);
                if let Ok((e, nh, _)) = fs.create(ctx(), ino, &name, 0o600, o.u32(), 0, None) {
                    oks += 1;
                    m.entry(ino, name.as_bytes(), &e);
                    assert_eq!(e.attr.st_mode & libc::S_IFMT, libc::S_IFREG, "create made a directory");
                    handles.extend(nh);
                }
            }
            11 => {
                let name = cname(&mut o);
                if let Ok(e) = fs.mkdir(ctx(), ino, &name, 0o700, 0, None) {
                    oks += 1;
                    m.entry(ino, name.as_bytes(), &e);
                    assert_eq!(e.attr.st_mode & libc::S_IFMT, libc::S_IFDIR, "mkdir made a file");
                }
            }
            12 | 13 => {
                let name = cname(&mut o);
                let r = if op == 12 { fs.unlink(ctx(), ino, &name) } else { fs.rmdir(ctx(), ino, &name) };
                if r.is_ok() {
                    oks += 1;
                    m.drop_name(ino, name.as_bytes());
                }
            }
            14 => {
                let from = cname(&mut o);
                let to_dir = m.pick(&mut o);
                let to = cname(&mut o);
                let flags = if o.u8() % 8 == 0 { o.u32() } else { 0 };
                let moving = m.nodes.iter().find(|(_, n)| n.0 == ino && n.1 == from.as_bytes()).map(|(i, _)| *i);
                // The kernel's VFS never moves a directory into itself or below it, and answers a rename of a name onto
                // itself without asking the filesystem.
                if moving.is_some_and(|d| m.below(to_dir, d)) || (ino == to_dir && from == to) {
                    continue;
                }
                let r = fs.rename(ctx(), ino, &from, to_dir, &to, flags);
                if tracing() {
                    eprintln!("  rename {from:?} in {ino} to {to:?} in {to_dir} flags {flags}: {:?}", r.as_ref().err());
                }
                if r.is_ok() {
                    oks += 1;
                    m.drop_name(to_dir, to.as_bytes());
                    if let Some(x) = moving {
                        if let Some(n) = m.nodes.get_mut(&x) {
                            n.0 = to_dir;
                            n.1 = to.as_bytes().to_vec();
                        }
                    }
                }
            }
            15 => {
                if let Ok((Some(dh), _)) = fs.opendir(ctx(), ino, 0) {
                    oks += 1;
                    dir_handles.insert(dh, ino);
                }
            }
            16 => {
                let dh = if dir_handles.is_empty() || o.u8() < 16 {
                    o.u64()
                } else {
                    let mut k: Vec<u64> = dir_handles.keys().copied().collect();
                    k.sort_unstable();
                    k[o.u8() as usize % k.len()]
                };
                let size = o.u16() as u32;
                let offset = o.u16() as u64;
                if let Ok(mut it) = fs.readdir(ctx(), ino, dh, size, offset) {
                    oks += 1;
                    let dir = dir_handles.get(&dh).copied();
                    let mut n = 0u64;
                    while let Some(e) = it.next() {
                        n += 1;
                        assert!(n <= 65536, "listing past its cap");
                        assert_eq!(e.offset, offset + n, "entry offsets");
                        let name = e.name.to_str().expect("listed name not UTF-8");
                        assert_name(name);
                        assert!(e.type_ == libc::DT_DIR as u32 || e.type_ == libc::DT_REG as u32, "entry type {}", e.type_);
                        assert_ne!(e.ino, 0, "listed inode 0");
                        if e.ino != UNKNOWN_INO {
                            // A known inode is the node of this very name, never another file's.
                            let node = m.nodes.get(&e.ino);
                            if let (Some(node), Some(dir)) = (node, dir) {
                                assert!(node.0 == dir && node.1 == e.name.to_bytes(), "listed {name:?} with the inode of another node");
                                assert_eq!(node.2, e.type_ == libc::DT_DIR as u32, "listed {name:?} as another kind");
                            }
                        }
                    }
                }
            }
            17 => {
                let dh = *dir_handles.keys().min().unwrap_or(&h);
                let _ = fs.releasedir(ctx(), ino, 0, dh);
                dir_handles.remove(&dh);
            }
            18 => {
                if let Ok(st) = fs.statfs(ctx(), ino) {
                    oks += 1;
                    let b = st.f_bsize as u64;
                    assert!(b.is_power_of_two() && (512..=1 << 20).contains(&b), "block size {b}");
                    assert!(st.f_bavail <= st.f_bfree && st.f_bfree <= st.f_blocks, "free above the total");
                    assert!((st.f_blocks as u64) <= (1u64 << 44) / b * 4, "{} blocks", st.f_blocks);
                    assert_eq!(st.f_namemax, 255);
                }
            }
            _ => {
                if let Some(n) = m.nodes.get(&ino) {
                    let all = n.3;
                    let count = if o.u8() & 1 == 0 { all } else { o.u8() as u64 % (all + 1) };
                    fs.forget(ctx(), ino, count);
                    let n = m.nodes.get_mut(&ino).unwrap();
                    n.3 -= count;
                    if n.3 == 0 {
                        m.nodes.remove(&ino);
                        m.retired.insert(ino);
                    }
                } else {
                    fs.forget(ctx(), ino, o.u8() as u64);
                }
            }
        }
    }
    // The orderly stop at the end: write back and unmount within a short budget.
    let _ = fs.closer().close(Duration::ZERO, Duration::from_millis(50));
    drop(fs);
    let all: Vec<JoinHandle<()>> = threads.lock().unwrap().drain(..).collect();
    for t in all {
        if let Err(p) = t.join() {
            std::panic::resume_unwind(p);
        }
    }
    oks
}
