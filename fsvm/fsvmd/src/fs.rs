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

//! The FUSE side. Android's kernel talks FUSE to this process, this process talks the checked protocol to the VM.
//! Nothing from the VM reaches the kernel unchecked: names, sizes and times pass fsvm_proto first, inode numbers are
//! Android's own, and owner, group and mode come from vold's settings, never from the card.

use fsvm_proto::client::{CallError, CallResult};
use fsvm_proto::{Attr, CheckState, Client, Hello, Kind, StreamTransport, MAX_IO, MAX_OPEN_LISTING_BYTES};
use fuse::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, FileSystem, FsOptions, OpenOptions, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ROOT: u64 = fuse::sys::ROOT_ID;
/// How long the kernel may cache names and attributes. Only this process changes the volume.
const TIMEOUT: Duration = Duration::from_secs(5);
/// d_ino for directory entries not looked up yet. The kernel looks names up before it uses them.
const UNKNOWN_INO: u64 = u64::MAX >> 1;

fn err(e: i32) -> io::Error {
    io::Error::from_raw_os_error(e)
}

fn call_err(e: CallError) -> io::Error {
    if let CallError::Broken(why) = &e {
        error!("filesystem VM session broken: {why}");
    }
    err(e.errno())
}

struct Node {
    /// The VM's id for this node, or None until it is looked up again (after the VM took the id back, or after a
    /// new VM took over the session).
    guest: Option<u64>,
    parent: u64,
    name: Vec<u8>,
    kind: Kind,
    lookups: u64,
}

/// An open file: the VM it was opened in (State::generation) and the VM's handle for it, which keeps serving the
/// file after its name went. None when the VM had no handle left (reads and writes then go by name).
struct OpenFile {
    generation: u64,
    guest: Option<u64>,
}

/// Most files open at once (the VM keeps 1024 handles, beyond that files are served by name).
const MAX_OPEN_FILES: usize = 8192;

struct Listing {
    entries: Vec<(CString, Kind, u64)>,
    /// What fsvm_proto counted for it (MAX_LISTING_BYTES).
    bytes: usize,
}

/// Most directory listings open at once. Each holds at most MAX_LISTING_BYTES, all together at most
/// MAX_OPEN_LISTING_BYTES.
const MAX_LISTINGS: usize = 64;
/// Most new VMs for one mount within RESTART_WINDOW. After that fsvmd exits and vold reports the card as not opened.
const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(600);
/// Deepest path resolved again after a VM change. FAT and exFAT paths cannot go deeper with names of one byte.
const MAX_DEPTH: usize = 2048;

/// Starts a new VM for the same volume when the session broke (a missed deadline, a VM that stopped).
pub trait Session: Send {
    /// Returns the new client and what the new VM said at its mount (root node, read-only, check pending).
    fn restart(&mut self) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)>;
    /// Stops the VM and waits up to `within` for its end.
    fn stop_vm(&mut self, within: Duration);
}

struct State {
    client: Client<StreamTransport<UnixStream>>,
    root_guest: u64,
    session: Box<dyn Session>,
    restarts: Vec<Instant>,
    read_only: Arc<AtomicBool>,
    nodes: HashMap<u64, Node>,
    by_guest: HashMap<u64, u64>,
    by_name: HashMap<(u64, Vec<u8>), u64>,
    next_ino: u64,
    listings: HashMap<u64, Listing>,
    listing_bytes: usize,
    files: HashMap<u64, OpenFile>,
    next_handle: u64,
    /// Counts new VMs. A file handle is the count at its open: after a new VM took over, acknowledged writes of the
    /// old one may be lost, and fsync or close on an older handle says so (EIO).
    generation: u64,
    /// Set once the filesystem was written back and unmounted in the VM before a stop: nothing is served after.
    closed: bool,
    /// The volume is served read-only until the VM's check after the mount passes (Checker).
    check_pending: bool,
}

pub struct FsvmFs {
    state: Arc<Mutex<State>>,
    closing: Arc<AtomicBool>,
    /// The switch after the check runs (the volume is briefly unmounted in the VM): an orderly stop waits for it.
    switching: Arc<AtomicBool>,
    read_only: Arc<AtomicBool>,
    gid: u32,
    dir_mode: u32,
    file_mode: u32,
}

impl FsvmFs {
    /// `obb`: an app's OBB image, read-only for its owner's group (vold mounted these with fmask and dmask 0227).
    pub fn new(
        client: Client<StreamTransport<UnixStream>>,
        root_guest: u64,
        read_only: bool,
        gid: u32,
        obb: bool,
        check_pending: bool,
        session: Box<dyn Session>,
    ) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, Node { guest: Some(root_guest), parent: ROOT, name: Vec::new(), kind: Kind::Dir, lookups: 1 });
        let mut by_guest = HashMap::new();
        by_guest.insert(root_guest, ROOT);
        let read_only = Arc::new(AtomicBool::new(read_only || obb));
        FsvmFs {
            state: Arc::new(Mutex::new(State {
                client,
                root_guest,
                session,
                restarts: Vec::new(),
                read_only: read_only.clone(),
                nodes,
                by_guest,
                by_name: HashMap::new(),
                next_ino: ROOT + 1,
                listings: HashMap::new(),
                listing_bytes: 0,
                files: HashMap::new(),
                next_handle: 1,
                generation: 0,
                closed: false,
                check_pending,
            })),
            closing: Arc::new(AtomicBool::new(false)),
            switching: Arc::new(AtomicBool::new(false)),
            read_only,
            gid,
            dir_mode: if obb { 0o550 } else { 0o770 },
            file_mode: if obb { 0o440 } else { 0o660 },
        }
    }

    /// A handle that outlives the FUSE loop, for the orderly stop (Closer::close).
    pub fn closer(&self) -> Closer {
        Closer { state: self.state.clone(), closing: self.closing.clone(), switching: self.switching.clone() }
    }

    /// Runs the VM's check after the mount for a volume served read-only until it passes, outside vold's lock and
    /// without a time limit, then the switch to writable. `done(true)` once writable, `done(false)` when it stays
    /// read-only (vold then reports it so and SystemUI says why). Ends with the volume.
    pub fn spawn_checker(&self, done: Box<dyn Fn(bool) + Send>) {
        let checker = Checker {
            state: self.state.clone(),
            read_only: self.read_only.clone(),
            switching: self.switching.clone(),
            done,
        };
        std::thread::spawn(move || checker.run());
    }

    #[allow(clippy::useless_conversion)]
    fn stat(&self, ino: u64, a: &Attr) -> libc::stat64 {
        // SAFETY: every field of stat64 is valid as zero.
        let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };
        st.st_ino = ino;
        st.st_uid = 0;
        st.st_gid = self.gid;
        // As vold mounted cards before: group read and write, nothing for others, never executable. OBBs: read only.
        match a.kind {
            Kind::Dir => {
                st.st_mode = libc::S_IFDIR | self.dir_mode;
                st.st_nlink = 2;
            }
            Kind::File => {
                st.st_mode = libc::S_IFREG | self.file_mode;
                st.st_nlink = 1;
            }
        }
        st.st_size = a.size as i64;
        st.st_blksize = 4096;
        st.st_blocks = a.size.div_ceil(512) as i64;
        st.st_mtime = a.mtime_s;
        st.st_mtime_nsec = a.mtime_ns as i64;
        st.st_ctime = a.mtime_s;
        st.st_ctime_nsec = a.mtime_ns as i64;
        st.st_atime = a.mtime_s;
        st.st_atime_nsec = a.mtime_ns as i64;
        st
    }

    fn writable(&self) -> io::Result<()> {
        if self.read_only.load(Ordering::Relaxed) {
            Err(err(libc::EROFS))
        } else {
            Ok(())
        }
    }
}

impl State {
    fn node(&self, ino: u64) -> io::Result<&Node> {
        self.nodes.get(&ino).ok_or_else(|| err(libc::ENOENT))
    }

    fn is_dir(&self, ino: u64) -> io::Result<()> {
        match self.node(ino)?.kind {
            Kind::Dir => Ok(()),
            Kind::File => Err(err(libc::ENOTDIR)),
        }
    }

    /// Forgets the VM's id of a node and of its ancestors, so that they are looked up again.
    fn invalidate(&mut self, mut ino: u64) {
        for _ in 0..MAX_DEPTH {
            if ino == ROOT {
                return;
            }
            let Some(n) = self.nodes.get_mut(&ino) else { return };
            if let Some(g) = n.guest.take() {
                self.by_guest.remove(&g);
            }
            ino = n.parent;
        }
    }

    /// The VM's id for a node, looking the path up again where the VM's id is gone.
    fn resolve(&mut self, ino: u64, depth: usize) -> Result<u64, CallError> {
        if ino == ROOT {
            return Ok(self.root_guest);
        }
        let n = self.nodes.get(&ino).ok_or(CallError::Errno(libc::ENOENT))?;
        if let Some(g) = n.guest {
            return Ok(g);
        }
        if depth >= MAX_DEPTH {
            return Err(CallError::Errno(libc::ENAMETOOLONG));
        }
        let (parent, name, kind) = (n.parent, n.name.clone(), n.kind);
        let pg = self.resolve(parent, depth + 1)?;
        let a = self.client.lookup(pg, &name)?;
        if a.kind != kind {
            // The name now holds something else. The kernel's node for it is gone.
            return Err(CallError::Errno(libc::ENOENT));
        }
        if self.by_guest.get(&a.node).is_some_and(|&other| other != ino) {
            warn!("filesystem VM returned one node for two names");
            return Err(CallError::Errno(libc::EIO));
        }
        self.by_guest.insert(a.node, ino);
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.guest = Some(a.node);
        }
        Ok(a.node)
    }

    /// Starts a new VM after the session broke, within the restart limit. Past it fsvmd exits: the FUSE mount ends,
    /// and vold, which watches this process, reports the card as not opened.
    fn recover(&mut self, why: &str) {
        let now = Instant::now();
        self.restarts.retain(|t| now.duration_since(*t) < RESTART_WINDOW);
        if self.restarts.len() >= MAX_RESTARTS {
            error!("filesystem VM session broken ({why}), {MAX_RESTARTS} new VMs within {RESTART_WINDOW:?}, giving up");
            std::process::exit(2);
        }
        self.restarts.push(now);
        warn!("filesystem VM session broken ({why}), starting a new VM");
        match self.session.restart() {
            Ok((client, hello)) => {
                let root = hello.root;
                self.generation += 1;
                self.client = client;
                self.root_guest = root;
                if hello.read_only {
                    self.read_only.store(true, Ordering::Relaxed);
                }
                // The new VM found the volume marked dirty (the old one ended with it mounted writable): read-only
                // again until its own check passes.
                self.check_pending = hello.check_pending;
                self.by_guest.clear();
                for (&ino, n) in self.nodes.iter_mut() {
                    n.guest = if ino == ROOT { Some(root) } else { None };
                }
                self.by_guest.insert(root, ROOT);
            }
            Err(e) => {
                error!("no new filesystem VM: {e:?}");
                std::process::exit(2);
            }
        }
    }

    /// Runs one call on a node: resolves the VM's id, and on a stale id or a broken session tries once more.
    fn call<T>(&mut self, ino: u64, f: impl FnMut(&mut Client<StreamTransport<UnixStream>>, u64) -> CallResult<T>) -> io::Result<T> {
        self.call_with(ino, true, f)
    }

    /// The same for a call that is not safe to repeat (create, mkdir, unlink, rmdir): when the session broke during
    /// it, the old VM may have done it, so it is not sent again. The app gets EIO, and the next call goes to the new
    /// VM. A stale id is retried: the VM refused that call before doing anything.
    fn call_once<T>(&mut self, ino: u64, f: impl FnMut(&mut Client<StreamTransport<UnixStream>>, u64) -> CallResult<T>) -> io::Result<T> {
        self.call_with(ino, false, f)
    }

    fn call_with<T>(
        &mut self,
        ino: u64,
        replay: bool,
        mut f: impl FnMut(&mut Client<StreamTransport<UnixStream>>, u64) -> CallResult<T>,
    ) -> io::Result<T> {
        if self.closed {
            return Err(err(libc::EIO));
        }
        for attempt in 0..3 {
            let last = attempt == 2;
            let r = match self.resolve(ino, 0) {
                Ok(g) => f(&mut self.client, g),
                Err(e) => Err(e),
            };
            match r {
                Ok(v) => return Ok(v),
                Err(CallError::Errno(libc::ESTALE)) if !last => self.invalidate(ino),
                Err(CallError::Broken(why)) if !last && replay => self.recover(&why),
                Err(CallError::Broken(why)) => {
                    self.recover(&why);
                    return Err(err(libc::EIO));
                }
                Err(e) => return Err(call_err(e)),
            }
        }
        Err(err(libc::EIO))
    }

    /// Opens `ino` in the VM and keeps it as an open file. Its handle is fsvmd's own number.
    fn open_file(&mut self, ino: u64, write: bool) -> io::Result<u64> {
        if self.files.len() >= MAX_OPEN_FILES {
            return Err(err(libc::EMFILE));
        }
        let guest = match self.call(ino, |c, g| c.open_handle(g, write)) {
            Ok(h) => Some(h),
            // The VM has no handle left: this file is served by name.
            Err(e) if e.raw_os_error() == Some(libc::EMFILE) => None,
            Err(e) => return Err(e),
        };
        let h = self.next_handle;
        self.next_handle += 1;
        self.files.insert(h, OpenFile { generation: self.generation, guest });
        Ok(h)
    }

    /// The VM's handle of an open file, when it was opened in the VM that serves now.
    fn guest_handle(&self, h: u64) -> Option<u64> {
        self.files.get(&h).filter(|f| f.generation == self.generation).and_then(|f| f.guest)
    }

    /// Whether writes through this open file may have been lost: it was opened in a VM that has been replaced since.
    fn stale(&self, h: u64) -> bool {
        self.files.get(&h).is_some_and(|f| f.generation != self.generation)
    }

    /// A call through an open file's handle. A broken session starts a new VM and answers EIO: the handle is gone.
    fn handle_call<T>(
        &mut self,
        handle: u64,
        mut f: impl FnMut(&mut Client<StreamTransport<UnixStream>>, u64) -> CallResult<T>,
    ) -> io::Result<T> {
        if self.closed {
            return Err(err(libc::EIO));
        }
        match f(&mut self.client, handle) {
            Ok(v) => Ok(v),
            Err(CallError::Broken(why)) => {
                self.recover(&why);
                Err(err(libc::EIO))
            }
            Err(e) => Err(call_err(e)),
        }
    }

    /// A rename resolves both directories on every attempt, so neither id is stale after a new VM took over. Not
    /// repeated after a broken session (call_once).
    fn rename_call(&mut self, olddir: u64, from: &[u8], newdir: u64, to: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(err(libc::EIO));
        }
        for attempt in 0..3 {
            let last = attempt == 2;
            let r = match (self.resolve(olddir, 0), self.resolve(newdir, 0)) {
                (Ok(a), Ok(b)) => self.client.rename(a, from, b, to),
                (Err(e), _) | (_, Err(e)) => Err(e),
            };
            match r {
                Ok(()) => return Ok(()),
                Err(CallError::Errno(libc::ESTALE)) if !last => {
                    self.invalidate(olddir);
                    self.invalidate(newdir);
                }
                Err(CallError::Broken(why)) => {
                    self.recover(&why);
                    return Err(err(libc::EIO));
                }
                Err(e) => return Err(call_err(e)),
            }
        }
        Err(err(libc::EIO))
    }

    /// Maps the VM's node to Android's inode number. A node must keep its one place in the tree: a VM that
    /// returns the same directory under a second name could make Android see a loop.
    fn map(&mut self, parent: u64, name: &[u8], a: &Attr) -> io::Result<u64> {
        if let Some(&ino) = self.by_guest.get(&a.node) {
            let n = self.nodes.get_mut(&ino).ok_or_else(|| err(libc::EIO))?;
            if n.parent != parent || n.name != name || n.kind != a.kind {
                warn!("filesystem VM returned one node for two names");
                return Err(err(libc::EIO));
            }
            n.lookups += 1;
            return Ok(ino);
        }
        let key = (parent, name.to_vec());
        if let Some(&ino) = self.by_name.get(&key) {
            let n = self.nodes.get_mut(&ino).ok_or_else(|| err(libc::EIO))?;
            if n.kind == a.kind {
                // The same name after the VM changed or took its id back.
                if let Some(old) = n.guest.replace(a.node) {
                    self.by_guest.remove(&old);
                }
                n.lookups += 1;
                self.by_guest.insert(a.node, ino);
                return Ok(ino);
            }
            // Another kind of node under the old name: the old inode no longer has a name.
            self.by_name.remove(&key);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(ino, Node { guest: Some(a.node), parent, name: name.to_vec(), kind: a.kind, lookups: 1 });
        self.by_guest.insert(a.node, ino);
        self.by_name.insert(key, ino);
        Ok(ino)
    }

    fn rename_node(&mut self, from_dir: u64, from: &[u8], to_dir: u64, to: &[u8]) {
        if let Some(ino) = self.by_name.remove(&(from_dir, from.to_vec())) {
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.parent = to_dir;
                n.name = to.to_vec();
            }
            self.by_name.insert((to_dir, to.to_vec()), ino);
        }
    }

    fn drop_child(&mut self, parent: u64, name: &[u8]) {
        if let Some(ino) = self.by_name.remove(&(parent, name.to_vec())) {
            if let Some(n) = self.nodes.remove(&ino) {
                if let Some(g) = n.guest {
                    self.by_guest.remove(&g);
                }
            }
        }
    }
}

/// Writes the volume back and unmounts it in the VM before the VM is stopped, so an eject loses nothing and leaves
/// the card clean. Used when the FUSE loop ended (vold unmounted the volume) and on SIGTERM (vold's stop).
pub struct Closer {
    state: Arc<Mutex<State>>,
    closing: Arc<AtomicBool>,
    switching: Arc<AtomicBool>,
}

/// How an orderly stop ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Closed {
    /// Everything written back, the filesystem unmounted and marked clean, the VM stopped.
    Clean,
    /// Not everything may be on the disk: vold must not call the volume safely removed.
    NotWrittenBack,
    /// Another stop runs already (the FUSE loop ended and vold's stop request came on top). It decides.
    InProgress,
}

/// Below this the VM's dirty data counts as written.
const DIRTY_DONE: u64 = 64 << 10;
/// The write back must have made progress within this, or the stop goes on without waiting further.
const NO_PROGRESS: Duration = Duration::from_secs(4);
/// What UNMOUNT gets at least after the wait for the dirty data (when the whole stop allows that much).
const UNMOUNT_MIN: Duration = Duration::from_secs(4);
/// The VM is given this long to end before fsvmd does, so its disk is free (a mixed card's partition).
const VM_END: Duration = Duration::from_secs(3);

impl Closer {
    /// Waits up to `lock_wait` for a call in progress, then has the VM write everything back as long as its dirty
    /// data keeps going down, and unmount, all within `max` from the start. Then stops the VM and waits for its end.
    pub fn close(&self, lock_wait: Duration, max: Duration) -> Closed {
        if self.closing.swap(true, Ordering::SeqCst) {
            return Closed::InProgress;
        }
        let start = Instant::now();
        let deadline = start + max;
        // The switch after the check holds the lock while the VM unmounts, repairs and mounts again. Stopping the VM
        // in the middle could leave a repair half done, so it gets the whole time.
        let until = start + if self.switching.load(Ordering::SeqCst) { max } else { lock_wait };
        let mut guard = loop {
            match self.state.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    error!("a call to the filesystem VM is still running, stopping without writing back");
                    return Closed::NotWrittenBack;
                }
            }
        };
        if guard.closed {
            return Closed::Clean;
        }
        guard.closed = true;
        let result = if guard.client.is_broken() {
            error!("the filesystem VM session is broken, stopping without writing back");
            Closed::NotWrittenBack
        } else {
            // The VM writes back by itself (within about 1 s, at most 8 MiB waiting). Waiting while that goes down
            // gives a slow card the time it needs, and a stuck one no more than NO_PROGRESS.
            let mut least = u64::MAX;
            let mut progress_at = Instant::now();
            loop {
                let now = Instant::now();
                if now + UNMOUNT_MIN >= deadline {
                    break;
                }
                match guard.client.dirty() {
                    Ok(d) if d < DIRTY_DONE => break,
                    Ok(d) => {
                        if d < least {
                            if least != u64::MAX {
                                info!("writing back: {} KiB left", d >> 10);
                            }
                            least = d;
                            progress_at = now;
                        } else if now.duration_since(progress_at) > NO_PROGRESS {
                            warn!("writing back: no progress for {NO_PROGRESS:?}, {} KiB left", d >> 10);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("writing back: the VM did not say how much is left: {e:?}");
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let budget = deadline.saturating_duration_since(Instant::now());
            match guard.client.unmount(budget) {
                Ok(()) => {
                    info!("written back and unmounted in the VM in {:?}, the volume is clean", start.elapsed());
                    Closed::Clean
                }
                Err(e) => {
                    error!("writing back and unmounting in the VM failed after {:?}: {e:?}", start.elapsed());
                    Closed::NotWrittenBack
                }
            }
        };
        // The VM ends before fsvmd does, so nothing holds its disk any more when vold takes it back.
        guard.session.stop_vm(VM_END);
        result
    }
}

/// The read-only check runs as long as it takes. Errors it found are repaired only when it took at most this long,
/// so the repair (as long as the check, plus writes) stays short: apps wait for it and an eject waits for it.
const REPAIR_AFTER_CHECK_MAX: Duration = Duration::from_secs(20);
/// What the repair may take in the VM, and the whole switch (unmount, repair, mount, free-space count).
const REPAIR_MAX: Duration = Duration::from_secs(15);
const SWITCH_MAX: Duration = Duration::from_secs(45);
const CHECK_POLL: Duration = Duration::from_secs(1);

struct Checker {
    state: Arc<Mutex<State>>,
    read_only: Arc<AtomicBool>,
    switching: Arc<AtomicBool>,
    done: Box<dyn Fn(bool) + Send>,
}

impl Checker {
    fn run(self) {
        loop {
            std::thread::sleep(CHECK_POLL);
            let mut s = match self.state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            if s.closed {
                return;
            }
            if !s.check_pending {
                continue;
            }
            match s.client.check_poll() {
                Ok((CheckState::Running, _)) => {}
                Ok((state @ (CheckState::Passed | CheckState::Errors), ran)) => {
                    if state == CheckState::Errors && ran > REPAIR_AFTER_CHECK_MAX {
                        warn!("the check found errors after {ran:?}: the volume stays read-only, it needs a computer");
                        s.check_pending = false;
                        (self.done)(false);
                        continue;
                    }
                    info!("the check {} after {ran:?}, switching to writable", if state == CheckState::Errors { "found errors to repair" } else { "passed" });
                    self.switching.store(true, Ordering::SeqCst);
                    let r = s.client.check_switch(REPAIR_MAX, SWITCH_MAX);
                    self.switching.store(false, Ordering::SeqCst);
                    match r {
                        Ok(()) => {
                            info!("checked, the volume is writable now");
                            s.check_pending = false;
                            self.read_only.store(false, Ordering::SeqCst);
                            (self.done)(true);
                        }
                        Err(CallError::Broken(why)) => s.recover(&why),
                        Err(e) => {
                            warn!("the switch after the check failed ({}): the volume stays read-only", e.errno());
                            s.check_pending = false;
                            (self.done)(false);
                        }
                    }
                }
                Ok((CheckState::Failed | CheckState::None, _)) | Err(CallError::Errno(_)) => {
                    warn!("the check did not run or did not finish: the volume stays read-only");
                    s.check_pending = false;
                    (self.done)(false);
                }
                Err(CallError::Broken(why)) => s.recover(&why),
            }
        }
    }
}

/// Serves FUSE on vold's /dev/fuse until the mount goes. The loop's read buffer, the max_write the kernel learns in
/// INIT (FileSystem::max_buffer_size) and vold's `max_read=131072` mount option (fs/Fsvm.cpp) are all MAX_IO, the
/// most one protocol READ or WRITE carries. The buffer is taken from the filesystem itself, so the two cannot differ.
pub fn serve_fuse<F: FileSystem + Sync + Send>(dev_fuse: std::fs::File, fs: F) -> fuse::Result<()> {
    let io = fs.max_buffer_size();
    assert_eq!(io, MAX_IO, "the FUSE buffer must hold one protocol READ or WRITE");
    let mut config = fuse::FuseConfig::new();
    config.dev_fuse(dev_fuse).max_read(io).max_write(io).num_threads(1);
    config.enter_message_loop(fs)
}

pub struct DirIter {
    entries: Vec<(CString, Kind, u64)>,
    offset: u64,
    cur: usize,
}

impl DirectoryIterator for DirIter {
    fn next(&mut self) -> Option<DirEntry<'_>> {
        let (name, kind, ino) = self.entries.get(self.cur)?;
        self.cur += 1;
        Some(DirEntry {
            ino: *ino,
            offset: self.offset + self.cur as u64,
            type_: match kind {
                Kind::Dir => libc::DT_DIR.into(),
                Kind::File => libc::DT_REG.into(),
            },
            name,
        })
    }
}

impl FileSystem for FsvmFs {
    type Inode = u64;
    type Handle = u64;
    type DirIter = DirIter;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    /// The max_write crosvm's INIT reply gives the kernel. It must equal the buffer the FUSE loop reads /dev/fuse
    /// with (serve_fuse): the kernel refuses every read smaller than its header room plus max_write with EINVAL
    /// (fs/fuse/dev.c, fuse_dev_do_read). crosvm's default of 1 MiB ended each card's FUSE loop right after INIT.
    fn max_buffer_size(&self) -> u32 {
        MAX_IO
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let mut s = self.state.lock().unwrap();
        s.is_dir(parent)?;
        let a = s.call(parent, |c, g| c.lookup(g, name.to_bytes()))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        Ok(Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT })
    }

    fn forget(&self, _ctx: Context, ino: u64, count: u64) {
        if ino == ROOT {
            return;
        }
        let mut s = self.state.lock().unwrap();
        let gone = match s.nodes.get_mut(&ino) {
            Some(n) => {
                n.lookups = n.lookups.saturating_sub(count);
                n.lookups == 0
            }
            None => false,
        };
        if gone {
            if let Some(n) = s.nodes.remove(&ino) {
                if s.by_name.get(&(n.parent, n.name.clone())) == Some(&ino) {
                    s.by_name.remove(&(n.parent, n.name));
                }
                if let Some(g) = n.guest {
                    s.by_guest.remove(&g);
                    // Best effort: the VM may drop its slot. A failure only keeps a slot alive in the VM.
                    let _ = s.client.forget(g);
                }
            }
        }
    }

    fn getattr(&self, _ctx: Context, ino: u64, h: Option<u64>) -> io::Result<(libc::stat64, Duration)> {
        let mut s = self.state.lock().unwrap();
        // An open file answers through its handle, also after its name went.
        let a = match h.and_then(|h| s.guest_handle(h)) {
            Some(guest) => s.handle_call(guest, |c, g| c.getattr_handle(g))?,
            None => s.call(ino, |c, g| c.getattr(g))?,
        };
        Ok((self.stat(ino, &a), TIMEOUT))
    }

    fn setattr(
        &self,
        _ctx: Context,
        ino: u64,
        attr: libc::stat64,
        _h: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let mut s = self.state.lock().unwrap();
        let mut a = s.call(ino, |c, g| c.getattr(g))?;
        if valid.intersects(SetattrValid::SIZE | SetattrValid::MTIME | SetattrValid::MTIME_NOW) {
            self.writable()?;
        }
        if valid.contains(SetattrValid::SIZE) {
            a = s.call(ino, |c, g| c.truncate(g, attr.st_size.max(0) as u64))?;
        }
        if valid.contains(SetattrValid::MTIME_NOW) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            a = s.call(ino, |c, g| c.set_mtime(g, now.as_secs() as i64, now.subsec_nanos()))?;
        } else if valid.contains(SetattrValid::MTIME) {
            a = s.call(ino, |c, g| c.set_mtime(g, attr.st_mtime, attr.st_mtime_nsec as u32))?;
        }
        // Owner, group and mode are vold's choice for the whole volume, as they were with the kernel mount.
        Ok((self.stat(ino, &a), TIMEOUT))
    }

    fn open(&self, _ctx: Context, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.state.lock().unwrap();
        s.node(ino)?;
        let acc = flags as i32 & libc::O_ACCMODE;
        if acc != libc::O_RDONLY {
            self.writable()?;
        }
        if flags as i32 & libc::O_TRUNC != 0 {
            self.writable()?;
            s.call(ino, |c, g| c.truncate(g, 0))?;
        }
        let h = s.open_file(ino, acc != libc::O_RDONLY)?;
        Ok((Some(h), OpenOptions::empty()))
    }

    fn release(
        &self,
        _ctx: Context,
        _ino: u64,
        _flags: u32,
        h: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        if let Some(guest) = s.guest_handle(h) {
            let _ = s.handle_call(guest, |c, g| c.close_handle(g));
        }
        s.files.remove(&h);
        Ok(())
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        ino: u64,
        h: u64,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let mut s = self.state.lock().unwrap();
        let data = match s.guest_handle(h) {
            Some(guest) => s.handle_call(guest, |c, g| c.read_handle(g, offset, size.min(MAX_IO)))?,
            None => s.call(ino, |c, g| c.read(g, offset, size.min(MAX_IO)))?,
        };
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        ino: u64,
        h: u64,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        self.writable()?;
        if size > MAX_IO {
            return Err(err(libc::EINVAL));
        }
        let mut buf = vec![0u8; size as usize];
        r.read_exact(&mut buf)?;
        let mut s = self.state.lock().unwrap();
        let n = match s.guest_handle(h) {
            Some(guest) => s.handle_call(guest, |c, g| c.write_handle(g, offset, &buf))?,
            None => s.call(ino, |c, g| c.write(g, offset, &buf))?,
        };
        Ok(n as usize)
    }

    /// close(): every write already reached the VM's filesystem (FUSE writes here are write-through), and the
    /// filesystem writes it back within about two seconds, as the kernel's FAT driver did with close. An app that
    /// needs the data on the card calls fsync, and an eject writes everything back first (Closer).
    fn flush(&self, _ctx: Context, _ino: u64, h: u64, _lock_owner: u64) -> io::Result<()> {
        let s = self.state.lock().unwrap();
        if s.stale(h) {
            // A new VM took over since this file was opened: writes the old one acknowledged may be lost.
            return Err(err(libc::EIO));
        }
        Ok(())
    }

    /// fsync and fdatasync: the file's data, and for fsync its directory entry and times, are on the card when this
    /// returns.
    fn fsync(&self, _ctx: Context, ino: u64, datasync: bool, h: u64) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        if s.stale(h) {
            return Err(err(libc::EIO));
        }
        match s.guest_handle(h) {
            Some(guest) => s.handle_call(guest, |c, g| c.fsync_handle(g, datasync)),
            None => s.call(ino, |c, g| c.fsync(g, datasync)),
        }
    }

    fn fsyncdir(&self, _ctx: Context, ino: u64, datasync: bool, _h: u64) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        s.is_dir(ino)?;
        s.call(ino, |c, g| c.fsync(g, datasync))
    }

    fn create(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        _mode: u32,
        flags: u32,
        _umask: u32,
        _security_ctx: Option<&CStr>,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        s.is_dir(parent)?;
        let a = s.call_once(parent, |c, g| c.create(g, name.to_bytes(), flags as i32 & libc::O_EXCL != 0))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        let entry = Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT };
        let h = s.open_file(ino, true)?;
        Ok((entry, Some(h), OpenOptions::empty()))
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        _mode: u32,
        _umask: u32,
        _security_ctx: Option<&CStr>,
    ) -> io::Result<Entry> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        s.is_dir(parent)?;
        let a = s.call_once(parent, |c, g| c.mkdir(g, name.to_bytes()))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        Ok(Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT })
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        s.is_dir(parent)?;
        s.call_once(parent, |c, g| c.unlink(g, name.to_bytes()))?;
        s.drop_child(parent, name.to_bytes());
        Ok(())
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        s.is_dir(parent)?;
        s.call_once(parent, |c, g| c.rmdir(g, name.to_bytes()))?;
        s.drop_child(parent, name.to_bytes());
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.writable()?;
        if flags != 0 {
            // RENAME_NOREPLACE and RENAME_EXCHANGE are not offered by the VM.
            return Err(err(libc::EINVAL));
        }
        let mut s = self.state.lock().unwrap();
        s.is_dir(olddir)?;
        s.is_dir(newdir)?;
        s.rename_call(olddir, oldname.to_bytes(), newdir, newname.to_bytes())?;
        s.drop_child(newdir, newname.to_bytes());
        s.rename_node(olddir, oldname.to_bytes(), newdir, newname.to_bytes());
        Ok(())
    }

    fn opendir(&self, _ctx: Context, ino: u64, _flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.state.lock().unwrap();
        s.is_dir(ino)?;
        if s.listings.len() >= MAX_LISTINGS {
            return Err(err(libc::EMFILE));
        }
        let listing = s.call(ino, |c, g| c.list(g))?;
        if s.listing_bytes + listing.bytes > MAX_OPEN_LISTING_BYTES {
            warn!("open directory listings would take more than {MAX_OPEN_LISTING_BYTES} bytes, refusing one more");
            return Err(err(libc::ENOMEM));
        }
        let bytes = listing.bytes;
        if listing.dropped > 0 || listing.duplicates > 0 || listing.truncated {
            warn!(
                "directory listing cleaned: {} refused, {} duplicates, truncated {}",
                listing.dropped, listing.duplicates, listing.truncated
            );
        }
        let mut entries = Vec::with_capacity(listing.entries.len());
        for (name, a) in listing.entries {
            // Names passed fsvm_proto's rules, so they hold no NUL.
            let Ok(c) = CString::new(name) else { continue };
            let known = s
                .by_guest
                .get(&a.node)
                .or_else(|| s.by_name.get(&(ino, c.as_bytes().to_vec())))
                .copied()
                .unwrap_or(UNKNOWN_INO);
            entries.push((c, a.kind, known));
        }
        let h = s.next_handle;
        s.next_handle += 1;
        s.listing_bytes += bytes;
        s.listings.insert(h, Listing { entries, bytes });
        Ok((Some(h), OpenOptions::empty()))
    }

    fn readdir(&self, _ctx: Context, _ino: u64, h: u64, size: u32, offset: u64) -> io::Result<DirIter> {
        let s = self.state.lock().unwrap();
        let l = s.listings.get(&h).ok_or_else(|| err(libc::EBADF))?;
        let start = (offset as usize).min(l.entries.len());
        let mut end = start;
        let mut estimate = 0usize;
        while end < l.entries.len() && estimate < size as usize {
            estimate += (size_of::<fuse::sys::Dirent>() + l.entries[end].0.to_bytes().len() + 7) & !7;
            end += 1;
        }
        Ok(DirIter { entries: l.entries[start..end].to_vec(), offset, cur: 0 })
    }

    fn releasedir(&self, _ctx: Context, _ino: u64, _flags: u32, h: u64) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        if let Some(l) = s.listings.remove(&h) {
            s.listing_bytes -= l.bytes;
        }
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _ino: u64) -> io::Result<libc::statvfs64> {
        let mut s = self.state.lock().unwrap();
        let t = s.call(ROOT, |c, _| c.statfs())?;
        // SAFETY: every field of statvfs64 is valid as zero.
        let mut st: libc::statvfs64 = unsafe { std::mem::zeroed() };
        st.f_bsize = t.bsize as _;
        st.f_frsize = t.bsize as _;
        st.f_blocks = t.blocks as _;
        st.f_bfree = t.bfree as _;
        st.f_bavail = t.bavail as _;
        st.f_namemax = t.namemax as _;
        Ok(st)
    }
}
