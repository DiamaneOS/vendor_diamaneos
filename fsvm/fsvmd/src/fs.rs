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
use fsvm_proto::{Attr, CheckState, Client, Hello, Kind, StreamTransport, MAX_IO, MAX_LISTING_BYTES, MAX_OPEN_LISTING_BYTES};
use fuse::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, FileSystem, FsOptions, OpenOptions, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};
use log::{error, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::mem::{size_of, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Condvar;
use std::sync::{Arc, Mutex, MutexGuard};
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
    match &e {
        CallError::Broken(why) => error!("filesystem VM session broken: {why}"),
        CallError::OutOfTime => warn!("a request ran out of its time for the filesystem VM"),
        CallError::Errno(_) => {}
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
    /// A file a replaced VM served. Nothing proves that its name holds the same file in the new VM, so it is never
    /// looked up by name again: calls on it answer ESTALE, the kernel looks the name up again and gets a new inode,
    /// whose cached pages are not this one's (State::recover). Kept until the kernel forgets it.
    replaced: bool,
}

/// An open file: the VM it was opened in (State::generation), the VM's handle for it, which keeps serving the file
/// after its name went, and the kind of node it was opened as. Its I/O goes through that handle only: once another VM
/// serves the volume, the handle is gone and nothing proves that the file's name still holds the same file, so its
/// I/O fails and the app opens the file again.
struct OpenFile {
    generation: u64,
    guest: u64,
    kind: Kind,
}

/// Most files open at once (the VM keeps 1024 handles, an open beyond them fails with EMFILE).
const MAX_OPEN_FILES: usize = 8192;

struct Listing {
    entries: Vec<(CString, Kind, u64)>,
    /// What fsvm_proto counted for it (MAX_LISTING_BYTES), held in the card's Listings until the listing goes.
    _charge: Charge,
}

/// The memory all open directory listings of one card take together, at most MAX_OPEN_LISTING_BYTES. A drive's
/// partitions share one (drive.rs), a volume with a VM of its own has its own.
#[derive(Default)]
pub struct Listings {
    used: Mutex<usize>,
}

impl Listings {
    /// Takes `bytes` of the card's listing memory, or None when that would pass MAX_OPEN_LISTING_BYTES.
    fn take(self: &Arc<Self>, bytes: usize) -> Option<Charge> {
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        if *used + bytes > MAX_OPEN_LISTING_BYTES {
            return None;
        }
        *used += bytes;
        Some(Charge { listings: self.clone(), bytes })
    }

    /// What the card's open listings take now.
    pub fn used(&self) -> usize {
        *self.used.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Listing memory taken, given back when this goes (a listing released, or the volume gone with listings still open).
struct Charge {
    listings: Arc<Listings>,
    bytes: usize,
}

impl Charge {
    fn keep(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        *self.listings.used.lock().unwrap_or_else(|p| p.into_inner()) -= self.bytes - bytes;
        self.bytes = bytes;
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        *self.listings.used.lock().unwrap_or_else(|p| p.into_inner()) -= self.bytes;
    }
}

/// Most directory listings open at once. Each holds at most MAX_LISTING_BYTES, all of a card's together at most
/// MAX_OPEN_LISTING_BYTES.
const MAX_LISTINGS: usize = 64;
/// Most new VMs for one mount within RESTART_WINDOW. After that fsvmd exits and vold reports the card as not opened.
const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(600);
/// Deepest path resolved again after a VM change. FAT and exFAT paths cannot go deeper with names of one byte.
const MAX_DEPTH: usize = 2048;

/// Starts a new VM for the same volume when the session broke (a missed deadline, a VM that stopped), or for a
/// partition of a drive a new session in the drive's VM (drive.rs).
pub trait Session: Send {
    /// Returns the new client and mount result before the request's absolute deadline.
    fn restart(&mut self, deadline: Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)>;
    /// Stops the VM and waits up to `within` for its end.
    fn stop_vm(&mut self, within: Duration);
    /// No new session came up within the restart limit. A volume with a VM of its own ends fsvmd: its FUSE mount
    /// ends, and vold, which watches this process, reports the card as not opened. A partition of a drive tells vold
    /// on its own pipe and answers EIO from then on (State::failed): the drive's other partitions keep serving.
    fn give_up(&mut self) {
        std::process::exit(2);
    }
}

struct State {
    client: Client<StreamTransport<UnixStream>>,
    root_guest: u64,
    session: Box<dyn Session>,
    restarts: Vec<Instant>,
    read_only: Arc<AtomicBool>,
    /// Read-only as asked (vold's --read-only: a drive opened read-only, an OBB). Set once: no new VM, check or
    /// switch makes such a volume writable, and it has no check.
    asked_read_only: bool,
    nodes: HashMap<u64, Node>,
    by_guest: HashMap<u64, u64>,
    by_name: HashMap<(u64, Vec<u8>), u64>,
    next_ino: u64,
    listings: HashMap<u64, Listing>,
    /// The card's listing memory (Listings).
    card_listings: Arc<Listings>,
    files: HashMap<u64, OpenFile>,
    next_handle: u64,
    remote_cleanup: VecDeque<RemoteCleanup>,
    retry_forgets: VecDeque<(RemoteCleanup, Instant, Duration)>,
    close_turn: bool,
    cleanup: Arc<CleanupQueue>,
    /// Counts new VMs. A file handle is the count at its open: after a new VM took over, the old one's handle is
    /// gone, so the file's I/O fails, and acknowledged writes of the old one may be lost, so fsync or close says so
    /// (EIO).
    generation: u64,
    /// Set before a call that may change the volume in the VM that serves now (a write, create, mkdir, unlink, rmdir,
    /// rename, truncate, a new time).
    changed: bool,
    /// A VM that may have changed the volume was replaced: what it acknowledged may not be on the card. The orderly
    /// stop then reports the volume as not written back, however clean the last VM's unmount, so the user gets the
    /// "Not all changes reached this card" warning. Kept until that stop.
    lost_changes: bool,
    /// The end of the FUSE request being served (Deadlines::operation), also for a new VM's client.
    op_deadline: Option<Instant>,
    /// A new VM came up during the request being served: at most one per request.
    recovered: bool,
    /// Where notices to the kernel go (serve_fuse, notifier): what it cached of the nodes of a replaced VM.
    kernel: Option<mpsc::Sender<Vec<Notice>>>,
    /// Set once the filesystem was written back and unmounted in the VM before a stop: nothing is served after.
    closed: bool,
    /// Set when no new session came up after a broken one (Session::give_up): nothing is served after, and the
    /// orderly stop says the volume was not written back.
    failed: bool,
    /// The volume is served read-only until the VM's check after the mount passes (Checker).
    check_pending: bool,
    /// Wakes the Checker: a check is pending again (a new VM after a broken session), or the volume goes.
    wake: Arc<Condvar>,
}

/// Admission bounds include debt already transferred to remote cleanup.
const MAX_CACHED_NODES: usize = 32768;
const CLEANUP_BATCH: usize = 64;

#[derive(Clone, Copy)]
enum CleanupJob {
    Release(u64),
    ReleaseDir(u64),
    Forget(u64, u64),
}

#[derive(Clone, Copy)]
enum RemoteCleanup {
    Close { generation: u64, handle: u64 },
    Forget { generation: u64, node: u64 },
}

#[derive(Default)]
struct CleanupInbox {
    files: HashSet<u64>,
    directories: HashSet<u64>,
    nodes: HashSet<u64>,
    releases: HashSet<u64>,
    releasedirs: HashSet<u64>,
    forgets: HashMap<u64, u64>,
    ready: bool,
    stopped: bool,
}

#[derive(Default)]
struct CleanupQueue {
    inbox: Mutex<CleanupInbox>,
    wake: Condvar,
    aborted: AtomicBool,
    foreground: AtomicUsize,
    cleanup_turn: AtomicBool,
}

impl CleanupQueue {
    fn push(&self, job: CleanupJob) {
        let mut inbox = self.inbox.lock().unwrap_or_else(|p| p.into_inner());
        if self.aborted.load(Ordering::SeqCst) { return; }
        match job {
            CleanupJob::Release(h) if inbox.files.remove(&h) => { inbox.releases.insert(h); }
            CleanupJob::ReleaseDir(h) if inbox.directories.remove(&h) => { inbox.releasedirs.insert(h); }
            CleanupJob::Forget(ino, count) if inbox.nodes.contains(&ino) && count != 0 => {
                let debt = inbox.forgets.entry(ino).or_default();
                *debt = debt.saturating_add(count);
            }
            _ => return,
        }
        inbox.ready = true;
        self.wake.notify_one();
    }

    fn local_pending(&self) -> bool {
        let inbox = self.inbox.lock().unwrap_or_else(|p| p.into_inner());
        !inbox.releases.is_empty() || !inbox.releasedirs.is_empty() || !inbox.forgets.is_empty()
    }

    fn kick(&self) {
        self.inbox.lock().unwrap_or_else(|p| p.into_inner()).ready = true;
        self.wake.notify_one();
    }

    fn stop(&self) {
        let mut inbox = self.inbox.lock().unwrap_or_else(|p| p.into_inner());
        inbox.stopped = true;
        inbox.ready = true;
        self.wake.notify_one();
    }
}

struct ForegroundWaiter<'a>(&'a CleanupQueue);
impl Drop for ForegroundWaiter<'_> {
    fn drop(&mut self) { self.0.foreground.fetch_sub(1, Ordering::SeqCst); }
}

fn cleanup_worker(state: std::sync::Weak<Mutex<State>>, queue: Arc<CleanupQueue>, operation: Duration) {
    loop {
        let stopped = {
            let mut inbox = queue.inbox.lock().unwrap_or_else(|p| p.into_inner());
            while !inbox.ready && !inbox.stopped {
                inbox = queue.wake.wait(inbox).unwrap_or_else(|p| p.into_inner());
            }
            inbox.ready = false;
            inbox.stopped
        };
        let Some(state) = state.upgrade() else { return };
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if queue.foreground.load(Ordering::SeqCst) != 0 && !queue.cleanup_turn.load(Ordering::SeqCst) {
            drop(state);
            queue.kick();
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        state.drain_cleanup(&queue);
        if queue.aborted.load(Ordering::SeqCst) {
            state.end_cleanup_session(&queue);
            return;
        }
        // A retry stays separate so one refusing node cannot obstruct fresh CLOSE or FORGET work.
        let mut retry_delay = None;
        if let Some((remote, at, delay)) = state.retry_forgets.pop_front() {
            if at <= Instant::now() && (!state.close_turn || state.remote_cleanup.is_empty()) {
                state.remote_cleanup.push_front(remote);
                retry_delay = Some((remote, delay));
            } else {
                state.retry_forgets.push_back((remote, at, delay));
            }
        }
        // Alternate handle and node work when both have debt.
        let wanted = state.close_turn;
        if let Some(index) = state.remote_cleanup.iter().position(|r| matches!(r, RemoteCleanup::Close { .. }) == wanted) {
            if let Some(remote) = state.remote_cleanup.remove(index) { state.remote_cleanup.push_front(remote); }
        }
        if let Some(remote) = state.remote_cleanup.front().copied() {
            let generation = match remote {
                RemoteCleanup::Close { generation, .. } | RemoteCleanup::Forget { generation, .. } => generation,
            };
            if generation != state.generation {
                state.remote_cleanup.pop_front();
            } else if state.closed || state.failed {
                state.end_cleanup_session(&queue);
                return;
            } else if matches!(remote, RemoteCleanup::Forget { node, .. } if state.by_guest.contains_key(&node)) {
                state.remote_cleanup.pop_front();
            } else {
                let meta = state.client.deadlines.meta;
                let budget = match remote {
                    RemoteCleanup::Close { .. } => state.client.deadlines.io.max(state.client.deadlines.mutate),
                    RemoteCleanup::Forget { .. } => meta,
                };
                state.client.deadlines.meta = budget.min(operation);
                state.op_deadline = None;
                state.client.op_deadline = None;
                let result = match remote {
                    RemoteCleanup::Close { handle, .. } => state.client.close_handle(handle),
                    RemoteCleanup::Forget { node, .. } => state.client.forget(node),
                };
                state.client.deadlines.meta = meta;
                match result {
                    Ok(()) => { state.remote_cleanup.pop_front(); }
                    Err(CallError::Errno(_) | CallError::OutOfTime) if matches!(remote, RemoteCleanup::Forget { .. }) => {
                        state.remote_cleanup.pop_front();
                        let old = retry_delay.filter(|(r, _)| same_remote(*r, remote)).map(|(_, delay)| delay)
                            .unwrap_or(Duration::from_millis(50));
                        let delay = (old * 2).min(Duration::from_secs(30));
                        state.retry_forgets.push_back((remote, Instant::now() + delay, delay));
                    }
                    Err(e) => {
                        warn!("remote cleanup was not confirmed: {e:?}");
                        state.end_cleanup_session(&queue);
                        return;
                    }
                }
            }
            state.close_turn = !state.close_turn;
        }
        let active = !state.remote_cleanup.is_empty() || queue.local_pending();
        let more = active || !state.retry_forgets.is_empty();
        queue.cleanup_turn.store(false, Ordering::SeqCst);
        drop(state);
        if more {
            queue.kick();
            std::thread::sleep(if active { Duration::from_millis(1) } else { Duration::from_millis(50) });
        } else if stopped {
            return;
        }
    }
}

fn same_remote(a: RemoteCleanup, b: RemoteCleanup) -> bool {
    match (a, b) {
        (RemoteCleanup::Close { generation: a, handle: x }, RemoteCleanup::Close { generation: b, handle: y }) => a == b && x == y,
        (RemoteCleanup::Forget { generation: a, node: x }, RemoteCleanup::Forget { generation: b, node: y }) => a == b && x == y,
        _ => false,
    }
}

pub struct FsvmFs {
    cleanup: Arc<CleanupQueue>,
    state: Arc<Mutex<State>>,
    closing: Arc<AtomicBool>,
    /// The switch after the check runs (a remount in the VM, an unmount after a repair): a stop waits for it.
    switching: Arc<AtomicBool>,
    read_only: Arc<AtomicBool>,
    /// The request budget, read before waiting for the state lock.
    operation: Duration,
    /// The owner every node shows (vold's --owner-uid: MediaProvider, which sets times on files apps wrote through
    /// /storage, as stock's FAT and exFAT drivers let group media_rw do with allow_utime). 0 for OBB images.
    uid: u32,
    gid: u32,
    dir_mode: u32,
    file_mode: u32,
}

impl FsvmFs {
    /// `asked_read_only`: vold asked for read-only. `vm_read_only`: the VM serves it read-only (a write-protected card,
    /// a check pending). `obb`: an app's OBB image, read-only for its owner's group (vold mounted these with fmask and
    /// dmask 0227).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Client<StreamTransport<UnixStream>>,
        root_guest: u64,
        asked_read_only: bool,
        vm_read_only: bool,
        gid: u32,
        obb: bool,
        check_pending: bool,
        session: Box<dyn Session>,
    ) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, Node { guest: Some(root_guest), parent: ROOT, name: Vec::new(), kind: Kind::Dir, lookups: 1, replaced: false });
        let mut by_guest = HashMap::new();
        by_guest.insert(root_guest, ROOT);
        let asked_read_only = asked_read_only || obb;
        if asked_read_only && check_pending {
            warn!("a check pending on a volume asked read-only: it stays read-only, unchecked");
        }
        let check_pending = check_pending && !asked_read_only;
        let read_only = Arc::new(AtomicBool::new(asked_read_only || vm_read_only || check_pending));
        let operation = client.deadlines.operation;
        let cleanup = Arc::new(CleanupQueue::default());
        let state = Arc::new(Mutex::new(State {
            client,
            root_guest,
            session,
            restarts: Vec::new(),
            read_only: read_only.clone(),
            asked_read_only,
            nodes,
            by_guest,
            by_name: HashMap::new(),
            next_ino: ROOT + 1,
            listings: HashMap::new(),
            card_listings: Arc::new(Listings::default()),
            files: HashMap::new(),
            next_handle: 1,
            remote_cleanup: VecDeque::new(),
            retry_forgets: VecDeque::new(),
            close_turn: true,
            cleanup: cleanup.clone(),
            generation: 0,
            changed: false,
            lost_changes: false,
            op_deadline: None,
            recovered: false,
            kernel: None,
            closed: false,
            failed: false,
            check_pending,
            wake: Arc::new(Condvar::new()),
        }));
        let weak = Arc::downgrade(&state);
        let work = cleanup.clone();
        std::thread::spawn(move || cleanup_worker(weak, work, operation));
        FsvmFs {
            state,
            cleanup,
            closing: Arc::new(AtomicBool::new(false)),
            switching: Arc::new(AtomicBool::new(false)),
            read_only,
            operation,
            uid: 0,
            gid,
            dir_mode: if obb { 0o550 } else { 0o770 },
            file_mode: if obb { 0o440 } else { 0o660 },
        }
    }

    /// Every node shows `uid` as its owner (a card's: MediaProvider's uid).
    pub fn with_owner(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// The card's listing memory, shared with the other partitions of its drive.
    pub fn with_listings(self, listings: Arc<Listings>) -> Self {
        self.state.lock().unwrap().card_listings = listings;
        self
    }

    /// The state for one FUSE request: its calls to the VM end within Deadlines::operation from now (State::begin).
    fn op(&self) -> io::Result<Op<'_>> {
        let deadline = Instant::now() + self.operation;
        self.cleanup.foreground.fetch_add(1, Ordering::SeqCst);
        let _waiter = ForegroundWaiter(&self.cleanup);
        loop {
            if self.cleanup.aborted.load(Ordering::SeqCst) { return Err(err(libc::EIO)); }
            if Instant::now() >= deadline {
                return Err(err(libc::EIO));
            }
            match self.state.try_lock() {
                Ok(mut s) => {
                    if self.cleanup.cleanup_turn.load(Ordering::SeqCst) && s.cleanup_pending() {
                        drop(s);
                        self.cleanup.kick();
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    s.drain_cleanup(&self.cleanup);
                    if self.cleanup.aborted.load(Ordering::SeqCst) || Instant::now() >= deadline {
                        return Err(err(libc::EIO));
                    }
                    s.begin(deadline);
                    self.cleanup.cleanup_turn.store(true, Ordering::SeqCst);
                    return Ok(Op(s));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(err(libc::EIO)),
            }
        }
    }

    fn defer_cleanup(&self, job: CleanupJob) {
        self.cleanup.push(job);
    }

    /// A handle that outlives the FUSE loop, for the orderly stop (Closer::close).
    pub fn closer(&self) -> Closer {
        Closer { state: self.state.clone(), closing: self.closing.clone(), switching: self.switching.clone() }
    }

    /// Runs the VM's check after the mount for a volume served read-only until it passes, outside vold's lock and
    /// without a time limit, then the switch to writable. Tells vold (`done`): b'W' once writable, b'F' when it stays
    /// read-only (vold reports it so and SystemUI says why), b'c' when a new VM after a broken session checks it
    /// again (read-only meanwhile), b'E' when the errors it found need a repair longer than apps may wait (vold then
    /// takes the volume from apps for it). The thread sleeps while no check is pending. Ends with the volume.
    pub fn spawn_checker(&self, done: Box<dyn Fn(u8) + Send>) {
        let checker = Checker {
            state: self.state.clone(),
            read_only: self.read_only.clone(),
            switching: self.switching.clone(),
            closing: self.closing.clone(),
            done,
        };
        std::thread::spawn(move || checker.run());
    }

    #[allow(clippy::useless_conversion)]
    fn stat(&self, ino: u64, a: &Attr) -> libc::stat64 {
        // SAFETY: every field of stat64 is valid as zero.
        let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };
        st.st_ino = ino;
        st.st_uid = self.uid;
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

impl Drop for FsvmFs {
    fn drop(&mut self) { self.cleanup.stop(); }
}

/// What vold is told once a volume is served (main.rs start_serving): `R` served writable, `r` served read-only for
/// good (read-only as asked, a write-protected card, an error the VM's driver found), `c` read-only while the VM
/// checks it, with W or F to follow. A volume asked read-only is never checked.
pub fn ready_letter(asked_read_only: bool, hello: &Hello) -> u8 {
    if asked_read_only || (hello.read_only && !hello.check_pending) {
        b'r'
    } else if hello.check_pending {
        b'c'
    } else {
        b'R'
    }
}

/// One FUSE request's hold on the state. When it ends, the next user (the checker, the orderly stop, the next
/// request) starts without the request's deadline.
struct Op<'a>(MutexGuard<'a, State>);

impl Deref for Op<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.0
    }
}

impl DerefMut for Op<'_> {
    fn deref_mut(&mut self) -> &mut State {
        &mut self.0
    }
}

impl Drop for Op<'_> {
    fn drop(&mut self) {
        self.0.op_deadline = None;
        self.0.client.op_deadline = None;
    }
}

/// What the kernel is told to forget of a replaced VM's nodes (FUSE_NOTIFY_INVAL_ENTRY, FUSE_NOTIFY_INVAL_INODE).
pub enum Notice {
    /// A name in a directory: the kernel looks it up again.
    Entry(u64, Vec<u8>),
    /// A node's attributes and cached data: the kernel asks for them again.
    Inode(u64),
}

const FUSE_NOTIFY_INVAL_INODE: i32 = 2;
const FUSE_NOTIFY_INVAL_ENTRY: i32 = 3;

/// One notice as the kernel reads it from /dev/fuse: struct fuse_out_header (unique 0, the notice's code in `error`)
/// and struct fuse_notify_inval_inode_out, or struct fuse_notify_inval_entry_out with the name and its NUL.
fn notice_bytes(n: &Notice) -> Vec<u8> {
    let (code, body) = match n {
        Notice::Inode(ino) => {
            let mut b = ino.to_le_bytes().to_vec();
            // Offset 0 and length 0: every cached page, and the attributes.
            b.extend_from_slice(&0i64.to_le_bytes());
            b.extend_from_slice(&0i64.to_le_bytes());
            (FUSE_NOTIFY_INVAL_INODE, b)
        }
        Notice::Entry(parent, name) => {
            let mut b = parent.to_le_bytes().to_vec();
            b.extend_from_slice(&(name.len() as u32).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(name);
            b.push(0);
            (FUSE_NOTIFY_INVAL_ENTRY, b)
        }
    };
    let mut m = Vec::with_capacity(16 + body.len());
    m.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    m.extend_from_slice(&code.to_le_bytes());
    m.extend_from_slice(&0u64.to_le_bytes());
    m.extend_from_slice(&body);
    m
}

/// Writes the notices to the kernel, from a thread of its own: the kernel may wait in such a write for a request the
/// FUSE thread has to answer first (a page it reads, a directory it changes). Ends when the volume goes.
fn notifier(mut dev: std::fs::File, notices: mpsc::Receiver<Vec<Notice>>) {
    for batch in notices {
        for n in &batch {
            // ENOENT: the kernel holds nothing of that node any more.
            let _ = dev.write(&notice_bytes(n));
        }
    }
}

impl State {
    fn cleanup_pending(&self) -> bool {
        !self.remote_cleanup.is_empty() || self.cleanup.local_pending()
    }

    fn node_capacity(&self) -> io::Result<()> {
        let pending = self.remote_cleanup.iter().filter(|r| matches!(r, RemoteCleanup::Forget { .. })).count()
            + self.retry_forgets.len();
        if self.nodes.len() + pending >= MAX_CACHED_NODES { Err(err(libc::EAGAIN)) } else { Ok(()) }
    }

    fn file_capacity(&self) -> io::Result<()> {
        let pending = self.remote_cleanup.iter().filter(|r| matches!(r, RemoteCleanup::Close { .. })).count();
        if self.files.len() + pending >= MAX_OPEN_FILES { Err(err(libc::EMFILE)) } else { Ok(()) }
    }

    /// Local retirement is bounded and never performs protocol I/O.
    fn drain_cleanup(&mut self, queue: &CleanupQueue) {
        let jobs = {
            let mut inbox = queue.inbox.lock().unwrap_or_else(|p| p.into_inner());
            let mut jobs = Vec::new();
            for _ in 0..CLEANUP_BATCH {
                if let Some(h) = inbox.releases.iter().next().copied() {
                    inbox.releases.remove(&h);
                    jobs.push(CleanupJob::Release(h));
                }
                if let Some(h) = inbox.releasedirs.iter().next().copied() {
                    inbox.releasedirs.remove(&h);
                    jobs.push(CleanupJob::ReleaseDir(h));
                }
                if let Some((&ino, &count)) = inbox.forgets.iter().next() {
                    inbox.forgets.remove(&ino);
                    jobs.push(CleanupJob::Forget(ino, count));
                }
                if jobs.len() >= CLEANUP_BATCH { break; }
            }
            jobs
        };
        for job in jobs {
            match job {
                CleanupJob::ReleaseDir(handle) => { self.listings.remove(&handle); }
                CleanupJob::Release(handle) => {
                    if let Some(file) = self.files.remove(&handle) {
                        if file.generation == self.generation {
                            self.remote_cleanup.push_back(RemoteCleanup::Close { generation: file.generation, handle: file.guest });
                        }
                    }
                }
                CleanupJob::Forget(ino, count) => {
                    if let Some(remote) = self.forget(ino, count) { self.remote_cleanup.push_back(remote); }
                }
            }
        }
    }

    fn end_cleanup_session(&mut self, queue: &CleanupQueue) {
        queue.aborted.store(true, Ordering::SeqCst);
        self.read_only.store(true, Ordering::SeqCst);
        self.lost_changes |= self.changed;
        // EOF makes the guest retire its handle table, but local shutdown does not acknowledge that work.
        // Keep every unconfirmed identity until this failed session's State is torn down.
        let _ = self.client.transport_mut().0.shutdown(std::net::Shutdown::Both);
        if !self.closed && !self.failed { self.give_up(); }
        self.failed = true;
        self.wake.notify_all();
    }

    /// A FUSE request starts: its calls to the VM end within Deadlines::operation, and it may bring up one new VM.
    fn begin(&mut self, end: Instant) {
        self.op_deadline = Some(end);
        self.client.op_deadline = Some(end);
        self.recovered = false;
    }

    fn node(&self, ino: u64) -> io::Result<&Node> {
        self.nodes.get(&ino).ok_or_else(|| err(libc::ENOENT))
    }

    fn is_dir(&self, ino: u64) -> io::Result<()> {
        match self.node(ino)?.kind {
            Kind::Dir => Ok(()),
            Kind::File => Err(err(libc::ENOTDIR)),
        }
    }

    /// The VM's attributes of a node it named before must keep its kind: a node that turns from a file into a
    /// directory (or the root into a file) is the VM contradicting itself.
    fn same_kind(&self, ino: u64, a: &Attr) -> io::Result<()> {
        match self.nodes.get(&ino) {
            Some(n) if n.kind != a.kind => {
                warn!("filesystem VM changed the kind of a node");
                Err(err(libc::EIO))
            }
            _ => Ok(()),
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
        if n.replaced {
            return Err(CallError::Errno(libc::ESTALE));
        }
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
        if self.failed {
            return;
        }
        if self.restarts.len() >= MAX_RESTARTS {
            error!("filesystem VM session broken ({why}), {MAX_RESTARTS} new VMs within {RESTART_WINDOW:?}, giving up");
            self.give_up();
            return;
        }
        self.restarts.push(now);
        self.recovered = true;
        warn!("filesystem VM session broken ({why}), starting a new VM");
        // Whatever the old VM acknowledged since it served may not be on the card: the stop says so (lost_changes).
        if self.changed {
            warn!("the replaced VM may have changed the volume: its eject will say not all changes reached the card");
            self.lost_changes = true;
        }
        self.changed = false;
        let deadline = self.op_deadline.unwrap_or(now + self.client.deadlines.operation);
        match self.session.restart(deadline) {
            Ok((mut client, hello)) => {
                let root = hello.root;
                self.generation += 1;
                client.op_deadline = self.op_deadline;
                self.client = client;
                self.root_guest = root;
                // What the new VM says, unless the volume is read-only as asked: a new VM that mounted the volume clean
                // and writable (the old one had marked it clean in the switch) makes it writable again.
                self.read_only.store(self.asked_read_only || hello.read_only, Ordering::SeqCst);
                // The new VM found the volume marked dirty (the old one ended with it mounted writable): read-only
                // again until its own check passes. A volume asked read-only is never checked.
                self.check_pending = hello.check_pending && !self.asked_read_only;
                self.wake.notify_all();
                self.by_guest.clear();
                for (&ino, n) in self.nodes.iter_mut() {
                    n.guest = if ino == ROOT { Some(root) } else { None };
                    // Directories are found by their path again, files get new inodes (Node::replaced).
                    n.replaced |= n.kind == Kind::File;
                }
                let nodes = &self.nodes;
                self.by_name.retain(|_, ino| nodes.get(ino).is_some_and(|n| !n.replaced));
                self.by_guest.insert(root, ROOT);
                self.tell_kernel();
            }
            Err(e) => {
                error!("no new filesystem VM: {e:?}");
                self.give_up();
            }
        }
    }

    /// The kernel forgets what it cached of the replaced VM's nodes: the names of its files (they get new inodes,
    /// Node::replaced) and every node's attributes and data. A file the old VM served may differ in the new one (writes
    /// it acknowledged may be lost, a name may hold another file), and the kernel would otherwise show the old for up
    /// to TIMEOUT, cached pages until the next open. Directories keep their names and inodes, so a process working in
    /// one keeps it.
    fn tell_kernel(&self) {
        let Some(kernel) = &self.kernel else { return };
        let mut batch: Vec<Notice> =
            self.nodes.values().filter(|n| n.replaced).map(|n| Notice::Entry(n.parent, n.name.clone())).collect();
        batch.extend(self.nodes.keys().map(|&ino| Notice::Inode(ino)));
        let _ = kernel.send(batch);
    }

    /// A request found the session broken: a new VM, unless one came up during this request already (then the next
    /// request brings one up). A request waits for at most one VM's start.
    fn broken(&mut self, why: &str) {
        if !self.recovered {
            self.recover(why);
        }
    }

    fn give_up(&mut self) {
        self.failed = true;
        self.read_only.store(true, Ordering::SeqCst);
        self.wake.notify_all();
        self.session.give_up();
    }

    /// Runs one call on a node: resolves the VM's id, and on a stale id or a broken session tries once more, within
    /// the request's time.
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
        if self.closed || self.failed {
            return Err(err(libc::EIO));
        }
        if self.nodes.get(&ino).is_some_and(|n| n.replaced) {
            return Err(err(libc::ESTALE));
        }
        let generation = self.generation;
        for attempt in 0..3 {
            if self.failed || (generation != self.generation && self.nodes.get(&ino).is_some_and(|n| n.kind == Kind::File)) {
                return Err(err(libc::EIO));
            }
            let last = attempt == 2;
            let r = match self.resolve(ino, 0) {
                Ok(g) => f(&mut self.client, g),
                Err(e) => Err(e),
            };
            match r {
                Ok(v) => return Ok(v),
                Err(CallError::Errno(libc::ESTALE)) if !last => self.invalidate(ino),
                Err(CallError::Broken(why)) => {
                    // The call goes again only when it is safe to repeat, once a new VM serves (within the request's
                    // deadline, which the new VM's calls keep).
                    let again = replay && !last && !self.recovered;
                    self.broken(&why);
                    if !again {
                        return Err(err(libc::EIO));
                    }
                }
                Err(e) => return Err(call_err(e)),
            }
        }
        Err(err(libc::EIO))
    }

    /// Opens `ino` in the VM and keeps it as an open file. Its handle is fsvmd's own number. EMFILE when the VM has
    /// no handle left: a file is served through its handle only.
    fn open_file(&mut self, ino: u64, write: bool) -> io::Result<u64> {
        self.file_capacity()?;
        let kind = self.node(ino)?.kind;
        let guest = self.call(ino, |c, g| c.open_handle(g, write))?;
        let h = self.next_handle;
        self.next_handle += 1;
        self.files.insert(h, OpenFile { generation: self.generation, guest, kind });
        self.cleanup.inbox.lock().unwrap_or_else(|p| p.into_inner()).files.insert(h);
        Ok(h)
    }

    /// The VM's handle of an open file and the kind it was opened as, when it was opened in the VM that serves now.
    fn open_handle(&self, h: u64) -> Option<(u64, Kind)> {
        self.files.get(&h).filter(|f| f.generation == self.generation).map(|f| (f.guest, f.kind))
    }

    /// The VM's handle for an open file's I/O. A file opened in a VM that has been replaced since has none: its name
    /// may hold another file now, so its I/O fails (EIO) and the app opens it again.
    fn io_handle(&self, h: u64) -> io::Result<u64> {
        match self.files.get(&h) {
            Some(f) if f.generation == self.generation => Ok(f.guest),
            Some(_) => Err(err(libc::EIO)),
            None => Err(err(libc::EBADF)),
        }
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
        if self.closed || self.failed {
            return Err(err(libc::EIO));
        }
        match f(&mut self.client, handle) {
            Ok(v) => Ok(v),
            Err(CallError::Broken(why)) => {
                self.broken(&why);
                Err(err(libc::EIO))
            }
            Err(e) => Err(call_err(e)),
        }
    }

    /// A rename resolves both directories on every attempt, so neither id is stale after a new VM took over. Not
    /// repeated after a broken session (call_once).
    fn rename_call(&mut self, olddir: u64, from: &[u8], newdir: u64, to: &[u8]) -> io::Result<()> {
        if self.closed || self.failed {
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
                    self.broken(&why);
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
            if n.replaced || n.parent != parent || n.name != name || n.kind != a.kind {
                warn!("filesystem VM returned one node for two names");
                return Err(err(libc::EIO));
            }
            n.lookups = n.lookups.saturating_add(1);
            // The name is this node's again (a node of another kind may have held it since): an unlink or a rename of
            // the name must reach this node, the one the kernel now holds for it.
            self.by_name.insert((parent, name.to_vec()), ino);
            return Ok(ino);
        }
        let key = (parent, name.to_vec());
        if let Some(&ino) = self.by_name.get(&key) {
            let n = self.nodes.get_mut(&ino).ok_or_else(|| err(libc::EIO))?;
            if !n.replaced && n.kind == a.kind {
                // The same name after the VM changed or took its id back.
                if let Some(old) = n.guest.replace(a.node) {
                    self.by_guest.remove(&old);
                }
                n.lookups = n.lookups.saturating_add(1);
                self.by_guest.insert(a.node, ino);
                return Ok(ino);
            }
            // A different kind needs a new inode. Replace the name only once it can be mapped.
        }
        self.node_capacity()?;
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(ino, Node { guest: Some(a.node), parent, name: name.to_vec(), kind: a.kind, lookups: 1, replaced: false });
        self.by_guest.insert(a.node, ino);
        self.by_name.insert(key, ino);
        self.cleanup.inbox.lock().unwrap_or_else(|p| p.into_inner()).nodes.insert(ino);
        Ok(ino)
    }

    /// The kernel forgets `count` lookups of a node. The last one removes it.
    fn forget(&mut self, ino: u64, count: u64) -> Option<RemoteCleanup> {
        if ino == ROOT {
            return None;
        }
        let gone = match self.nodes.get_mut(&ino) {
            Some(n) => {
                n.lookups = n.lookups.saturating_sub(count);
                n.lookups == 0
            }
            None => false,
        };
        if gone {
            if let Some(n) = self.nodes.remove(&ino) {
                let mut inbox = self.cleanup.inbox.lock().unwrap_or_else(|p| p.into_inner());
                inbox.nodes.remove(&ino);
                inbox.forgets.remove(&ino);
                drop(inbox);
                if self.by_name.get(&(n.parent, n.name.clone())) == Some(&ino) {
                    self.by_name.remove(&(n.parent, n.name));
                }
                if let Some(g) = n.guest {
                    self.by_guest.remove(&g);
                    return Some(RemoteCleanup::Forget { generation: self.generation, node: g });
                }
            }
        }
        None
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
#[derive(Clone)]
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
        let mut deadline = start + max;
        // The switch after the check holds the lock while the VM repairs. Stopping the VM in the middle could leave a
        // repair half done, so it gets up to SWITCH_MAX (within `max`). It is read on every round: the Checker may
        // have started it just before `closing` was set (it starts none after).
        let switch_until = start + max.min(SWITCH_MAX);
        let mut waited_for_switch = false;
        let mut guard = loop {
            match self.state.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let switching = self.switching.load(Ordering::SeqCst);
                    waited_for_switch |= switching;
                    if Instant::now() < if switching { switch_until } else { start + lock_wait } {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    error!("a call to the filesystem VM is still running, stopping without writing back");
                    return Closed::NotWrittenBack;
                }
            }
        };
        // After a switch the volume was read-only until a moment ago, so there is next to nothing to write back, but
        // the unmount still gets its minimum.
        if waited_for_switch {
            deadline = deadline.max(Instant::now() + UNMOUNT_MIN.min(max));
        }
        guard.wake.notify_all();
        if guard.closed {
            return Closed::Clean;
        }
        guard.closed = true;
        let result = if guard.failed {
            error!("no session serves the volume any more, stopping without writing back");
            Closed::NotWrittenBack
        } else if guard.client.is_broken() {
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
                Ok(()) if guard.lost_changes => {
                    warn!("written back and unmounted in the VM, but an earlier VM's changes may be lost");
                    Closed::NotWrittenBack
                }
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
        guard.kernel = None;
        // The VM ends before fsvmd does, so nothing holds its disk any more when vold takes it back. A drive's VM serves
        // its other partitions on: the session ends, and the VM's server of this disk with it.
        guard.session.stop_vm(VM_END);
        let _ = guard.client.transport_mut().0.shutdown(std::net::Shutdown::Both);
        result
    }
}

/// The read-only check runs as long as it takes. Errors it found are repaired only when it took at most this long,
/// so the repair (as long as the check, plus writes) stays short: apps wait for it and an eject waits for it.
const REPAIR_AFTER_CHECK_MAX: Duration = Duration::from_secs(10);
/// What the repair may take in the VM, and the whole switch. A check that passed is a remount in the VM (no unmount,
/// files stay open, well under a second). After a repair the volume is unmounted, repaired, checked once more without
/// writes (up to 5 s more) and mounted again, with its free space counted. An eject during a switch waits for it
/// (Closer::close): SWITCH_MAX plus UNMOUNT_MIN and the VM's end stays below vold's 26 s for the orderly stop, and the
/// volume was read-only until then, so nothing is left to write back.
const REPAIR_MAX: Duration = Duration::from_secs(8);
pub const SWITCH_MAX: Duration = Duration::from_secs(16);
const CHECK_POLL: Duration = Duration::from_secs(1);

struct Checker {
    state: Arc<Mutex<State>>,
    read_only: Arc<AtomicBool>,
    switching: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
    done: Box<dyn Fn(u8) + Send>,
}

impl Checker {
    fn run(self) {
        let Ok(mut s) = self.state.lock() else { return };
        // vold was told c (read-only while the VM checks it) when the check is pending from the start.
        let mut owed = s.check_pending;
        loop {
            // A volume asked read-only is never checked, so never switched to writable (FsvmFs::new, State::recover).
            if s.closed || s.failed || s.asked_read_only || self.closing.load(Ordering::SeqCst) {
                return;
            }
            if !s.check_pending {
                // A new VM after a broken session mounted the volume clean and writable (the old one marked it clean in
                // the switch and its answer was lost): vold still waits for the check's end.
                if owed && !self.read_only.load(Ordering::SeqCst) {
                    info!("a new VM serves the volume writable, the check is over");
                    owed = false;
                    (self.done)(b'W');
                }
                // Nothing to do until a new VM checks again or the volume goes (State::recover, Closer::close).
                s = match s.wake.clone().wait(s) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                continue;
            }
            if !owed {
                warn!("a new VM checks the volume again, read-only meanwhile");
                owed = true;
                (self.done)(b'c');
            }
            // The check runs in the VM. One poll a second, the lock free in between.
            drop(s);
            std::thread::sleep(CHECK_POLL);
            s = match self.state.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            if s.closed || self.closing.load(Ordering::SeqCst) || !s.check_pending {
                continue;
            }
            match s.client.check_poll() {
                Ok((CheckState::Running, _)) => {}
                Ok((state @ (CheckState::Passed | CheckState::Errors), ran)) => {
                    if state == CheckState::Errors && (ran > REPAIR_AFTER_CHECK_MAX ||
                        s.client.deferred_fat_mount_elapsed.saturating_add(ran) >= SWITCH_MAX) {
                        // Too long to repair while apps wait: vold takes the volume from apps and has it repaired
                        // with no time limit (fsvmd --repair), as stock's check before the mount.
                        warn!("check errors after {ran:?}, FAT mount {:?}: vold repairs without apps", s.client.deferred_fat_mount_elapsed);
                        s.check_pending = false;
                        owed = false;
                        (self.done)(b'E');
                        continue;
                    }
                    // The closer sets closing first and then reads switching: either it sees this switch and waits
                    // for it, or the switch does not start.
                    self.switching.store(true, Ordering::SeqCst);
                    if self.closing.load(Ordering::SeqCst) {
                        self.switching.store(false, Ordering::SeqCst);
                        return;
                    }
                    info!("the check {} after {ran:?}, switching to writable", if state == CheckState::Errors { "found errors to repair" } else { "passed" });
                    s.changed = true;
                    let r = s.client.check_switch(REPAIR_MAX, SWITCH_MAX);
                    self.switching.store(false, Ordering::SeqCst);
                    match r {
                        Ok(()) => {
                            info!("checked, the volume is writable now");
                            s.check_pending = false;
                            owed = false;
                            // A check is pending only for a volume asked writable (FsvmFs::new, State::recover).
                            self.read_only.store(s.asked_read_only, Ordering::SeqCst);
                            (self.done)(b'W');
                        }
                        Err(CallError::Broken(why)) => s.recover(&why),
                        Err(e) => {
                            warn!("the switch after the check failed ({}): the volume stays read-only", e.errno());
                            s.check_pending = false;
                            owed = false;
                            (self.done)(b'F');
                        }
                    }
                }
                Ok((CheckState::Failed | CheckState::None, _)) | Err(CallError::Errno(_) | CallError::OutOfTime) => {
                    warn!("the check did not run or did not finish: the volume stays read-only");
                    s.check_pending = false;
                    owed = false;
                    (self.done)(b'F');
                }
                Err(CallError::Broken(why)) => s.recover(&why),
            }
        }
    }
}

/// Serves FUSE on vold's /dev/fuse until the mount goes. The loop's read buffer, the max_write the kernel learns in
/// INIT (FileSystem::max_buffer_size) and vold's `max_read=131072` mount option (fs/Fsvm.cpp) are all MAX_IO, the
/// most one protocol READ or WRITE carries. The buffer is taken from the filesystem itself, so the two cannot differ.
/// A second descriptor of the same /dev/fuse carries the notices of a replaced VM (State::tell_kernel).
pub fn serve_fuse(dev_fuse: std::fs::File, fs: FsvmFs) -> fuse::Result<()> {
    let io = fs.max_buffer_size();
    assert_eq!(io, MAX_IO, "the FUSE buffer must hold one protocol READ or WRITE");
    let state = fs.state.clone();
    match dev_fuse.try_clone() {
        Ok(dev) => {
            let (tx, rx) = mpsc::channel();
            state.lock().unwrap_or_else(|p| p.into_inner()).kernel = Some(tx);
            std::thread::spawn(move || notifier(dev, rx));
        }
        Err(e) => warn!("no notices to the kernel after a new VM: {e}"),
    }
    let mut config = fuse::FuseConfig::new();
    config.dev_fuse(dev_fuse).max_read(io).max_write(io).num_threads(1);
    let r = config.enter_message_loop(fs);
    // The notifier ends, and its descriptor with it.
    state.lock().unwrap_or_else(|p| p.into_inner()).kernel = None;
    r
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
        let mut s = self.op()?;
        s.is_dir(parent)?;
        // map validates and reuses an existing inode before it checks capacity for a new one.
        let a = s.call(parent, |c, g| c.lookup(g, name.to_bytes()))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        Ok(Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT })
    }

    fn forget(&self, _ctx: Context, ino: u64, count: u64) {
        self.defer_cleanup(CleanupJob::Forget(ino, count));
    }

    fn getattr(&self, _ctx: Context, ino: u64, h: Option<u64>) -> io::Result<(libc::stat64, Duration)> {
        let mut s = self.op()?;
        // fstat of a file opened in a replaced VM (also the kernel's size check before a read): its name may hold
        // another file now.
        if h.is_some_and(|h| s.stale(h)) {
            return Err(err(libc::EIO));
        }
        // An open file answers through its handle, also after its name went, and keeps the kind it was opened as.
        let a = match h.and_then(|h| s.open_handle(h)) {
            Some((guest, kind)) => {
                let a = s.handle_call(guest, |c, g| c.getattr_handle(g))?;
                if a.kind != kind {
                    warn!("filesystem VM changed the kind of an open file");
                    return Err(err(libc::EIO));
                }
                a
            }
            None => s.call(ino, |c, g| c.getattr(g))?,
        };
        s.same_kind(ino, &a)?;
        Ok((self.stat(ino, &a), TIMEOUT))
    }

    fn setattr(
        &self,
        _ctx: Context,
        ino: u64,
        attr: libc::stat64,
        h: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let mut s = self.op()?;
        let generation = s.generation;
        let modifying = valid.intersects(SetattrValid::SIZE | SetattrValid::MTIME | SetattrValid::MTIME_NOW);
        let guest = h.map(|h| s.io_handle(h)).transpose()?;
        let kind = h.and_then(|h| s.open_handle(h)).map(|(_, kind)| kind);
        let check_kind = |s: &State, a: &Attr| -> io::Result<()> {
            s.same_kind(ino, a)?;
            if kind.is_some_and(|kind| kind != a.kind) {
                warn!("filesystem VM changed the kind of an open file");
                return Err(err(libc::EIO));
            }
            Ok(())
        };
        let mut a = match guest {
            Some(g) => s.handle_call(g, |c, g| c.getattr_handle(g))?,
            None => s.call(ino, |c, g| c.getattr(g))?,
        };
        check_kind(&s, &a)?;
        if modifying {
            // A directory lookup can follow its path after recovery, a pending mutation cannot.
            if s.generation != generation {
                return Err(err(libc::EIO));
            }
            self.writable()?;
            s.changed = true;
        }
        if valid.contains(SetattrValid::SIZE) {
            let size = attr.st_size.max(0) as u64;
            a = match guest {
                Some(g) => s.handle_call(g, |c, g| c.truncate_handle(g, size))?,
                None => s.call_once(ino, |c, g| c.truncate(g, size))?,
            };
            check_kind(&s, &a)?;
        }
        let mtime = if valid.contains(SetattrValid::MTIME_NOW) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            Some((now.as_secs() as i64, now.subsec_nanos()))
        } else if valid.contains(SetattrValid::MTIME) {
            Some((attr.st_mtime, attr.st_mtime_nsec as u32))
        } else {
            None
        };
        if let Some((secs, nanos)) = mtime {
            a = match guest {
                Some(g) => s.handle_call(g, |c, g| c.set_mtime_handle(g, secs, nanos))?,
                None => s.call_once(ino, |c, g| c.set_mtime(g, secs, nanos))?,
            };
            check_kind(&s, &a)?;
        }
        // Owner, group and mode are vold's choice for the whole volume, as they were with the kernel mount.
        Ok((self.stat(ino, &a), TIMEOUT))
    }

    fn open(&self, _ctx: Context, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.op()?;
        s.node(ino)?;
        let acc = flags as i32 & libc::O_ACCMODE;
        if acc != libc::O_RDONLY {
            self.writable()?;
        }
        if flags as i32 & libc::O_TRUNC != 0 {
            self.writable()?;
            s.changed = true;
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
        self.defer_cleanup(CleanupJob::Release(h));
        Ok(())
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        _ino: u64,
        h: u64,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let mut s = self.op()?;
        let guest = s.io_handle(h)?;
        let data = s.handle_call(guest, |c, g| c.read_handle(g, offset, size.min(MAX_IO)))?;
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        _ino: u64,
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
        let mut s = self.op()?;
        let guest = s.io_handle(h)?;
        s.changed = true;
        let n = s.handle_call(guest, |c, g| c.write_handle(g, offset, &buf))?;
        Ok(n as usize)
    }

    /// close(): every write already reached the VM's filesystem (FUSE writes here are write-through), and the
    /// filesystem writes it back within about two seconds, as the kernel's FAT driver did with close. An app that
    /// needs the data on the card calls fsync, and an eject writes everything back first (Closer).
    fn flush(&self, _ctx: Context, _ino: u64, h: u64, _lock_owner: u64) -> io::Result<()> {
        let s = self.op()?;
        if s.stale(h) {
            // A new VM took over since this file was opened: writes the old one acknowledged may be lost.
            return Err(err(libc::EIO));
        }
        Ok(())
    }

    /// fsync and fdatasync: the file's data, and for fsync its directory entry and times, are on the card when this
    /// returns.
    fn fsync(&self, _ctx: Context, _ino: u64, datasync: bool, h: u64) -> io::Result<()> {
        let mut s = self.op()?;
        let guest = s.io_handle(h)?;
        s.handle_call(guest, |c, g| c.fsync_handle(g, datasync))
    }

    fn fsyncdir(&self, _ctx: Context, ino: u64, datasync: bool, _h: u64) -> io::Result<()> {
        let mut s = self.op()?;
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
        let mut s = self.op()?;
        s.is_dir(parent)?;
        s.node_capacity()?;
        s.file_capacity()?;
        s.changed = true;
        let a = s.call_once(parent, |c, g| c.create(g, name.to_bytes(), flags as i32 & libc::O_EXCL != 0))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        let entry = Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT };
        let h = match s.open_file(ino, true) {
            Ok(h) => h,
            Err(e) => {
                // The kernel gets no entry, so it never forgets the lookup map() counted: take it back here.
                self.defer_cleanup(CleanupJob::Forget(ino, 1));
                return Err(e);
            }
        };
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
        let mut s = self.op()?;
        s.is_dir(parent)?;
        s.node_capacity()?;
        s.changed = true;
        let a = s.call_once(parent, |c, g| c.mkdir(g, name.to_bytes()))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        Ok(Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT })
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.op()?;
        s.is_dir(parent)?;
        s.changed = true;
        s.call_once(parent, |c, g| c.unlink(g, name.to_bytes()))?;
        s.drop_child(parent, name.to_bytes());
        Ok(())
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.op()?;
        s.is_dir(parent)?;
        s.changed = true;
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
        let mut s = self.op()?;
        s.is_dir(olddir)?;
        s.is_dir(newdir)?;
        s.changed = true;
        s.rename_call(olddir, oldname.to_bytes(), newdir, newname.to_bytes())?;
        s.drop_child(newdir, newname.to_bytes());
        s.rename_node(olddir, oldname.to_bytes(), newdir, newname.to_bytes());
        Ok(())
    }

    fn opendir(&self, _ctx: Context, ino: u64, _flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.op()?;
        s.is_dir(ino)?;
        if s.listings.len() >= MAX_LISTINGS {
            return Err(err(libc::EMFILE));
        }
        // The most a listing may take is held while it is read, then what it took: the card's listings together,
        // the one being read included, never pass MAX_OPEN_LISTING_BYTES.
        let Some(mut charge) = s.card_listings.take(MAX_LISTING_BYTES) else {
            let used = s.card_listings.used();
            warn!("open directory listings of the card take {used} bytes of {MAX_OPEN_LISTING_BYTES}, refusing one more");
            return Err(err(libc::ENOMEM));
        };
        let listing = s.call(ino, |c, g| c.list(g))?;
        charge.keep(listing.bytes);
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
            // An inode Android knows only for this very name and kind in this directory: the VM's id of another
            // node must not lend this entry that node's inode number.
            let this = |i: &u64| s.nodes.get(i).is_some_and(|n| n.parent == ino && n.name == c.as_bytes() && n.kind == a.kind);
            let known = s
                .by_guest
                .get(&a.node)
                .copied()
                .filter(this)
                .or_else(|| s.by_name.get(&(ino, c.as_bytes().to_vec())).copied().filter(this))
                .unwrap_or(UNKNOWN_INO);
            entries.push((c, a.kind, known));
        }
        let h = s.next_handle;
        s.next_handle += 1;
        s.listings.insert(h, Listing { entries, _charge: charge });
        s.cleanup.inbox.lock().unwrap_or_else(|p| p.into_inner()).directories.insert(h);
        Ok((Some(h), OpenOptions::empty()))
    }

    fn readdir(&self, _ctx: Context, _ino: u64, h: u64, size: u32, offset: u64) -> io::Result<DirIter> {
        let s = self.op()?;
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
        self.defer_cleanup(CleanupJob::ReleaseDir(h));
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _ino: u64) -> io::Result<libc::statvfs64> {
        let mut s = self.op()?;
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

#[cfg(test)]
mod cleanup_tests;
