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
use fsvm_proto::{Attr, Client, Kind, StreamTransport, MAX_IO};
use fuse::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, FileSystem, FsOptions, OpenOptions, SetattrValid, ZeroCopyReader,
    ZeroCopyWriter,
};
use log::{error, warn};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

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
    guest: u64,
    parent: u64,
    name: Vec<u8>,
    kind: Kind,
    lookups: u64,
}

struct Listing {
    entries: Vec<(CString, Kind, u64)>,
}

struct State {
    client: Client<StreamTransport<UnixStream>>,
    nodes: HashMap<u64, Node>,
    by_guest: HashMap<u64, u64>,
    next_ino: u64,
    listings: HashMap<u64, Listing>,
    next_handle: u64,
}

pub struct FsvmFs {
    state: Mutex<State>,
    read_only: bool,
    gid: u32,
    dir_mode: u32,
    file_mode: u32,
}

impl FsvmFs {
    /// `obb`: an app's OBB image, read-only for its owner's group (vold mounted these with fmask and dmask 0227).
    pub fn new(client: Client<StreamTransport<UnixStream>>, root_guest: u64, read_only: bool, gid: u32, obb: bool) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, Node { guest: root_guest, parent: ROOT, name: Vec::new(), kind: Kind::Dir, lookups: 1 });
        let mut by_guest = HashMap::new();
        by_guest.insert(root_guest, ROOT);
        FsvmFs {
            state: Mutex::new(State { client, nodes, by_guest, next_ino: ROOT + 1, listings: HashMap::new(), next_handle: 1 }),
            read_only: read_only || obb,
            gid,
            dir_mode: if obb { 0o550 } else { 0o770 },
            file_mode: if obb { 0o440 } else { 0o660 },
        }
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
        if self.read_only {
            Err(err(libc::EROFS))
        } else {
            Ok(())
        }
    }
}

impl State {
    fn guest(&self, ino: u64) -> io::Result<u64> {
        self.nodes.get(&ino).map(|n| n.guest).ok_or_else(|| err(libc::ENOENT))
    }

    fn dir(&self, ino: u64) -> io::Result<u64> {
        match self.nodes.get(&ino) {
            Some(n) if n.kind == Kind::Dir => Ok(n.guest),
            Some(_) => Err(err(libc::ENOTDIR)),
            None => Err(err(libc::ENOENT)),
        }
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
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(ino, Node { guest: a.node, parent, name: name.to_vec(), kind: a.kind, lookups: 1 });
        self.by_guest.insert(a.node, ino);
        Ok(ino)
    }

    fn rename_node(&mut self, from_dir: u64, from: &[u8], to_dir: u64, to: &[u8]) {
        if let Some(n) = self.nodes.values_mut().find(|n| n.parent == from_dir && n.name == from) {
            n.parent = to_dir;
            n.name = to.to_vec();
        }
    }

    fn drop_child(&mut self, parent: u64, name: &[u8]) {
        let found = self.nodes.iter().find(|(_, n)| n.parent == parent && n.name == name).map(|(i, _)| *i);
        if let Some(ino) = found {
            if let Some(n) = self.nodes.remove(&ino) {
                self.by_guest.remove(&n.guest);
            }
        }
    }
}

fn check<T>(r: CallResult<T>) -> io::Result<T> {
    r.map_err(call_err)
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

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let mut s = self.state.lock().unwrap();
        let dir = s.dir(parent)?;
        let a = check(s.client.lookup(dir, name.to_bytes()))?;
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
                s.by_guest.remove(&n.guest);
                // Best effort: the VM may drop its handle. A failure here only keeps a handle alive in the VM.
                let _ = s.client.forget(n.guest);
            }
        }
    }

    fn getattr(&self, _ctx: Context, ino: u64, _h: Option<u64>) -> io::Result<(libc::stat64, Duration)> {
        let mut s = self.state.lock().unwrap();
        let g = s.guest(ino)?;
        let a = check(s.client.getattr(g))?;
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
        let g = s.guest(ino)?;
        let mut a = check(s.client.getattr(g))?;
        if valid.intersects(SetattrValid::SIZE | SetattrValid::MTIME | SetattrValid::MTIME_NOW) {
            self.writable()?;
        }
        if valid.contains(SetattrValid::SIZE) {
            a = check(s.client.truncate(g, attr.st_size.max(0) as u64))?;
        }
        if valid.contains(SetattrValid::MTIME_NOW) {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            a = check(s.client.set_mtime(g, now.as_secs() as i64, now.subsec_nanos()))?;
        } else if valid.contains(SetattrValid::MTIME) {
            a = check(s.client.set_mtime(g, attr.st_mtime, attr.st_mtime_nsec as u32))?;
        }
        // Owner, group and mode are vold's choice for the whole volume, as they were with the kernel mount.
        Ok((self.stat(ino, &a), TIMEOUT))
    }

    fn open(&self, _ctx: Context, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.state.lock().unwrap();
        let g = s.guest(ino)?;
        let acc = flags as i32 & libc::O_ACCMODE;
        if acc != libc::O_RDONLY {
            self.writable()?;
        }
        if flags as i32 & libc::O_TRUNC != 0 {
            self.writable()?;
            check(s.client.truncate(g, 0))?;
        }
        Ok((Some(ino), OpenOptions::empty()))
    }

    fn release(
        &self,
        _ctx: Context,
        _ino: u64,
        _flags: u32,
        _h: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        ino: u64,
        _h: u64,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let mut s = self.state.lock().unwrap();
        let g = s.guest(ino)?;
        let data = check(s.client.read(g, offset, size.min(MAX_IO)))?;
        w.write_all(&data)?;
        Ok(data.len())
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        ino: u64,
        _h: u64,
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
        let g = s.guest(ino)?;
        let n = check(s.client.write(g, offset, &buf))?;
        Ok(n as usize)
    }

    fn flush(&self, _ctx: Context, _ino: u64, _h: u64, _lock_owner: u64) -> io::Result<()> {
        Ok(())
    }

    fn fsync(&self, _ctx: Context, ino: u64, _datasync: bool, _h: u64) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        let g = s.guest(ino)?;
        check(s.client.fsync(g))
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
        let dir = s.dir(parent)?;
        let a = check(s.client.create(dir, name.to_bytes(), flags as i32 & libc::O_EXCL != 0))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        let entry = Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT };
        Ok((entry, Some(ino), OpenOptions::empty()))
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
        let dir = s.dir(parent)?;
        let a = check(s.client.mkdir(dir, name.to_bytes()))?;
        let ino = s.map(parent, name.to_bytes(), &a)?;
        Ok(Entry { inode: ino, generation: 0, attr: self.stat(ino, &a), attr_timeout: TIMEOUT, entry_timeout: TIMEOUT })
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        let dir = s.dir(parent)?;
        check(s.client.unlink(dir, name.to_bytes()))?;
        s.drop_child(parent, name.to_bytes());
        Ok(())
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.writable()?;
        let mut s = self.state.lock().unwrap();
        let dir = s.dir(parent)?;
        check(s.client.rmdir(dir, name.to_bytes()))?;
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
        let from = s.dir(olddir)?;
        let to = s.dir(newdir)?;
        check(s.client.rename(from, oldname.to_bytes(), to, newname.to_bytes()))?;
        s.drop_child(newdir, newname.to_bytes());
        s.rename_node(olddir, oldname.to_bytes(), newdir, newname.to_bytes());
        Ok(())
    }

    fn opendir(&self, _ctx: Context, ino: u64, _flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        let mut s = self.state.lock().unwrap();
        let dir = s.dir(ino)?;
        let listing = check(s.client.list(dir))?;
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
            let known = s.by_guest.get(&a.node).copied().unwrap_or(UNKNOWN_INO);
            entries.push((c, a.kind, known));
        }
        let h = s.next_handle;
        s.next_handle += 1;
        s.listings.insert(h, Listing { entries });
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
        self.state.lock().unwrap().listings.remove(&h);
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _ino: u64) -> io::Result<libc::statvfs64> {
        let mut s = self.state.lock().unwrap();
        let t = check(s.client.statfs())?;
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
