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

//! The checking client. One call is one request and one reply, finished within a total deadline. A VM that sends
//! a byte at a time cannot stretch a call: the deadline counts from the start of the call, not per read.

use crate::*;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// A byte stream with a total deadline per call.
pub trait Transport {
    fn send_by(&mut self, buf: &[u8], deadline: Instant) -> io::Result<()>;
    fn recv_by(&mut self, buf: &mut [u8], deadline: Instant) -> io::Result<()>;
}

/// A stream socket with read and write timeouts, such as a vsock or Unix socket.
pub trait TimedStream: Read + Write {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()>;
}

impl TimedStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, d)
    }
}

/// Wraps a stream so that every call has a total deadline. Each read or write waits at most for the time left.
pub struct StreamTransport<S: TimedStream>(pub S);

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
    }
    // A zero timeout means "no timeout" for SO_RCVTIMEO, so never pass less than a millisecond.
    Ok((deadline - now).max(Duration::from_millis(1)))
}

fn retryable(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

impl<S: TimedStream> Transport for StreamTransport<S> {
    fn send_by(&mut self, mut buf: &[u8], deadline: Instant) -> io::Result<()> {
        while !buf.is_empty() {
            self.0.set_write_timeout(Some(remaining(deadline)?))?;
            match self.0.write(buf) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => buf = &buf[n..],
                Err(e) if retryable(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn recv_by(&mut self, mut buf: &mut [u8], deadline: Instant) -> io::Result<()> {
        while !buf.is_empty() {
            self.0.set_read_timeout(Some(remaining(deadline)?))?;
            match self.0.read(buf) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => buf = &mut buf[n..],
                Err(e) if retryable(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Total time allowed per call.
#[derive(Debug, Clone, Copy)]
pub struct Deadlines {
    pub hello: Duration,
    /// Lookups, attributes, listings and statfs.
    pub meta: Duration,
    /// Calls that change the volume (create, mkdir, unlink, rmdir, rename, truncate, set time): a cheap card in the
    /// middle of its garbage collection can take seconds for one.
    pub mutate: Duration,
    pub io: Duration,
    /// MOUNT: the VM's kernel mounts the filesystem and counts its free space once, which reads a whole FAT. A
    /// 2 TB FAT32 card with 32 KiB clusters has 256 MiB per FAT, about 13 s from a slow card. Later STATFS calls
    /// answer from the kernel's count and keep the short `meta` deadline. vold waits for all of a mount while it holds
    /// its lock (system/vold fs/Fsvm.cpp), so this stays well under a minute.
    pub mount: Duration,
    /// One whole directory listing, all its pages together.
    pub listing: Duration,
    /// Everything one FUSE request may ask of the VM, all calls together: looking a path up again, the call and its
    /// repeat. As long as the longest single call (a listing), so that every call fits.
    pub operation: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        // A 128 KiB read from a card takes milliseconds. These leave room for a slow card and a busy phone, and
        // stay below the FUSE request timeouts apps see.
        Deadlines {
            hello: Duration::from_secs(10),
            meta: Duration::from_secs(5),
            mutate: Duration::from_secs(15),
            io: Duration::from_secs(15),
            mount: Duration::from_secs(30),
            listing: Duration::from_secs(30),
            operation: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every call a FUSE request makes fits in its operation's time.
    #[test]
    fn every_call_fits_in_an_operation() {
        let d = Deadlines::default();
        for call in [d.meta, d.mutate, d.io, d.listing] {
            assert!(call <= d.operation, "{call:?} does not fit in {:?}", d.operation);
        }
    }
}

/// The result of one call: an errno for Android (the filesystem's answer), or a broken session.
#[derive(Debug)]
pub enum CallError {
    /// The VM answered with this errno (already narrowed to the passed-through set).
    Errno(i32),
    /// The session is broken: a timeout, a closed stream or a malformed reply. Android answers EIO and the caller
    /// may start a new VM.
    Broken(String),
    /// Not sent: the call's deadline would end after the operation's (Client::op_deadline). The session stays as it
    /// was, and Android answers EIO.
    OutOfTime,
}

impl CallError {
    pub fn errno(&self) -> i32 {
        match self {
            CallError::Errno(e) => *e,
            CallError::Broken(_) | CallError::OutOfTime => errno::EIO,
        }
    }
}

pub type CallResult<T> = Result<T, CallError>;

/// The client. Not thread safe: fsvmd serialises calls on one session.
pub struct Client<T: Transport> {
    t: T,
    next_id: u32,
    broken: Option<String>,
    pub deadlines: Deadlines,
    /// The end of the operation the calls serve (a FUSE request, Deadlines::operation). A call whose own deadline
    /// would end later is not sent (CallError::OutOfTime): a call cut short would break a slow but sound session.
    pub op_deadline: Option<Instant>,
    /// Elapsed successful deferred FAT mount, cleared before each new mount attempt.
    pub deferred_fat_mount_elapsed: Duration,
}

impl<T: Transport> Client<T> {
    pub fn new(t: T, deadlines: Deadlines) -> Self {
        Client { t, next_id: 1, broken: None, deadlines, op_deadline: None, deferred_fat_mount_elapsed: Duration::ZERO }
    }

    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    /// The transport, to end the session (a socket's shutdown).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.t
    }

    fn fail<X>(&mut self, why: String) -> CallResult<X> {
        if self.broken.is_none() {
            self.broken = Some(why.clone());
        }
        Err(CallError::Broken(why))
    }

    /// Sends a request and reads the checked reply payload. `max_len` bounds the payload before it is read.
    fn call(&mut self, mut req: Request, op: Op, max_len: u32, budget: Duration) -> CallResult<Vec<u8>> {
        if matches!(op, Op::Mount) { self.deferred_fat_mount_elapsed = Duration::ZERO; }
        if let Some(why) = &self.broken {
            return Err(CallError::Broken(why.clone()));
        }
        let deadline = Instant::now() + budget;
        if self.op_deadline.is_some_and(|end| deadline > end) {
            return Err(CallError::OutOfTime);
        }
        req.op = op as u16;
        req.id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        if let Err(e) = self.t.send_by(&req.encode(), deadline) {
            return self.fail(format!("{op:?} send: {e}"));
        }
        let mut h = [0u8; RSP_HEADER];
        if let Err(e) = self.t.recv_by(&mut h, deadline) {
            return self.fail(format!("{op:?} reply header: {e}"));
        }
        let rh = match check_reply_header(&h, req.id, op, max_len) {
            Ok(rh) => rh,
            Err(e) => return self.fail(format!("{op:?} reply: {e:?}")),
        };
        if rh.status < 0 {
            return Err(CallError::Errno(errno::for_op(op, -rh.status)));
        }
        let mut payload = vec![0u8; rh.len as usize];
        if let Err(e) = self.t.recv_by(&mut payload, deadline) {
            return self.fail(format!("{op:?} payload: {e}"));
        }
        Ok(payload)
    }

    fn attr_call(&mut self, req: Request, op: Op) -> CallResult<Attr> {
        let budget = match op {
            Op::Lookup | Op::Getattr => self.deadlines.meta,
            _ => self.deadlines.mutate,
        };
        let p = self.call(req, op, ATTR_SIZE as u32, budget)?;
        match decode_attr(&p) {
            // The id of a listed name without a slot belongs in READDIR replies only.
            Ok(a) if a.node == NODE_LISTED => self.fail(format!("{op:?} attr: the listed-name id")),
            Ok(a) => Ok(a),
            Err(e) => self.fail(format!("{op:?} attr: {e:?}")),
        }
    }

    /// A node the call made must be of the kind it asked for.
    fn made(&mut self, a: Attr, kind: Kind, op: Op) -> CallResult<Attr> {
        if a.kind != kind {
            return self.fail(format!("{op:?} answered a {:?}", a.kind));
        }
        Ok(a)
    }

    fn empty_call(&mut self, req: Request, op: Op) -> CallResult<()> {
        let budget = if op == Op::Forget { self.deadlines.meta } else { self.deadlines.mutate };
        let p = self.call(req, op, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    fn checked<'a>(&self, name: &'a [u8]) -> CallResult<&'a [u8]> {
        // Names Android sends follow the same rules as names the VM returns.
        match names::check_name(name) {
            Ok(_) => Ok(name),
            Err(_) => Err(CallError::Errno(errno::EINVAL)),
        }
    }

    /// Names the disk this connection serves (`index`, 0 for the VM's first), with this side's protocol version: the
    /// first call on every connection. The VM refuses another version, and its HELLO must carry this one
    /// (decode_hello). A fresh server has nothing mounted.
    pub fn select_disk(&mut self, index: u32) -> CallResult<Hello> {
        let budget = self.deadlines.hello;
        let req = Request { node: VERSION as u64, arg: index as u64, ..Default::default() };
        let p = self.call(req, Op::Disk, HELLO_SIZE as u32, budget)?;
        match decode_hello(&p) {
            Ok(h) if h.fs_kind != 0 => self.fail("disk: a fresh server claims a mounted filesystem".into()),
            Ok(h) => Ok(h),
            Err(e) => self.fail(format!("disk: {e:?}")),
        }
    }

    pub fn hello(&mut self) -> CallResult<Hello> {
        let budget = self.deadlines.hello;
        let p = self.call(Request::default(), Op::Hello, HELLO_SIZE as u32, budget)?;
        match decode_hello(&p) {
            Ok(h) => Ok(h),
            Err(e) => self.fail(format!("hello: {e:?}")),
        }
    }

    /// Reads the partition layout the VM found on its disk, checked against the size and logical block size Android
    /// knows.
    pub fn layout(&mut self, disk_bytes: u64, block_size: u32) -> CallResult<layout::Layout> {
        let budget = self.deadlines.hello;
        let p = self.call(Request::default(), Op::Layout, layout::MAX_LAYOUT_PAYLOAD as u32, budget)?;
        match layout::decode_layout(&p, disk_bytes, block_size) {
            Ok(l) => Ok(l),
            Err(e) => self.fail(format!("layout: {e:?}")),
        }
    }

    /// Mounts partition `index` (0: the whole disk), which must still be at `start` and `length` sectors. Once per
    /// VM. A writable mount is checked first, for at most `check` (zero: no check). The reply must name a
    /// filesystem, and `expect_fs` when that is not 0. It may be read-only when the check did not finish.
    pub fn mount(&mut self, index: u32, start: u64, length: u64, read_only: bool, expect_fs: u32, check: Duration) -> CallResult<Hello> {
        let check_ms = check.as_millis().min(u32::MAX as u128) as u32;
        // The check, then the mount and the first free-space count.
        let budget = self.deadlines.mount + check;
        let req = Request {
            arg: index as u64,
            node: start,
            node2: length,
            flags: read_only as u16,
            len: check_ms,
            ..Default::default()
        };
        let p = self.call(req, Op::Mount, HELLO_SIZE as u32, budget)?;
        match decode_hello(&p) {
            Ok(h) if h.fs_kind == 0 => self.fail("mount: no filesystem".into()),
            Ok(h) if expect_fs != 0 && h.fs_kind != expect_fs => {
                self.fail(format!("mount: filesystem {} where the layout said {expect_fs}", h.fs_kind))
            }
            Ok(h) if read_only && !h.read_only => self.fail("mount: writable where read-only was asked".into()),
            // A read-only mount has no check after it: that check's switch would make it writable.
            Ok(h) if read_only && h.check_pending => self.fail("mount: a check pending where read-only was asked".into()),
            Ok(h) => Ok(h),
            Err(e) => self.fail(format!("mount: {e:?}")),
        }
    }

    /// Mounts writable, as fsvmd serves cards: a volume marked dirty is mounted read-only at once and checked
    /// afterwards (`check_poll`, `check_switch`), and HELLO's `check_pending` says so. Nothing is checked before the
    /// mount, so the mount keeps to its own deadline.
    pub fn mount_check_later(&mut self, index: u32, start: u64, length: u64, expect_fs: u32) -> CallResult<Hello> {
        let budget = self.deadlines.mount;
        let req = Request { arg: index as u64, node: start, node2: length, flags: 2, ..Default::default() };
        let started = Instant::now();
        let p = self.call(req, Op::Mount, HELLO_SIZE as u32, budget)?;
        match decode_hello(&p) {
            Ok(h) if h.fs_kind == 0 => self.fail("mount: no filesystem".into()),
            Ok(h) if expect_fs != 0 && h.fs_kind != expect_fs => {
                self.fail(format!("mount: filesystem {} where the layout said {expect_fs}", h.fs_kind))
            }
            Ok(h) => { self.deferred_fat_mount_elapsed = if h.fs_kind == FS_VFAT { started.elapsed() } else { Duration::ZERO }; Ok(h) },
            Err(e) => self.fail(format!("mount: {e:?}")),
        }
    }

    /// Formats the VM's whole disk as `fs` (FS_VFAT or FS_EXFAT) within `budget`.
    pub fn format(&mut self, fs: u32, budget: Duration) -> CallResult<()> {
        let ms = budget.as_millis().min(u32::MAX as u128) as u32;
        let p = self.call(Request { arg: fs as u64, len: ms, ..Default::default() }, Op::Format, 0, budget + Duration::from_secs(2))?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    /// Starts the check after the mount, or tells how it goes and how long it ran.
    pub fn check_poll(&mut self) -> CallResult<(CheckState, Duration)> {
        let budget = self.deadlines.meta;
        let p = self.call(Request { arg: 0, ..Default::default() }, Op::Check, 8, budget)?;
        if p.len() != 8 {
            return self.fail(format!("check reply {} bytes", p.len()));
        }
        let state = match le_u32(&p, 0) {
            0 => CheckState::Running,
            1 => CheckState::Passed,
            2 => CheckState::Errors,
            3 => CheckState::Failed,
            4 => CheckState::None,
            s => return self.fail(format!("check state {s}")),
        };
        Ok((state, Duration::from_millis(le_u32(&p, 4) as u64)))
    }

    /// The switch after the check: unmounted, repaired within `repair` if the check found errors, marked clean and
    /// mounted writable. An errno means the volume stays read-only. `budget` covers the repair, the unmount and the
    /// mount with its free-space count.
    pub fn check_switch(&mut self, repair: Duration, budget: Duration) -> CallResult<()> {
        let repair_ms = repair.as_millis().min(u32::MAX as u128) as u32;
        let p = self.call(Request { arg: 1, len: repair_ms, ..Default::default() }, Op::Check, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    pub fn lookup(&mut self, parent: u64, name: &[u8]) -> CallResult<Attr> {
        let name = match names::check_name(name) {
            Ok(_) => name,
            // A name that could never be listed is not there.
            Err(_) => return Err(CallError::Errno(errno::ENOENT)),
        };
        self.attr_call(Request { node: parent, name, ..Default::default() }, Op::Lookup)
    }

    pub fn getattr(&mut self, node: u64) -> CallResult<Attr> {
        self.attr_call(Request { node, ..Default::default() }, Op::Getattr)
    }

    /// Reads a whole directory, page by page, deduplicated and capped in entries, bytes and time
    /// (`deadlines.listing` for all pages together). What is not read in time is not shown.
    pub fn list(&mut self, dir: u64) -> CallResult<Listing> {
        let mut listing = Listing::default();
        let mut seen = std::collections::HashSet::new();
        let mut cookie = 0u64;
        let mut deadline = Instant::now() + self.deadlines.listing;
        if let Some(end) = self.op_deadline {
            deadline = deadline.min(end);
        }
        for _ in 0..MAX_DIR_PAGES {
            // A page gets its full deadline or is not asked for: a slow page cut short would break the session.
            let left = deadline.saturating_duration_since(Instant::now());
            if left < self.deadlines.meta {
                listing.truncated = true;
                return Ok(listing);
            }
            let budget = self.deadlines.meta;
            let p = self.call(Request { node: dir, arg: cookie, ..Default::default() }, Op::Readdir, MAX_DIR_PAYLOAD as u32, budget)?;
            let page = match decode_dir_page(&p) {
                Ok(page) => page,
                Err(e) => return self.fail(format!("readdir: {e:?}")),
            };
            let next = page.next_cookie;
            if !listing.add_page(page, &mut seen) {
                return Ok(listing);
            }
            if next == 0 {
                return Ok(listing);
            }
            // Cookies must move forward, or a VM could loop Android forever.
            if next <= cookie {
                return self.fail(format!("readdir: cookie {next} after {cookie}"));
            }
            cookie = next;
        }
        listing.truncated = true;
        Ok(listing)
    }

    /// Reads at most `len` bytes (at most MAX_IO) at `offset`. The reply may be shorter, never longer.
    pub fn read(&mut self, node: u64, offset: u64, len: u32) -> CallResult<Vec<u8>> {
        let len = len.min(MAX_IO);
        let budget = self.deadlines.io;
        self.call(Request { node, arg: offset, len, ..Default::default() }, Op::Read, len, budget)
    }

    /// Writes at most MAX_IO bytes at `offset` and returns how many the VM wrote.
    pub fn write(&mut self, node: u64, offset: u64, data: &[u8]) -> CallResult<u32> {
        let data = &data[..data.len().min(MAX_IO as usize)];
        let budget = self.deadlines.io;
        let p = self.call(
            Request { node, arg: offset, len: data.len() as u32, data, ..Default::default() },
            Op::Write,
            WRITE_REPLY_SIZE as u32,
            budget,
        )?;
        if p.len() != WRITE_REPLY_SIZE {
            return self.fail(format!("write reply {} bytes", p.len()));
        }
        let n = le_u32(&p, 0);
        if n as usize > data.len() {
            return self.fail(format!("write: {n} written of {}", data.len()));
        }
        Ok(n)
    }

    /// Opens a file and answers the VM's handle for it (0 is never one). EMFILE when the VM has no handle left.
    pub fn open_handle(&mut self, node: u64, write: bool) -> CallResult<u64> {
        let budget = self.deadlines.meta;
        let p = self.call(Request { node, flags: write as u16, ..Default::default() }, Op::Open, 8, budget)?;
        if p.len() != 8 || le_u64(&p, 0) == 0 {
            return self.fail("open: no handle".to_string());
        }
        Ok(le_u64(&p, 0))
    }

    pub fn close_handle(&mut self, handle: u64) -> CallResult<()> {
        let budget = self.deadlines.meta;
        let p = self.call(Request { node2: handle, ..Default::default() }, Op::Close, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    /// READ through an open file's handle.
    pub fn read_handle(&mut self, handle: u64, offset: u64, len: u32) -> CallResult<Vec<u8>> {
        let len = len.min(MAX_IO);
        let budget = self.deadlines.io;
        self.call(Request { node2: handle, arg: offset, len, ..Default::default() }, Op::Read, len, budget)
    }

    /// WRITE through an open file's handle.
    pub fn write_handle(&mut self, handle: u64, offset: u64, data: &[u8]) -> CallResult<u32> {
        let data = &data[..data.len().min(MAX_IO as usize)];
        let budget = self.deadlines.io;
        let p = self.call(
            Request { node2: handle, arg: offset, len: data.len() as u32, data, ..Default::default() },
            Op::Write,
            WRITE_REPLY_SIZE as u32,
            budget,
        )?;
        if p.len() != WRITE_REPLY_SIZE {
            return self.fail(format!("write reply {} bytes", p.len()));
        }
        let n = le_u32(&p, 0);
        if n as usize > data.len() {
            return self.fail(format!("write: {n} written of {}", data.len()));
        }
        Ok(n)
    }

    /// GETATTR through an open file's handle (its size and time even after its name went).
    pub fn getattr_handle(&mut self, handle: u64) -> CallResult<Attr> {
        self.attr_call(Request { node2: handle, node: 1, ..Default::default() }, Op::Getattr)
    }

    /// FSYNC through an open file's handle.
    pub fn fsync_handle(&mut self, handle: u64, datasync: bool) -> CallResult<()> {
        let budget = self.deadlines.io;
        let p = self.call(Request { node2: handle, flags: datasync as u16, ..Default::default() }, Op::Fsync, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    pub fn create(&mut self, parent: u64, name: &[u8], exclusive: bool) -> CallResult<Attr> {
        let name = self.checked(name)?;
        let a = self.attr_call(Request { node: parent, name, flags: exclusive as u16, ..Default::default() }, Op::Create)?;
        self.made(a, Kind::File, Op::Create)
    }

    pub fn mkdir(&mut self, parent: u64, name: &[u8]) -> CallResult<Attr> {
        let name = self.checked(name)?;
        let a = self.attr_call(Request { node: parent, name, ..Default::default() }, Op::Mkdir)?;
        self.made(a, Kind::Dir, Op::Mkdir)
    }

    pub fn unlink(&mut self, parent: u64, name: &[u8]) -> CallResult<()> {
        let name = self.checked(name)?;
        self.empty_call(Request { node: parent, name, ..Default::default() }, Op::Unlink)
    }

    pub fn rmdir(&mut self, parent: u64, name: &[u8]) -> CallResult<()> {
        let name = self.checked(name)?;
        self.empty_call(Request { node: parent, name, ..Default::default() }, Op::Rmdir)
    }

    pub fn rename(&mut self, from_dir: u64, from: &[u8], to_dir: u64, to: &[u8]) -> CallResult<()> {
        let name = self.checked(from)?;
        let name2 = self.checked(to)?;
        self.empty_call(Request { node: from_dir, name, node2: to_dir, name2, ..Default::default() }, Op::Rename)
    }

    pub fn truncate(&mut self, node: u64, size: u64) -> CallResult<Attr> {
        if size > MAX_FILE_SIZE {
            return Err(CallError::Errno(errno::EFBIG));
        }
        self.attr_call(Request { node, arg: size, ..Default::default() }, Op::Truncate)
    }

    pub fn set_mtime(&mut self, node: u64, secs: i64, nanos: u32) -> CallResult<Attr> {
        let secs = secs.clamp(MTIME_MIN, MTIME_MAX) as u64;
        self.attr_call(Request { node, arg: secs, len: nanos.min(999_999_999), ..Default::default() }, Op::SetMtime)
    }

    /// Truncates the open file even after its name went. A replaced VM's handle is never sent here.
    pub fn truncate_handle(&mut self, handle: u64, size: u64) -> CallResult<Attr> {
        if size > MAX_FILE_SIZE {
            return Err(CallError::Errno(errno::EFBIG));
        }
        self.attr_call(Request { node2: handle, arg: size, ..Default::default() }, Op::Truncate)
    }

    /// Sets the open file's time through its handle.
    pub fn set_mtime_handle(&mut self, handle: u64, secs: i64, nanos: u32) -> CallResult<Attr> {
        let secs = secs.clamp(MTIME_MIN, MTIME_MAX) as u64;
        self.attr_call(Request { node2: handle, arg: secs, len: nanos.min(999_999_999), ..Default::default() }, Op::SetMtime)
    }

    pub fn statfs(&mut self) -> CallResult<Statfs> {
        let budget = self.deadlines.meta;
        let p = self.call(Request::default(), Op::Statfs, STATFS_SIZE as u32, budget)?;
        match decode_statfs(&p) {
            Ok(s) => Ok(s),
            Err(e) => self.fail(format!("statfs: {e:?}")),
        }
    }

    /// Writes a file's or directory's data (and with `datasync` false its metadata) to the card.
    pub fn fsync(&mut self, node: u64, datasync: bool) -> CallResult<()> {
        // A flush to a slow card can take a while.
        let budget = self.deadlines.io;
        let p = self.call(Request { node, flags: datasync as u16, ..Default::default() }, Op::Fsync, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    /// Writes everything back and unmounts the filesystem in the VM, which marks it clean. The VM can be stopped
    /// afterwards without losing anything. Errno when the VM could not write back or unmount.
    pub fn unmount(&mut self, budget: Duration) -> CallResult<()> {
        let p = self.call(Request::default(), Op::Unmount, 0, budget)?;
        debug_assert!(p.is_empty());
        Ok(())
    }

    /// The bytes the VM still has to write to its disk.
    pub fn dirty(&mut self) -> CallResult<u64> {
        let budget = self.deadlines.meta;
        let p = self.call(Request::default(), Op::Dirty, 8, budget)?;
        if p.len() != 8 {
            return self.fail(format!("dirty: {} bytes", p.len()));
        }
        Ok(le_u64(&p, 0))
    }

    pub fn forget(&mut self, node: u64) -> CallResult<()> {
        match self.empty_call(Request { node, ..Default::default() }, Op::Forget) {
            // A versioned node evicted by the guest has already retired this lookup debt.
            Err(CallError::Errno(errno::ESTALE | errno::ENOENT)) => Ok(()),
            result => result,
        }
    }
}
