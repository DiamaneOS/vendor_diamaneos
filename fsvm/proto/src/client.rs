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
}

impl CallError {
    pub fn errno(&self) -> i32 {
        match self {
            CallError::Errno(e) => *e,
            CallError::Broken(_) => errno::EIO,
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
}

impl<T: Transport> Client<T> {
    pub fn new(t: T, deadlines: Deadlines) -> Self {
        Client { t, next_id: 1, broken: None, deadlines }
    }

    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    fn fail<X>(&mut self, why: String) -> CallResult<X> {
        if self.broken.is_none() {
            self.broken = Some(why.clone());
        }
        Err(CallError::Broken(why))
    }

    /// Sends a request and reads the checked reply payload. `max_len` bounds the payload before it is read.
    fn call(&mut self, mut req: Request, op: Op, max_len: u32, budget: Duration) -> CallResult<Vec<u8>> {
        if let Some(why) = &self.broken {
            return Err(CallError::Broken(why.clone()));
        }
        let deadline = Instant::now() + budget;
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
            return Err(CallError::Errno(errno::pass_through(-rh.status)));
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
            Ok(h) => Ok(h),
            Err(e) => self.fail(format!("mount: {e:?}")),
        }
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
        let deadline = Instant::now() + self.deadlines.listing;
        for _ in 0..MAX_DIR_PAGES {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                listing.truncated = true;
                return Ok(listing);
            }
            let budget = self.deadlines.meta.min(left);
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

    pub fn create(&mut self, parent: u64, name: &[u8], exclusive: bool) -> CallResult<Attr> {
        let name = self.checked(name)?;
        self.attr_call(Request { node: parent, name, flags: exclusive as u16, ..Default::default() }, Op::Create)
    }

    pub fn mkdir(&mut self, parent: u64, name: &[u8]) -> CallResult<Attr> {
        let name = self.checked(name)?;
        self.attr_call(Request { node: parent, name, ..Default::default() }, Op::Mkdir)
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

    pub fn forget(&mut self, node: u64) -> CallResult<()> {
        self.empty_call(Request { node, ..Default::default() }, Op::Forget)
    }
}
