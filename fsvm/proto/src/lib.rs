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

//! The protocol between fsvmd on Android and the filesystem VM, version 3.
//!
//! A protected VM mounts a removable filesystem (SD card, USB drive) with its own kernel and serves it over vsock.
//! The VM is assumed hostile: a crafted filesystem may have taken over its kernel. So this crate decodes every reply
//! against fixed sizes and limits before anything reaches Android's FUSE code, and every call has a total deadline.
//! Any malformed reply breaks the session: the caller fails the request and starts a new VM at most a few times.
//!
//! All integers are little endian. One request, one reply.
//!
//! Request header (48 bytes): magic `FMV2`, op u16, flags u16, id u32, name_len u32, node u64, node2 u64, arg u64,
//! len u32, name2_len u32. Then name, name2, and for WRITE the data.
//!
//! Reply header (16 bytes): magic `FMR2`, id u32, status i32 (0, or a negative Linux errno), len u32. Then len
//! payload bytes. An error reply carries no payload.
//!
//! A VM starts with nothing mounted. LAYOUT reports the partitions it read from the disk (phase 2: Android's kernel
//! reads no partition table of an SD card or USB disk, see `layout`). MOUNT then mounts one of them, once per VM,
//! and replies like HELLO. Every other operation needs a mounted volume.
//!
//! The guest's mirror of these definitions is `guest/proto.h`.

#![forbid(unsafe_code)]

pub mod client;
pub mod layout;
pub mod names;

pub use client::{Client, Deadlines, StreamTransport, Transport};

pub const REQ_MAGIC: u32 = u32::from_le_bytes(*b"FMV2");
pub const RSP_MAGIC: u32 = u32::from_le_bytes(*b"FMR2");
/// 4: UNMOUNT, DIRTY, the data-only FSYNC flag and the dirty flag in HELLO. 5: OPEN and CLOSE, and file handles in
/// READ, WRITE and FSYNC. 6: the check after the mount (MOUNT flags bit 1, CHECK, HELLO's check flag).
pub const VERSION: u32 = 6;
pub const PORT: u32 = 5690;

pub const REQ_HEADER: usize = 48;
pub const RSP_HEADER: usize = 16;
pub const ATTR_SIZE: usize = 32;
pub const HELLO_SIZE: usize = 24;
pub const STATFS_SIZE: usize = 32;
pub const WRITE_REPLY_SIZE: usize = 8;
pub const DIR_PAGE_HEADER: usize = 16;

/// Largest READ or WRITE.
pub const MAX_IO: u32 = 128 * 1024;
/// Largest READDIR reply.
pub const MAX_DIR_PAYLOAD: usize = 64 * 1024;
/// Most entries in one READDIR reply.
pub const MAX_DIR_ENTRIES_PER_PAGE: u32 = 512;
/// Most entries kept for one directory. A crafted card can claim far more. Entries beyond this are not shown.
pub const MAX_DIR_ENTRIES: usize = 65536;
/// Most READDIR pages for one directory listing.
pub const MAX_DIR_PAGES: usize = 1024;
/// Memory one listing may take (names plus a fixed charge per entry), and all open listings of a volume together.
/// Entries beyond are not shown.
pub const MAX_LISTING_BYTES: usize = 4 << 20;
pub const MAX_OPEN_LISTING_BYTES: usize = 16 << 20;
/// What one listed entry costs besides its name.
pub const LISTING_ENTRY_COST: usize = 64;

/// Largest file size accepted from the VM (16 TiB, beyond any exFAT card sold today).
pub const MAX_FILE_SIZE: u64 = 1 << 44;
/// Modification times are clamped into the range FAT and exFAT can store, 1980 to 2107, plus the epoch for files
/// written without a time.
pub const MTIME_MIN: i64 = 0;
pub const MTIME_MAX: i64 = 4_354_819_199;

/// Operations.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Hello = 1,
    Lookup = 2,
    Getattr = 3,
    Readdir = 4,
    Read = 5,
    Write = 6,
    Create = 7,
    Mkdir = 8,
    Unlink = 9,
    Rmdir = 10,
    Rename = 11,
    Truncate = 12,
    SetMtime = 13,
    Statfs = 14,
    Fsync = 15,
    Forget = 16,
    Layout = 17,
    Mount = 18,
    /// Writes everything back, unmounts the filesystem in the VM (which marks it clean) and answers 0, or an errno
    /// when either failed. fsvmd sends it before every orderly stop of the VM.
    Unmount = 19,
    /// The bytes the VM still has to write to its disk (dirty plus under write back), 8 bytes. fsvmd watches it go
    /// down before an orderly stop.
    Dirty = 20,
    /// Opens a node (flags bit 0: for writing) and answers a handle, 8 bytes. READ, WRITE and FSYNC with the handle
    /// in `node2` reach the file even after its name went (unlinked, renamed over), as with a kernel mount.
    Open = 21,
    /// Closes the handle in `node2`.
    Close = 22,
    /// The check after a mount (MOUNT flags bit 1). `arg` 0: starts it or tells how it goes (8 bytes: state u32,
    /// milliseconds it ran u32). `arg` 1: the switch once it ended (`len`: milliseconds a repair may take), which
    /// unmounts, repairs if needed, marks the volume clean and mounts it writable, or answers an errno and leaves it
    /// read-only.
    Check = 23,
}

/// How the check after a mount goes (CHECK `arg` 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Running,
    /// No error but the dirty mark: the switch marks the volume clean.
    Passed,
    /// Errors the switch repairs.
    Errors,
    /// The checker did not run or did not finish: the volume stays read-only.
    Failed,
    /// No check pending.
    None,
}

/// The kinds of node a filesystem on a card can hold. FAT and exFAT have no links or special files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File = 1,
    Dir = 2,
}

/// Linux errno values the VM may report. Anything else becomes EIO.
pub mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EBADF: i32 = 9;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const EFBIG: i32 = 27;
    pub const ENOSPC: i32 = 28;
    pub const EROFS: i32 = 30;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOTEMPTY: i32 = 39;
    pub const ETIMEDOUT: i32 = 110;
    /// The VM no longer knows a node id (it took the slot back). fsvmd looks the name up again.
    pub const ESTALE: i32 = 116;

    /// Errors passed through as they are. They describe the filesystem, not the VM, and cannot confuse Android.
    pub fn pass_through(e: i32) -> i32 {
        match e {
            EPERM | ENOENT | EIO | EACCES | EBUSY | EEXIST | EXDEV | ENOTDIR | EISDIR | EINVAL | EFBIG
            | ENOSPC | EROFS | ENAMETOOLONG | ENOTEMPTY | ESTALE => e,
            _ => EIO,
        }
    }
}

/// The node id of a listed name the VM keeps no slot for (READDIR only). Never valid in a request.
pub const NODE_LISTED: u64 = u64::MAX;

/// Attributes of a node, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    /// The VM's handle for the node. Opaque, never used as an inode number on Android.
    pub node: u64,
    pub kind: Kind,
    /// File size. 0 for directories, whatever the VM said.
    pub size: u64,
    pub mtime_s: i64,
    pub mtime_ns: u32,
}

/// Why a reply was refused. Every variant breaks the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    BadMagic,
    WrongId { expected: u32, got: u32 },
    BadStatus(i32),
    PayloadOnError(u32),
    BadLength { op: Op, len: u32 },
    BadAttr(&'static str),
    BadDirPage(&'static str),
    BadLayout(layout::LayoutError),
    NotRunning,
}

pub(crate) fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub(crate) fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub(crate) fn le_i32(b: &[u8], at: usize) -> i32 {
    le_u32(b, at) as i32
}
pub(crate) fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// One request.
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    pub op: u16,
    pub flags: u16,
    pub id: u32,
    pub node: u64,
    pub node2: u64,
    pub arg: u64,
    pub len: u32,
    pub name: &'a [u8],
    pub name2: &'a [u8],
    pub data: &'a [u8],
}

impl Request<'_> {
    /// Encodes the request. Names must have been checked by the caller.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(REQ_HEADER + self.name.len() + self.name2.len() + self.data.len());
        b.extend_from_slice(&REQ_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.op.to_le_bytes());
        b.extend_from_slice(&self.flags.to_le_bytes());
        b.extend_from_slice(&self.id.to_le_bytes());
        b.extend_from_slice(&(self.name.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.node.to_le_bytes());
        b.extend_from_slice(&self.node2.to_le_bytes());
        b.extend_from_slice(&self.arg.to_le_bytes());
        b.extend_from_slice(&self.len.to_le_bytes());
        b.extend_from_slice(&(self.name2.len() as u32).to_le_bytes());
        b.extend_from_slice(self.name);
        b.extend_from_slice(self.name2);
        b.extend_from_slice(self.data);
        b
    }
}

/// A reply header, checked against the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyHeader {
    pub status: i32,
    pub len: u32,
}

/// Checks a reply header. `max_len` is the largest payload the operation allows. It is checked before any payload
/// is read, so a VM cannot make Android allocate or wait for more.
pub fn check_reply_header(h: &[u8; RSP_HEADER], id: u32, op: Op, max_len: u32) -> Result<ReplyHeader, ProtoError> {
    if le_u32(h, 0) != RSP_MAGIC {
        return Err(ProtoError::BadMagic);
    }
    let got = le_u32(h, 4);
    if got != id {
        return Err(ProtoError::WrongId { expected: id, got });
    }
    let status = le_i32(h, 8);
    let len = le_u32(h, 12);
    if status > 0 || status < -4095 {
        return Err(ProtoError::BadStatus(status));
    }
    if status < 0 && len != 0 {
        return Err(ProtoError::PayloadOnError(len));
    }
    if len > max_len {
        return Err(ProtoError::BadLength { op, len });
    }
    Ok(ReplyHeader { status, len })
}

/// Decodes and checks a node's attributes.
pub fn decode_attr(b: &[u8]) -> Result<Attr, ProtoError> {
    if b.len() != ATTR_SIZE {
        return Err(ProtoError::BadAttr("size"));
    }
    let node = le_u64(b, 0);
    if node == 0 {
        return Err(ProtoError::BadAttr("node 0"));
    }
    let kind = match b[28] {
        1 => Kind::File,
        2 => Kind::Dir,
        _ => return Err(ProtoError::BadAttr("kind")),
    };
    let size = le_u64(b, 8);
    let size = match kind {
        Kind::File if size > MAX_FILE_SIZE => return Err(ProtoError::BadAttr("file size")),
        Kind::File => size,
        Kind::Dir => 0,
    };
    let mtime_s = (le_u64(b, 16) as i64).clamp(MTIME_MIN, MTIME_MAX);
    let mtime_ns = le_u32(b, 24);
    let mtime_ns = if mtime_ns >= 1_000_000_000 { 0 } else { mtime_ns };
    Ok(Attr { node, kind, size, mtime_s, mtime_ns })
}

/// Encodes attributes (used by the guest's test double and by tests).
pub fn encode_attr(a: &Attr) -> [u8; ATTR_SIZE] {
    let mut b = [0u8; ATTR_SIZE];
    b[0..8].copy_from_slice(&a.node.to_le_bytes());
    b[8..16].copy_from_slice(&a.size.to_le_bytes());
    b[16..24].copy_from_slice(&a.mtime_s.to_le_bytes());
    b[24..28].copy_from_slice(&a.mtime_ns.to_le_bytes());
    b[28] = a.kind as u8;
    b
}

/// What the VM says about itself. `fs_kind` is 0 while nothing is mounted (HELLO on a fresh VM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub fs_kind: u32,
    pub read_only: bool,
    /// The filesystem was marked dirty when the VM mounted it (it was not cleanly unmounted before).
    pub was_dirty: bool,
    /// Mounted read-only until the check after the mount passes (CHECK).
    pub check_pending: bool,
    pub root: u64,
}

pub const FS_VFAT: u32 = 1;
pub const FS_EXFAT: u32 = 2;

pub fn decode_hello(b: &[u8]) -> Result<Hello, ProtoError> {
    if b.len() != HELLO_SIZE || le_u32(b, 0) != VERSION {
        return Err(ProtoError::BadLength { op: Op::Hello, len: b.len() as u32 });
    }
    let fs_kind = le_u32(b, 4);
    if fs_kind != 0 && fs_kind != FS_VFAT && fs_kind != FS_EXFAT {
        return Err(ProtoError::BadAttr("filesystem kind"));
    }
    if le_u32(b, 8) & !7 != 0 || le_u32(b, 12) != 0 {
        return Err(ProtoError::BadAttr("hello flags"));
    }
    let root = le_u64(b, 16);
    if root == 0 {
        return Err(ProtoError::BadAttr("root node 0"));
    }
    let flags = le_u32(b, 8);
    let check_pending = flags & 4 != 0;
    // Pending means read-only until the check passed.
    if check_pending && flags & 1 == 0 {
        return Err(ProtoError::BadAttr("hello flags"));
    }
    Ok(Hello { fs_kind, read_only: flags & 1 != 0, was_dirty: flags & 2 != 0, check_pending, root })
}

/// Filesystem totals, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub bsize: u32,
    pub namemax: u32,
}

pub fn decode_statfs(b: &[u8]) -> Result<Statfs, ProtoError> {
    if b.len() != STATFS_SIZE {
        return Err(ProtoError::BadLength { op: Op::Statfs, len: b.len() as u32 });
    }
    let bsize = le_u32(b, 24);
    if !(512..=(1 << 20)).contains(&bsize) || !bsize.is_power_of_two() {
        return Err(ProtoError::BadAttr("block size"));
    }
    let max_blocks = MAX_FILE_SIZE / bsize as u64 * 4;
    let blocks = le_u64(b, 0).min(max_blocks);
    let bfree = le_u64(b, 8).min(blocks);
    let bavail = le_u64(b, 16).min(bfree);
    Ok(Statfs { blocks, bfree, bavail, bsize, namemax: 255 })
}

/// One READDIR page as decoded: entries that passed every check, and how many were dropped.
#[derive(Debug, Default)]
pub struct DirPage {
    pub next_cookie: u64,
    pub entries: Vec<(String, Attr)>,
    pub dropped: u32,
}

/// Decodes a READDIR page. Structure errors (lengths that do not add up) break the session. A single bad entry
/// (forbidden name, unknown kind) is dropped and counted, the rest of the page is kept.
pub fn decode_dir_page(b: &[u8]) -> Result<DirPage, ProtoError> {
    if b.len() < DIR_PAGE_HEADER || b.len() > MAX_DIR_PAYLOAD {
        return Err(ProtoError::BadDirPage("page size"));
    }
    let next_cookie = le_u64(b, 0);
    let count = le_u32(b, 8);
    if count > MAX_DIR_ENTRIES_PER_PAGE {
        return Err(ProtoError::BadDirPage("entry count"));
    }
    let mut page = DirPage { next_cookie, ..Default::default() };
    let mut at = DIR_PAGE_HEADER;
    for _ in 0..count {
        if b.len() - at < ATTR_SIZE + 2 {
            return Err(ProtoError::BadDirPage("truncated entry"));
        }
        let attr = &b[at..at + ATTR_SIZE];
        let name_len = le_u16(b, at + ATTR_SIZE) as usize;
        at += ATTR_SIZE + 2;
        if name_len > names::MAX_NAME_BYTES || b.len() - at < name_len {
            return Err(ProtoError::BadDirPage("name length"));
        }
        let raw = &b[at..at + name_len];
        at += name_len;
        match (names::check_name(raw), decode_attr(attr)) {
            (Ok(name), Ok(a)) => page.entries.push((name.to_string(), a)),
            _ => page.dropped += 1,
        }
    }
    if at != b.len() {
        return Err(ProtoError::BadDirPage("trailing bytes"));
    }
    Ok(page)
}

/// Encodes a READDIR page (for the test double and tests).
pub fn encode_dir_page(next_cookie: u64, entries: &[(&[u8], Attr)]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&next_cookie.to_le_bytes());
    b.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    for (name, a) in entries {
        b.extend_from_slice(&encode_attr(a));
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name);
    }
    b
}

/// A whole directory listing after deduplication.
#[derive(Debug, Default)]
pub struct Listing {
    pub entries: Vec<(String, Attr)>,
    /// Memory the entries take, as MAX_LISTING_BYTES counts it.
    pub bytes: usize,
    /// Entries refused for their name or attributes.
    pub dropped: u32,
    /// Entries that repeat an earlier name, exactly or without case.
    pub duplicates: u32,
    /// True when the directory had more entries than are shown.
    pub truncated: bool,
}

impl Listing {
    /// Adds a page, dropping duplicates. Returns false once the listing is full.
    pub fn add_page(&mut self, page: DirPage, seen: &mut std::collections::HashSet<String>) -> bool {
        self.dropped += page.dropped;
        for (name, attr) in page.entries {
            if self.entries.len() >= MAX_DIR_ENTRIES || self.bytes + name.len() + LISTING_ENTRY_COST > MAX_LISTING_BYTES {
                self.truncated = true;
                return false;
            }
            if !seen.insert(names::collision_key(&name)) {
                self.duplicates += 1;
                continue;
            }
            self.bytes += name.len() + LISTING_ENTRY_COST;
            self.entries.push((name, attr));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(node: u64, kind: Kind, size: u64) -> Attr {
        Attr { node, kind, size, mtime_s: 1_700_000_000, mtime_ns: 5 }
    }

    #[test]
    fn attr_round_trip_and_limits() {
        let a = attr(7, Kind::File, 1234);
        assert_eq!(decode_attr(&encode_attr(&a)), Ok(a));
        let mut b = encode_attr(&a);
        b[28] = 3;
        assert!(decode_attr(&b).is_err());
        let mut big = a;
        big.size = MAX_FILE_SIZE + 1;
        assert!(decode_attr(&encode_attr(&big)).is_err());
        let mut zero = a;
        zero.node = 0;
        assert!(decode_attr(&encode_attr(&zero)).is_err());
        // Directories always read as size 0.
        let d = attr(9, Kind::Dir, u64::MAX);
        assert_eq!(decode_attr(&encode_attr(&d)).unwrap().size, 0);
        // Times outside FAT's range are clamped, bad nanoseconds become 0.
        let mut t = a;
        t.mtime_s = -5;
        t.mtime_ns = 2_000_000_000;
        let got = decode_attr(&encode_attr(&t)).unwrap();
        assert_eq!((got.mtime_s, got.mtime_ns), (MTIME_MIN, 0));
        t.mtime_s = i64::MAX;
        assert_eq!(decode_attr(&encode_attr(&t)).unwrap().mtime_s, MTIME_MAX);
    }

    #[test]
    fn reply_header_checks() {
        let mk = |magic: u32, id: u32, status: i32, len: u32| {
            let mut h = [0u8; RSP_HEADER];
            h[0..4].copy_from_slice(&magic.to_le_bytes());
            h[4..8].copy_from_slice(&id.to_le_bytes());
            h[8..12].copy_from_slice(&status.to_le_bytes());
            h[12..16].copy_from_slice(&len.to_le_bytes());
            h
        };
        assert_eq!(check_reply_header(&mk(RSP_MAGIC, 3, 0, 32), 3, Op::Getattr, 32), Ok(ReplyHeader { status: 0, len: 32 }));
        assert_eq!(check_reply_header(&mk(REQ_MAGIC, 3, 0, 32), 3, Op::Getattr, 32), Err(ProtoError::BadMagic));
        assert!(matches!(check_reply_header(&mk(RSP_MAGIC, 4, 0, 32), 3, Op::Getattr, 32), Err(ProtoError::WrongId { .. })));
        assert_eq!(check_reply_header(&mk(RSP_MAGIC, 3, 5, 0), 3, Op::Getattr, 32), Err(ProtoError::BadStatus(5)));
        assert_eq!(check_reply_header(&mk(RSP_MAGIC, 3, -9999, 0), 3, Op::Getattr, 32), Err(ProtoError::BadStatus(-9999)));
        assert_eq!(check_reply_header(&mk(RSP_MAGIC, 3, -2, 4), 3, Op::Getattr, 32), Err(ProtoError::PayloadOnError(4)));
        assert!(matches!(check_reply_header(&mk(RSP_MAGIC, 3, 0, u32::MAX), 3, Op::Read, MAX_IO), Err(ProtoError::BadLength { .. })));
    }

    #[test]
    fn dir_page_drops_bad_entries_and_refuses_bad_structure() {
        let good = attr(5, Kind::File, 10);
        let page = encode_dir_page(0, &[(b"ok.txt", good), (b"..", good), (b"a/b", good), (b"fine", good)]);
        let p = decode_dir_page(&page).unwrap();
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.dropped, 2);
        // Unknown kind inside an entry is dropped, not fatal.
        let mut page2 = encode_dir_page(0, &[(b"x", good)]);
        page2[DIR_PAGE_HEADER + 28] = 9;
        let p2 = decode_dir_page(&page2).unwrap();
        assert_eq!((p2.entries.len(), p2.dropped), (0, 1));
        // Trailing bytes, truncated entries and oversized counts are fatal.
        let mut t = page.clone();
        t.push(0);
        assert!(decode_dir_page(&t).is_err());
        assert!(decode_dir_page(&page[..page.len() - 1]).is_err());
        let mut c = page.clone();
        c[8..12].copy_from_slice(&(MAX_DIR_ENTRIES_PER_PAGE + 1).to_le_bytes());
        assert!(decode_dir_page(&c).is_err());
        let mut n = encode_dir_page(0, &[(b"x", good)]);
        let at = DIR_PAGE_HEADER + ATTR_SIZE;
        n[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(decode_dir_page(&n).is_err());
    }

    #[test]
    fn listing_drops_duplicates_and_case_collisions() {
        let a = attr(5, Kind::File, 1);
        let mut l = Listing::default();
        let mut seen = std::collections::HashSet::new();
        let p = decode_dir_page(&encode_dir_page(0, &[(b"IMG.jpg", a), (b"img.JPG", a), (b"IMG.jpg", a), (b"other", a)])).unwrap();
        assert!(l.add_page(p, &mut seen));
        assert_eq!(l.entries.len(), 2);
        assert_eq!(l.duplicates, 2);
        assert_eq!(l.entries[0].0, "IMG.jpg");
    }

    #[test]
    fn hello_and_statfs() {
        let mut h = [0u8; HELLO_SIZE];
        h[0..4].copy_from_slice(&VERSION.to_le_bytes());
        h[4..8].copy_from_slice(&FS_EXFAT.to_le_bytes());
        h[16..24].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            decode_hello(&h).unwrap(),
            Hello { fs_kind: FS_EXFAT, read_only: false, was_dirty: false, check_pending: false, root: 1 }
        );
        h[8] = 2;
        assert!(decode_hello(&h).unwrap().was_dirty);
        // Check pending only with read-only, unknown flags refused.
        h[8] = 4;
        assert!(decode_hello(&h).is_err());
        h[8] = 5;
        let p = decode_hello(&h).unwrap();
        assert!(p.check_pending && p.read_only);
        h[8] = 8;
        assert!(decode_hello(&h).is_err());
        h[8] = 0;
        h[4] = 0;
        assert_eq!(decode_hello(&h).unwrap().fs_kind, 0);
        h[4] = 9;
        assert!(decode_hello(&h).is_err());
        h[4] = 2;
        h[0] = 2; // version 2
        assert!(decode_hello(&h).is_err());
        let mut s = [0u8; STATFS_SIZE];
        s[0..8].copy_from_slice(&100u64.to_le_bytes());
        s[8..16].copy_from_slice(&500u64.to_le_bytes()); // more free than total: clamped
        s[16..24].copy_from_slice(&50u64.to_le_bytes());
        s[24..28].copy_from_slice(&4096u32.to_le_bytes());
        let st = decode_statfs(&s).unwrap();
        assert_eq!((st.blocks, st.bfree, st.bavail), (100, 100, 50));
        s[24..28].copy_from_slice(&3000u32.to_le_bytes());
        assert!(decode_statfs(&s).is_err());
    }
}
