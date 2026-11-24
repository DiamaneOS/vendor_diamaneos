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

//! What a filesystem VM sends back, as fsvmd reads it, under fuzzing: every decoder of fsvm_proto on arbitrary
//! bytes, and the checking client over a script of arbitrary replies. A compromised VM controls every byte, so each
//! decoder must end in an error or in a value that meets the protocol's limits, which the oracles below state again
//! on their own (sizes, lengths, counts, names, ranges), never by calling the code under test.
//!
//! Used by the libFuzzer targets (fsvm_proto_fuzzer, fsvm_client_fuzzer), by fsvmd's FUSE target (fs_target.rs),
//! by the corpus replay test, and by the seed writer (seeds/).

#![allow(dead_code)]

use fsvm_proto::client::{CallError, Client, Deadlines, Transport};
use fsvm_proto::layout::{self, Class, Layout, RawPart, Table};
use fsvm_proto::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::rc::Rc;
use std::time::{Duration, Instant};

/// A cursor over fuzz input. Reads past the end give zeros, so every input is a complete script.
pub struct Input<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Input { data, at: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }
    pub fn left(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }
    pub fn u8(&mut self) -> u8 {
        let v = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        v
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    pub fn u64(&mut self) -> u64 {
        (self.u32() as u64) | (self.u32() as u64) << 32
    }
    /// Up to n bytes, fewer at the end of the input.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let from = self.at.min(self.data.len());
        let to = from.saturating_add(n).min(self.data.len());
        self.at = to;
        &self.data[from..to]
    }
    /// Exactly n bytes, zero padded.
    pub fn padded(&mut self, n: usize) -> Vec<u8> {
        let mut v = self.bytes(n).to_vec();
        v.resize(n, 0);
        v
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let from = self.at.min(self.data.len());
        self.at = self.data.len();
        &self.data[from..]
    }
    /// A value spread over the interesting sizes: small, near powers of two, the limits and the extremes.
    pub fn size(&mut self) -> u64 {
        match self.u8() % 8 {
            0 => self.u8() as u64,
            1 => self.u16() as u64,
            2 => 1u64 << (self.u8() % 64),
            3 => (1u64 << (self.u8() % 64)).wrapping_sub(1),
            4 => (1u64 << (self.u8() % 64)).wrapping_add(1),
            5 => u64::MAX - self.u8() as u64,
            6 => self.u32() as u64,
            _ => self.u64(),
        }
    }
}

// --- Oracles: the protocol's limits, stated without the code under test --------------------------------------------

/// Characters no name Android shows may hold: they break paths or make a name look like another one.
pub fn bad_name_char(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || (0x7f..=0x9f).contains(&u)
        || c == '/'
        || c == '\\'
        || c == ':'
        || u == 0x61c
        || u == 0x200b
        || u == 0x200e
        || u == 0x200f
        || u == 0x2028
        || u == 0x2029
        || (0x202a..=0x202e).contains(&u)
        || (0x2060..=0x2064).contains(&u)
        || (0x2066..=0x2069).contains(&u)
        || u == 0xfeff
        || (0xfff9..=0xfffb).contains(&u)
}

/// A name Android may see: not empty, at most 1020 bytes and 255 UTF-16 units, not "." or "..", no bad character, no
/// joiner at either end.
pub fn assert_name(name: &str) {
    assert!(!name.is_empty(), "empty name accepted");
    assert!(name.len() <= 1020, "name of {} bytes accepted", name.len());
    assert!(name != "." && name != "..", "dot name accepted");
    let units: usize = name.chars().map(char::len_utf16).sum();
    assert!(units <= 255, "name of {units} UTF-16 units accepted");
    for c in name.chars() {
        assert!(!bad_name_char(c), "name with U+{:04X} accepted", c as u32);
    }
    let first = name.chars().next().unwrap();
    let last = name.chars().last().unwrap();
    for c in [first, last] {
        assert!(c != '\u{200c}' && c != '\u{200d}', "name with a joiner at an end accepted");
    }
}

pub fn assert_attr(a: &Attr) {
    assert_ne!(a.node, 0, "node 0 accepted");
    match a.kind {
        Kind::File => assert!(a.size <= 1 << 44, "file size {} accepted", a.size),
        Kind::Dir => assert_eq!(a.size, 0, "directory with a size"),
    }
    assert!((0..=4_354_819_199).contains(&a.mtime_s), "mtime {} accepted", a.mtime_s);
    assert!(a.mtime_ns < 1_000_000_000, "mtime ns {} accepted", a.mtime_ns);
}

pub fn assert_hello(h: &Hello) {
    assert!(h.fs_kind <= 2, "filesystem kind {} accepted", h.fs_kind);
    assert_ne!(h.root, 0, "root node 0 accepted");
    assert!(!h.check_pending || h.read_only, "check pending on a writable mount");
}

pub fn assert_statfs(s: &Statfs) {
    assert!(s.bsize.is_power_of_two() && (512..=1 << 20).contains(&s.bsize), "block size {}", s.bsize);
    assert!(s.blocks <= (1u64 << 44) / s.bsize as u64 * 4, "{} blocks of {}", s.blocks, s.bsize);
    assert!(s.bavail <= s.bfree && s.bfree <= s.blocks, "free counts above the total");
    assert_eq!(s.namemax, 255);
}

/// A whole listing: within its entry and memory caps, no two names that collide without case, every entry sound.
pub fn assert_listing(l: &Listing) {
    assert!(l.entries.len() <= 65536, "{} entries kept", l.entries.len());
    let bytes: usize = l.entries.iter().map(|(n, _)| n.len() + 64).sum();
    assert_eq!(bytes, l.bytes, "listing bytes miscounted");
    assert!(l.bytes <= 4 << 20, "listing of {} bytes kept", l.bytes);
    let mut keys = HashSet::new();
    for (name, a) in &l.entries {
        assert_name(name);
        assert_attr(a);
        assert!(keys.insert(name.to_lowercase()), "two entries named {name:?} without case");
    }
}

/// A partition layout vold may act on: every range inside the disk and clear of the tables, no overlaps, a small
/// count, unique numbers and GUIDs, the classes and fields each table allows. vold adds ranges to Android's kernel
/// from these numbers.
pub fn assert_layout(l: &Layout, disk_bytes: u64, block_size: u32) {
    let sectors = disk_bytes / 512;
    assert_eq!(disk_bytes % 512, 0);
    assert_eq!(l.disk_sectors, sectors, "disk size not Android's");
    assert!(l.parts.len() <= 16, "{} partitions", l.parts.len());
    let bs = block_size as u64;
    let entry_blocks = (128 * 128 + bs - 1) / bs;
    let (head, tail) = ((2 + entry_blocks) * bs / 512, (1 + entry_blocks) * bs / 512);
    let (mut meta, mut expand) = (0, 0);
    for (i, p) in l.parts.iter().enumerate() {
        assert!(p.length > 0, "empty partition");
        let end = p.start.checked_add(p.length).expect("range overflows");
        assert!(end <= sectors, "partition {} past the disk", p.index);
        match l.table {
            Table::None => {
                assert!(p.index == 0 && p.start == 0 && p.length == sectors, "whole-disk entry not the whole disk");
                assert!(p.fs_kind != 0 || p.damaged, "whole-disk entry without a filesystem");
            }
            Table::Mbr => assert!((1..=36).contains(&p.index) && p.start >= 1, "MBR entry {} at {}", p.index, p.start),
            Table::Gpt => {
                assert!((1..=128).contains(&p.index), "GPT entry {}", p.index);
                assert!(p.start >= head && end + tail <= sectors, "GPT entry over the tables");
                assert!(p.part_guid.is_some_and(|g| g != [0; 16]), "GPT entry without a GUID");
            }
        }
        if l.table != Table::Gpt {
            assert!(p.part_guid.is_none() && p.class == Class::Public, "GPT fields on a non-GPT entry");
        }
        match p.class {
            Class::Public => assert!(p.fs_kind <= 2),
            Class::AndroidMeta | Class::AndroidExpand => assert!(p.fs_kind == 0 && !p.damaged),
        }
        meta += (p.class == Class::AndroidMeta) as u32;
        expand += (p.class == Class::AndroidExpand) as u32;
        assert!(!p.damaged || p.fs_kind == 0, "damaged with a filesystem");
        if p.fs_kind == 0 {
            assert!(p.fs_uuid.is_none() && p.label.is_empty() && p.meta_bytes == 0, "filesystem fields without one");
        }
        assert!(p.meta_bytes <= p.length.saturating_mul(512) / 128, "metadata of {} bytes", p.meta_bytes);
        assert!(p.label.len() <= 47, "label of {} bytes", p.label.len());
        if !p.label.is_empty() {
            assert_name(&p.label);
            assert!(!p.label.ends_with(' '), "label with a trailing space");
        }
        if let Some(u) = &p.fs_uuid {
            assert!(u.len() == 9 && u.as_bytes()[4] == b'-', "uuid {u:?}");
        }
        for q in &l.parts[..i] {
            assert_ne!(p.index, q.index, "two entries numbered {}", p.index);
            assert!(p.part_guid.is_none() || p.part_guid != q.part_guid, "two entries with one GUID");
            assert!(end <= q.start || q.start + q.length <= p.start, "entries {} and {} overlap", q.index, p.index);
        }
    }
    assert!(meta <= 1 && expand <= 1, "more than one adoptable storage pair");
    assert_probe_text(&layout::probe_text(l), l);
}

/// fsvmd's report to vold (system/vold fs/Fsvm.cpp ParseLayout): at most vold's 4096 bytes, printable ASCII lines,
/// one header, one line per partition with ten fields, END.
pub fn assert_probe_text(t: &str, l: &Layout) {
    assert!(t.len() <= 4096, "probe report of {} bytes, vold reads at most 4096", t.len());
    assert!(t.bytes().all(|b| b == b'\n' || (0x20..0x7f).contains(&b)), "probe report not printable ASCII");
    assert!(t.ends_with("END\n"));
    let lines: Vec<&str> = t.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), l.parts.len() + 2);
    assert_eq!(lines[0].split(' ').count(), 4);
    for line in &lines[1..lines.len() - 1] {
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f.len(), 10, "probe line {line:?}");
        assert!(f.iter().all(|x| !x.is_empty()), "empty field in {line:?}");
    }
}

/// fsvmd's report of an accepted layout as vold's fuzzer reads it (system/vold tests/FsvmLayoutFuzzer.cpp): vold
/// must accept every one of them. The FNV-1a hash of the disk size, block size and report marks it as fsvmd's own,
/// so that the fuzzer's mutations of it are not held to that rule.
pub fn probe_report(l: &Layout, disk_bytes: u64, block_size: u32) -> Vec<u8> {
    let text = layout::probe_text(l);
    let hashed = format!("{disk_bytes} {block_size}\n{text}");
    let hash = hashed.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3));
    format!("FSVMD-OUTPUT {disk_bytes} {block_size} {hash:016x}\n{text}").into_bytes()
}

/// With FSVM_PROBE_REPORT_DIR set (a replay of the proto corpus), every accepted layout's report is written there, as
/// vold's fuzzer corpus.
fn keep_probe_report(l: &Layout, disk_bytes: u64, block_size: u32) {
    use std::hash::{Hash, Hasher};
    static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    if let Some(dir) = DIR.get_or_init(|| std::env::var_os("FSVM_PROBE_REPORT_DIR").map(Into::into)) {
        let r = probe_report(l, disk_bytes, block_size);
        let mut h = std::collections::hash_map::DefaultHasher::new();
        r.hash(&mut h);
        std::fs::write(dir.join(format!("fsvmd-{:016x}", h.finish())), r).expect("probe report");
    }
}

// --- Target 1: every decoder on arbitrary bytes --------------------------------------------------------------------

/// Runs one input and answers whether the decoder accepted it (the replay test checks that its seeds are accepted).
pub fn decoders(data: &[u8]) -> bool {
    let mut i = Input::new(data);
    match i.u8() % 9 {
        0 => decode_attr(i.rest())
            .map(|a| {
                assert_attr(&a);
                assert_eq!(decode_attr(&encode_attr(&a)), Ok(a), "attributes do not survive a round trip");
            })
            .is_ok(),
        1 => decode_hello(i.rest()).map(|h| assert_hello(&h)).is_ok(),
        2 => decode_statfs(i.rest()).map(|s| assert_statfs(&s)).is_ok(),
        3 => {
            // One page, then the same bytes cut into pages for a whole listing.
            let pages = i.u8() % 8 + 1;
            let b = i.rest();
            let accepted = match decode_dir_page(b) {
                Ok(p) => {
                    let count = u32::from_le_bytes(b[8..12].try_into().unwrap());
                    assert_eq!(p.entries.len() as u32 + p.dropped, count, "entries lost from a page");
                    for (n, a) in &p.entries {
                        assert_name(n);
                        assert_attr(a);
                    }
                    true
                }
                Err(_) => false,
            };
            let mut l = Listing::default();
            let mut seen = HashSet::new();
            for chunk in b.chunks((b.len() / pages as usize).max(1)) {
                if let Ok(p) = decode_dir_page(chunk) {
                    if !l.add_page(p, &mut seen) {
                        break;
                    }
                }
            }
            assert_listing(&l);
            accepted
        }
        4 | 5 => {
            let disk_bytes = i.size() & !511;
            let block_size = if i.u8() & 1 == 0 { 512 } else { 4096 };
            layout::decode_layout(i.rest(), disk_bytes, block_size)
                .map(|l| {
                    assert_layout(&l, disk_bytes, block_size);
                    keep_probe_report(&l, disk_bytes, block_size);
                })
                .is_ok()
        }
        6 => {
            let mut h = [0u8; RSP_HEADER];
            h.copy_from_slice(&i.padded(RSP_HEADER));
            let (id, max) = (i.u32(), i.u32());
            check_reply_header(&h, id, Op::Read, max)
                .map(|r| {
                    assert_eq!(u32::from_le_bytes(h[0..4].try_into().unwrap()), RSP_MAGIC);
                    assert_eq!(u32::from_le_bytes(h[4..8].try_into().unwrap()), id);
                    assert!((-4095..=0).contains(&r.status), "status {}", r.status);
                    assert!(r.len <= max && (r.status == 0 || r.len == 0));
                })
                .is_ok()
        }
        7 => names::check_name(i.rest()).map(assert_name).is_ok(),
        _ => {
            // A layout written by the guest's own encoder from fuzzed fields.
            let disk = i.size() % (1 << 50) & !511;
            let raw = layout_reply(&mut i, disk / 512);
            layout::decode_layout(&raw, disk, 512)
                .map(|l| {
                    assert_layout(&l, disk, 512);
                    keep_probe_report(&l, disk, 512);
                })
                .is_ok()
        }
    }
}

// --- Replies a VM may send, built from a script ---------------------------------------------------------------------

/// What fsvmd sent, as the fake VM read it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sent {
    pub op: u16,
    pub flags: u16,
    pub id: u32,
    pub node: u64,
    pub node2: u64,
    pub arg: u64,
    pub len: u32,
}

/// Parses one request fsvmd sent and checks that Android's side keeps to the protocol: the header, the lengths, and
/// names that pass the same rules as names the VM returns.
pub fn parse_request(b: &[u8]) -> Sent {
    assert!(b.len() >= REQ_HEADER, "short request");
    let le32 = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let le64 = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    assert_eq!(le32(0), REQ_MAGIC);
    let s = Sent {
        op: u16::from_le_bytes([b[4], b[5]]),
        flags: u16::from_le_bytes([b[6], b[7]]),
        id: le32(8),
        node: le64(16),
        node2: le64(24),
        arg: le64(32),
        len: le32(40),
    };
    let (n1, n2) = (le32(12) as usize, le32(44) as usize);
    let data = if s.op == Op::Write as u16 { s.len as usize } else { 0 };
    assert_eq!(b.len(), REQ_HEADER + n1 + n2 + data, "request length");
    assert!(s.op >= 1 && s.op <= 24, "op {}", s.op);
    assert_ne!(s.id, 0, "request id 0");
    for name in [&b[REQ_HEADER..REQ_HEADER + n1], &b[REQ_HEADER + n1..REQ_HEADER + n1 + n2]] {
        if !name.is_empty() {
            assert_name(std::str::from_utf8(name).expect("request name not UTF-8"));
        }
    }
    if s.op == Op::Write as u16 || s.op == Op::Read as u16 {
        assert!(s.len <= MAX_IO, "I/O of {} bytes asked", s.len);
    }
    s
}

/// The names a fuzzed reply or request picks from: plain, case twins, the forbidden and the borderline.
pub const NAMES: &[&str] = &[
    "a", "A", "b", "DCIM", "dcim", "photo.jpg", "PHOTO.JPG", "Android", "x y", ".hidden", "...", "日本語", "😀.png",
    "\u{0645}\u{06CC}\u{200C}\u{062E}", ".", "..", "a/b", "a\\b", "c:x", "a\0b", "photo\u{202E}gpj.exe", "\u{200C}a",
    "a\u{200D}", "\u{FEFF}x", "x\u{2028}y", "\u{85}", "İ", "ǅ", "ß", "SS",
];

pub fn name_from(i: &mut Input) -> Vec<u8> {
    let c = i.u8();
    if c < 200 {
        NAMES[c as usize % NAMES.len()].as_bytes().to_vec()
    } else if c < 230 {
        let n = i.u8() as usize;
        i.bytes(n).to_vec()
    } else {
        // Long names around the limits.
        let ch = ["a", "語", "😀"][c as usize % 3];
        ch.repeat(250 + (i.u8() % 12) as usize).into_bytes()
    }
}

fn attr_bytes(i: &mut Input) -> [u8; ATTR_SIZE] {
    let mut b = [0u8; ATTR_SIZE];
    let node = match i.u8() % 4 {
        0 => i.u8() as u64,
        1 => NODE_LISTED,
        _ => i.u64(),
    };
    b[0..8].copy_from_slice(&node.to_le_bytes());
    b[8..16].copy_from_slice(&i.size().to_le_bytes());
    b[16..24].copy_from_slice(&(i.size() as i64).wrapping_sub(i.u8() as i64 * 1_000_000_000).to_le_bytes());
    b[24..28].copy_from_slice(&i.u32().to_le_bytes());
    b[28] = match i.u8() % 8 {
        0 => i.u8(),
        1..=4 => 1,
        _ => 2,
    };
    b
}

fn dir_page(i: &mut Input) -> Vec<u8> {
    let mut b = Vec::new();
    let cookie = match i.u8() % 4 {
        0 => 0,
        1 => i.u8() as u64,
        _ => i.u64(),
    };
    b.extend_from_slice(&cookie.to_le_bytes());
    let count = i.u8() % 24;
    let claimed = if i.u8() % 16 == 0 { i.u32() } else { count as u32 };
    b.extend_from_slice(&claimed.to_le_bytes());
    b.extend_from_slice(&if i.u8() % 16 == 0 { i.u32() } else { 0 }.to_le_bytes());
    for _ in 0..count {
        b.extend_from_slice(&attr_bytes(i));
        let name = name_from(i);
        let len = if i.u8() % 32 == 0 { i.u16() } else { name.len() as u16 };
        b.extend_from_slice(&len.to_le_bytes());
        b.extend_from_slice(&name);
    }
    b
}

const GUIDS: [[u8; 16]; 3] = [layout::GPT_BASIC_DATA, layout::GPT_ANDROID_META, layout::GPT_ANDROID_EXPAND];

/// A LAYOUT reply from the guest's encoder, its fields fuzzed around the disk's size.
pub fn layout_reply(i: &mut Input, disk_sectors: u64) -> Vec<u8> {
    let claimed = if i.u8() % 8 == 0 { i.size() } else { disk_sectors };
    let table = i.u8() as u32 % 4;
    let count = i.u8() % 19;
    let mut parts = Vec::new();
    let mut at = [0u64, 1, 34, 48, 2048][i.u8() as usize % 5];
    for _ in 0..count {
        let start = match i.u8() % 4 {
            0 => at,
            1 => i.size(),
            _ => at.saturating_add(i.u16() as u64),
        };
        let length = match i.u8() % 5 {
            0 => disk_sectors.saturating_sub(start),
            1 => disk_sectors.saturating_sub(start).saturating_sub([33u64, 40][i.u8() as usize % 2]),
            2 => i.size(),
            _ => (i.u32() as u64) % (disk_sectors / 2 + 1),
        };
        at = start.saturating_add(length);
        let fs_kind = i.u8() as u32 % 4;
        parts.push(RawPart {
            index: match i.u8() % 4 {
                0 => i.u32(),
                _ => (parts.len() as u32) + (table != 0) as u32,
            },
            start,
            length,
            mbr_type: [0x0c, 0x07, 0x0b, 0x06, 0x0e, 0x83, 0][i.u8() as usize % 7],
            type_guid: match i.u8() % 5 {
                0..=2 => GUIDS[i.u8() as usize % 3],
                3 => [0; 16],
                _ => i.padded(16).try_into().unwrap(),
            },
            part_guid: match i.u8() % 4 {
                0 => [0; 16],
                1 => [7; 16],
                _ => i.padded(16).try_into().unwrap(),
            },
            fs_kind,
            damaged: i.u8() % 4 == 0,
            serial: if i.u8() & 1 == 0 { Some(i.u32()) } else { None },
            meta_bytes: if i.u8() & 1 == 0 { 0 } else { i.size() },
            label: if i.u8() & 1 == 0 { Vec::new() } else { name_from(i) },
        });
    }
    let mut b = layout::encode_layout(claimed, table, &parts);
    // Now and then a stray byte where the guest writes zeros, or a cut.
    match i.u8() % 16 {
        0 if !b.is_empty() => {
            let at = i.u16() as usize % b.len();
            b[at] ^= i.u8() | 1;
        }
        1 => b.truncate(i.u16() as usize),
        _ => {}
    }
    b
}

/// The reply payload fsvmd waits for after `s`, in the shape the protocol gives it.
fn natural_payload(i: &mut Input, s: &Sent, disk_sectors: u64) -> Vec<u8> {
    let op = s.op;
    let attr_ops = [Op::Lookup, Op::Getattr, Op::Create, Op::Mkdir, Op::Truncate, Op::SetMtime];
    if attr_ops.iter().any(|o| *o as u16 == op) {
        return attr_bytes(i).to_vec();
    }
    if op == Op::Hello as u16 || op == Op::Mount as u16 {
        let mut b = Vec::new();
        b.extend_from_slice(&(if i.u8() % 16 == 0 { i.u32() } else { VERSION }).to_le_bytes());
        b.extend_from_slice(&(i.u8() as u32 % 4).to_le_bytes());
        b.extend_from_slice(&(if i.u8() % 16 == 0 { i.u32() } else { i.u8() as u32 % 8 }).to_le_bytes());
        b.extend_from_slice(&(if i.u8() % 16 == 0 { i.u32() } else { 0 }).to_le_bytes());
        b.extend_from_slice(&(if i.u8() % 8 == 0 { 0 } else { i.u8() as u64 + 1 }).to_le_bytes());
        return b;
    }
    if op == Op::Statfs as u16 {
        let mut b = Vec::new();
        for _ in 0..3 {
            b.extend_from_slice(&i.size().to_le_bytes());
        }
        b.extend_from_slice(&(if i.u8() & 1 == 0 { 512u32 << (i.u8() % 13) } else { i.u32() }).to_le_bytes());
        b.extend_from_slice(&i.u32().to_le_bytes());
        return b;
    }
    if op == Op::Readdir as u16 {
        return dir_page(i);
    }
    if op == Op::Layout as u16 {
        return layout_reply(i, disk_sectors);
    }
    if op == Op::Read as u16 {
        let n = match i.u8() % 4 {
            0 => s.len,
            1 => i.u16() as u32 % (s.len + 1),
            _ => i.u32() % (s.len + 2),
        };
        return i.padded(n as usize);
    }
    if op == Op::Write as u16 {
        let mut b = Vec::new();
        let n = if i.u8() % 4 == 0 { i.u32() } else { s.len.saturating_sub(i.u8() as u32 % 3) };
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(&i.u32().to_le_bytes());
        return b;
    }
    if op == Op::Open as u16 || op == Op::Dirty as u16 {
        return (if i.u8() % 8 == 0 { 0 } else { i.u64() }).to_le_bytes().to_vec();
    }
    if op == Op::Check as u16 && s.arg == 0 {
        let mut b = Vec::new();
        b.extend_from_slice(&(i.u8() as u32 % 6).to_le_bytes());
        b.extend_from_slice(&i.u32().to_le_bytes());
        return b;
    }
    Vec::new()
}

/// One reply to `s` from the script. The first byte picks its form: a sound frame (most often), an errno, a length
/// that is not the payload's, a wrong id or magic, raw bytes, or nothing. `close` is set when the VM ends the stream
/// after it (raw bytes or nothing), so that nobody waits for bytes that never come.
pub fn reply(i: &mut Input, s: &Sent, disk_sectors: u64, close: &mut bool) -> Vec<u8> {
    let ctl = i.u8();
    let frame = |id: u32, magic: u32, status: i32, len: u32, payload: &[u8]| {
        let mut b = Vec::with_capacity(RSP_HEADER + payload.len());
        b.extend_from_slice(&magic.to_le_bytes());
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&status.to_le_bytes());
        b.extend_from_slice(&len.to_le_bytes());
        b.extend_from_slice(payload);
        b
    };
    if i.is_empty() && ctl == 0 {
        *close = true;
        return Vec::new();
    }
    match ctl % 16 {
        0..=8 => {
            let p = natural_payload(i, s, disk_sectors);
            frame(s.id, RSP_MAGIC, 0, p.len() as u32, &p)
        }
        9 | 10 => {
            // An errno, sometimes with a payload or an out-of-range status.
            let status = match i.u8() % 8 {
                0 => i.u32() as i32,
                1 => -(i.u16() as i32),
                _ => -((i.u8() % 120) as i32),
            };
            let len = if i.u8() % 8 == 0 { i.u8() as u32 } else { 0 };
            let p = i.padded(len as usize);
            frame(s.id, RSP_MAGIC, status, len, &p)
        }
        11 => {
            // A length that is not the payload's natural one: the payload is sent as the header says, so the stream
            // stays in step and only the length check decides.
            let len = match i.u8() % 4 {
                0 => i.u32(),
                1 => i.u16() as u32,
                2 => MAX_IO + i.u8() as u32,
                _ => i.u8() as u32,
            };
            if len > 1 << 20 {
                *close = true;
                frame(s.id, RSP_MAGIC, 0, len, &[])
            } else {
                let p = i.padded(len as usize);
                frame(s.id, RSP_MAGIC, 0, len, &p)
            }
        }
        12 => {
            let p = natural_payload(i, s, disk_sectors);
            let id = if i.u8() & 1 == 0 { s.id.wrapping_add(1) } else { i.u32() };
            frame(id, RSP_MAGIC, 0, p.len() as u32, &p)
        }
        13 => {
            let p = natural_payload(i, s, disk_sectors);
            frame(s.id, REQ_MAGIC, 0, p.len() as u32, &p)
        }
        14 => {
            *close = true;
            let n = i.u8() as usize;
            i.bytes(n).to_vec()
        }
        _ => {
            *close = true;
            Vec::new()
        }
    }
}

// --- Target 2: the checking client against a scripted VM -----------------------------------------------------------

/// A VM that answers every request from the script, in memory. Once it closed, every read fails as on a closed
/// stream, at once.
pub struct ScriptedVm<'a> {
    pub script: Input<'a>,
    pub disk_sectors: u64,
    pending: Vec<u8>,
    at: usize,
    closed: bool,
    /// Every request fsvmd sent, shared with the harness (the client owns the transport).
    pub sent: Rc<RefCell<Vec<Sent>>>,
}

impl<'a> ScriptedVm<'a> {
    pub fn new(script: &'a [u8], disk_sectors: u64, sent: Rc<RefCell<Vec<Sent>>>) -> Self {
        ScriptedVm { script: Input::new(script), disk_sectors, pending: Vec::new(), at: 0, closed: false, sent }
    }
}

impl Transport for ScriptedVm<'_> {
    fn send_by(&mut self, buf: &[u8], _deadline: Instant) -> io::Result<()> {
        let s = parse_request(buf);
        self.sent.borrow_mut().push(s);
        if self.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut close = false;
        let r = reply(&mut self.script, &s, self.disk_sectors, &mut close);
        self.pending.drain(..self.at);
        self.at = 0;
        self.pending.extend_from_slice(&r);
        self.closed = close;
        Ok(())
    }

    fn recv_by(&mut self, buf: &mut [u8], _deadline: Instant) -> io::Result<()> {
        if self.pending.len() - self.at < buf.len() {
            self.closed = true;
            self.at = self.pending.len();
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.copy_from_slice(&self.pending[self.at..self.at + buf.len()]);
        self.at += buf.len();
        Ok(())
    }
}

pub fn quick_deadlines() -> Deadlines {
    let s = Duration::from_secs(5);
    Deadlines { hello: s, meta: s, mutate: s, io: s, mount: s, listing: Duration::from_secs(60), operation: Duration::from_secs(60) }
}

/// Errnos fsvmd hands to Android: the pass-through set, the client's own for names and sizes, and EMFILE for an open.
pub fn assert_errno(e: &CallError, open: bool) {
    if let CallError::Errno(n) = e {
        let ok = [1, 2, 5, 9, 13, 16, 17, 18, 20, 21, 22, 27, 28, 30, 36, 39, 116];
        assert!(ok.contains(n) || (open && *n == 24), "errno {n} reached Android");
    }
}

/// Runs one input and answers (calls answered, whether the session broke): the replay test checks its seeds.
pub fn client_session(data: &[u8]) -> (usize, bool) {
    let mut i = Input::new(data);
    let ops_len = i.u16() as usize % 512;
    let ops = i.bytes(ops_len);
    let disk_sectors = match i.u8() % 4 {
        0 => 1 << 27,
        1 => i.u32() as u64,
        2 => i.size() % (1 << 50),
        _ => 2048 + i.u16() as u64,
    };
    let block_size = if i.u8() & 1 == 0 { 512 } else { 4096 };
    let script = i.rest();
    let sent = Rc::new(RefCell::new(Vec::new()));
    let count = || sent.borrow().len();
    let mut c = Client::new(ScriptedVm::new(script, disk_sectors, sent.clone()), quick_deadlines());
    let mut o = Input::new(ops);
    let mut broken_after: Option<usize> = None;
    let mut answered = 0;
    while !o.is_empty() {
        let op = o.u8() % 30;
        let node = match o.u8() % 4 {
            0 => 1,
            1 => o.u8() as u64,
            _ => o.u64(),
        };
        let name = name_from(&mut o);
        let r: Result<(), CallError> = match op {
            0 => c.hello().map(|h| assert_hello(&h)),
            1 => c.layout(disk_sectors * 512, block_size).map(|l| assert_layout(&l, disk_sectors * 512, block_size)),
            2 => {
                let (index, start, length, ro, fs) = (o.u8() as u32, o.u64(), o.u64(), o.u8() & 1 == 0, o.u8() as u32 % 3);
                c.mount(index, start, length, ro, fs, Duration::from_millis(o.u16() as u64)).map(|h| {
                    assert_hello(&h);
                    assert!(h.fs_kind != 0 && (fs == 0 || h.fs_kind == fs), "mount of filesystem {}", h.fs_kind);
                    assert!(!ro || h.read_only, "writable where read-only was asked");
                    assert!(!ro || !h.check_pending, "a check pending where read-only was asked");
                })
            }
            3 => {
                let fs = o.u8() as u32 % 3;
                c.mount_check_later(o.u8() as u32, o.u64(), o.u64(), fs).map(|h| {
                    assert_hello(&h);
                    assert!(h.fs_kind != 0 && (fs == 0 || h.fs_kind == fs), "mount of filesystem {}", h.fs_kind);
                })
            }
            4 => c.format(o.u8() as u32 % 3, Duration::from_millis(o.u16() as u64)),
            5 => c.check_poll().map(|_| ()),
            6 => c.check_switch(Duration::from_millis(o.u16() as u64), Duration::from_millis(o.u16() as u64)),
            7 => c.lookup(node, &name).map(|a| assert_node_attr(&a)),
            8 => c.getattr(node).map(|a| assert_node_attr(&a)),
            9 => {
                let first = count();
                let r = c.list(node).map(|l| assert_listing(&l));
                // Pages within MAX_DIR_PAGES, and cookies that only move forward.
                let pages: Vec<Sent> = sent.borrow()[first..].iter().copied().filter(|s| s.op == Op::Readdir as u16).collect();
                assert!(pages.len() <= MAX_DIR_PAGES, "{} pages asked for one listing", pages.len());
                for w in pages.windows(2) {
                    assert!(w[1].arg > w[0].arg, "cookie went back from {} to {}", w[0].arg, w[1].arg);
                }
                r
            }
            10 | 11 => {
                let len = o.u32();
                let r = if op == 10 { c.read(node, o.u64(), len) } else { c.read_handle(node, o.u64(), len) };
                r.map(|d| assert!(d.len() <= len.min(MAX_IO) as usize, "{} bytes read of {len}", d.len()))
            }
            12 | 13 => {
                let data = vec![0x5a; o.u32() as usize % (MAX_IO as usize + 16)];
                let r = if op == 12 { c.write(node, o.u64(), &data) } else { c.write_handle(node, o.u64(), &data) };
                r.map(|n| assert!(n as usize <= data.len().min(MAX_IO as usize), "{n} written of {}", data.len()))
            }
            14 => c.open_handle(node, o.u8() & 1 == 0).map(|h| assert_ne!(h, 0)),
            15 => c.close_handle(node),
            16 => c.getattr_handle(node).map(|a| assert_node_attr(&a)),
            17 => c.fsync_handle(node, o.u8() & 1 == 0),
            18 => c.create(node, &name, o.u8() & 1 == 0).map(|a| {
                assert_node_attr(&a);
                assert_eq!(a.kind, Kind::File, "create answered a directory");
            }),
            19 => c.mkdir(node, &name).map(|a| {
                assert_node_attr(&a);
                assert_eq!(a.kind, Kind::Dir, "mkdir answered a file");
            }),
            20 => c.unlink(node, &name),
            21 => c.rmdir(node, &name),
            22 => {
                let to = name_from(&mut o);
                c.rename(node, &name, o.u64(), &to)
            }
            23 => c.truncate(node, o.size()).map(|a| assert_node_attr(&a)),
            24 => c.set_mtime(node, o.u64() as i64, o.u32()).map(|a| assert_node_attr(&a)),
            25 => c.statfs().map(|s| assert_statfs(&s)),
            26 => c.fsync(node, o.u8() & 1 == 0),
            27 => c.unmount(Duration::from_millis(o.u16() as u64)),
            28 => c.dirty().map(|_| ()),
            _ => c.forget(node),
        };
        match &r {
            Err(CallError::Broken(_)) => {
                assert!(c.is_broken(), "a broken call left the session open");
                if let Some(n) = broken_after {
                    // Nothing is sent once the session broke.
                    assert_eq!(count(), n, "requests sent on a broken session");
                }
                broken_after = Some(count());
            }
            Err(e) => {
                // The client's own refusals (a name or size it never sends) need no VM, broken or not.
                if let Some(n) = broken_after {
                    assert_eq!(count(), n, "requests sent on a broken session");
                }
                assert_errno(e, op == 14);
            }
            Ok(()) => {
                assert!(broken_after.is_none(), "an answer on a broken session");
                answered += 1;
            }
        }
    }
    (answered, broken_after.is_some())
}

/// Attributes of a node a call answered: sound, and never the listed-name id, which is for READDIR only.
fn assert_node_attr(a: &Attr) {
    assert_attr(a);
    assert_ne!(a.node, NODE_LISTED, "the listed-name id outside READDIR");
}
