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

//! The partition layout the VM reads from a disk (phase 2). Android's kernel reads no partition table of an SD card
//! or a USB disk. The VM reads it and reports the partitions Android may use. vold adds the adoptable storage
//! partition to Android's kernel from these numbers, so every one of them is checked here against the disk size
//! Android knows, before vold sees it: ranges inside the disk and clear of the tables, no overlaps, a small count,
//! only the partition types Android uses, and the raw type codes classified here, never by the VM.
//!
//! LAYOUT reply: a 32-byte header (disk size in 512-byte sectors u64, table u32, count u32, 16 reserved bytes), then
//! `count` entries of 128 bytes:
//!
//! | offset | field |
//! | --- | --- |
//! | 0 | index u32: 0 for a filesystem on the whole disk, else the partition number |
//! | 4 | flags u32: bit 0 the filesystem serial below is valid |
//! | 8 | start u64, in 512-byte sectors |
//! | 16 | length u64, in 512-byte sectors |
//! | 24 | MBR type byte, then 3 zero bytes |
//! | 28 | GPT partition type GUID, 16 bytes as on disk |
//! | 44 | GPT unique partition GUID, 16 bytes as on disk |
//! | 60 | filesystem found u32: 0 none or unknown, 1 FAT, 2 exFAT |
//! | 64 | filesystem serial u32 |
//! | 68 | metadata bytes u64: one FAT, or the exFAT allocation bitmap |
//! | 76 | label length u8, then 47 bytes of UTF-8 label |
//! | 124 | 4 zero bytes |

use crate::names;
use crate::{le_u32, le_u64};

pub const LAYOUT_HEADER: usize = 32;
pub const LAYOUT_ENTRY: usize = 128;
/// Most partitions reported for one disk. vold uses a handful. A table claiming hundreds is refused.
pub const MAX_LAYOUT_ENTRIES: usize = 16;
pub const MAX_LAYOUT_PAYLOAD: usize = LAYOUT_HEADER + MAX_LAYOUT_ENTRIES * LAYOUT_ENTRY;
/// Longest label in bytes. FAT labels have 11 bytes, exFAT labels 11 UTF-16 units.
pub const MAX_LABEL_BYTES: usize = 47;
/// Highest partition number: 4 primary MBR partitions and up to 32 logical ones (numbered from 5, as Linux does,
/// the guest follows at most 32 links of the chain), 128 GPT entries.
pub const MAX_MBR_INDEX: u32 = 36;
pub const MAX_GPT_INDEX: u32 = 128;
/// Bytes of the usual 128 GPT entries.
const GPT_ENTRY_BYTES: u64 = 128 * 128;

/// 512-byte sectors a GPT occupies at the start of a disk with `block_size`-byte logical blocks: the protective MBR
/// and the header (one block each), then the entries. 34 for 512-byte blocks, 48 for 4096-byte blocks.
pub fn gpt_head_sectors(block_size: u32) -> u64 {
    let bs = block_size as u64;
    (2 + GPT_ENTRY_BYTES.div_ceil(bs)) * bs / 512
}

/// The same at the end: the backup entries and the backup header. 33 for 512-byte blocks, 40 for 4096-byte blocks.
pub fn gpt_tail_sectors(block_size: u32) -> u64 {
    let bs = block_size as u64;
    (1 + GPT_ENTRY_BYTES.div_ceil(bs)) * bs / 512
}

pub const GPT_HEAD_SECTORS: u64 = 34;
pub const GPT_TAIL_SECTORS: u64 = 33;

/// The partition types Android uses, as their GUID bytes appear on disk (the first three fields little endian).
pub const GPT_BASIC_DATA: [u8; 16] = guid(0xEBD0A0A2, 0xB9E5, 0x4433, [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
pub const GPT_ANDROID_META: [u8; 16] = guid(0x19A710A2, 0xB3CA, 0x11E4, [0xB0, 0x26, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF]);
pub const GPT_ANDROID_EXPAND: [u8; 16] = guid(0x193D1EA4, 0xB3CA, 0x11E4, [0xB0, 0x75, 0x10, 0x60, 0x4B, 0x88, 0x9D, 0xCF]);
/// MBR types vold serves as public volumes: FAT16, exFAT or NTFS, FAT32, FAT32 LBA, FAT16 LBA.
pub const MBR_PUBLIC_TYPES: [u8; 5] = [0x06, 0x07, 0x0b, 0x0c, 0x0e];

pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]]
}

/// The GUID in its usual text form, upper case, as sgdisk printed it for vold.
pub fn guid_text(g: &[u8; 16]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// No partition table: a filesystem on the whole disk (a "super-floppy" card, an OBB image).
    None,
    Mbr,
    Gpt,
}

/// What Android does with a partition. Decided here from the raw type, never by the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A public volume served by the filesystem VM.
    Public,
    /// Adoptable storage metadata (unused by vold, reported so that overlaps are checked).
    AndroidMeta,
    /// Adoptable storage: encrypted with a key on the phone, added to Android's kernel by vold.
    AndroidExpand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub index: u32,
    pub class: Class,
    pub start: u64,
    pub length: u64,
    /// The filesystem the VM found: 0 none or unknown, FS_VFAT, FS_EXFAT.
    pub fs_kind: u32,
    /// The volume UUID as blkid printed it ("6FFF-FAB8"), from the serial.
    pub fs_uuid: Option<String>,
    pub label: String,
    /// The unique partition GUID (adoptable storage finds its key by it).
    pub part_guid: Option<[u8; 16]>,
    pub meta_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub table: Table,
    pub disk_sectors: u64,
    pub parts: Vec<Part>,
    /// Labels that failed the name rules and were dropped (the partition stays).
    pub dropped_labels: u32,
}

/// Why a layout was refused. A refused layout means the disk is not opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    Size,
    Count(u32),
    DiskSize { vm: u64, android: u64 },
    TableKind(u32),
    Reserved,
    Index(u32),
    DuplicateIndex(u32),
    Range { index: u32, start: u64, length: u64 },
    Overlap(u32, u32),
    Type(u32),
    TypeFields(u32),
    FsKind(u32),
    Guid(u32),
    DuplicateGuid(u32),
    TooManyAdoptable,
    Meta(u32),
    WholeDisk,
    BlockSize(u32),
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Checks a label: trailing spaces trimmed, the name rules, at most MAX_LABEL_BYTES. A bad label is dropped, not
/// fatal: it only names the volume.
fn check_label(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.trim_end_matches(' ');
    if s.is_empty() {
        return Some(String::new());
    }
    names::check_name(s.as_bytes()).ok().map(str::to_string)
}

/// Decodes and checks a LAYOUT reply. `disk_bytes` is the disk size and `block_size` its logical block size (512 or
/// 4096) as Android's kernel reports them.
pub fn decode_layout(b: &[u8], disk_bytes: u64, block_size: u32) -> Result<Layout, LayoutError> {
    if block_size != 512 && block_size != 4096 {
        return Err(LayoutError::BlockSize(block_size));
    }
    if b.len() < LAYOUT_HEADER || b.len() > MAX_LAYOUT_PAYLOAD {
        return Err(LayoutError::Size);
    }
    let disk_sectors = le_u64(b, 0);
    let table = le_u32(b, 8);
    let count = le_u32(b, 12);
    if count as usize > MAX_LAYOUT_ENTRIES {
        return Err(LayoutError::Count(count));
    }
    if b.len() != LAYOUT_HEADER + count as usize * LAYOUT_ENTRY {
        return Err(LayoutError::Size);
    }
    if !is_zero(&b[16..32]) {
        return Err(LayoutError::Reserved);
    }
    // The VM sees the same disk. Any other size means it is not telling the truth about this one.
    if disk_bytes % 512 != 0 || disk_sectors.checked_mul(512) != Some(disk_bytes) {
        return Err(LayoutError::DiskSize { vm: disk_sectors, android: disk_bytes });
    }
    let table = match table {
        0 => Table::None,
        1 => Table::Mbr,
        2 => Table::Gpt,
        t => return Err(LayoutError::TableKind(t)),
    };
    // The usable range for partitions: clear of the tables at either end.
    let (lo, hi) = match table {
        Table::None => (0, disk_sectors),
        Table::Mbr => (1, disk_sectors),
        Table::Gpt => (gpt_head_sectors(block_size), disk_sectors.saturating_sub(gpt_tail_sectors(block_size))),
    };

    let mut parts = Vec::with_capacity(count as usize);
    let mut dropped_labels = 0;
    for i in 0..count as usize {
        let e = &b[LAYOUT_HEADER + i * LAYOUT_ENTRY..LAYOUT_HEADER + (i + 1) * LAYOUT_ENTRY];
        let index = le_u32(e, 0);
        let flags = le_u32(e, 4);
        let start = le_u64(e, 8);
        let length = le_u64(e, 16);
        let mbr_type = e[24];
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&e[28..44]);
        let mut part_guid = [0u8; 16];
        part_guid.copy_from_slice(&e[44..60]);
        let fs_kind = le_u32(e, 60);
        let serial = le_u32(e, 64);
        let meta_bytes = le_u64(e, 68);
        let label_len = e[76] as usize;
        if flags & !1 != 0 || !is_zero(&e[25..28]) || !is_zero(&e[124..128]) || label_len > MAX_LABEL_BYTES {
            return Err(LayoutError::Reserved);
        }
        if !is_zero(&e[77 + label_len..124]) {
            return Err(LayoutError::Reserved);
        }

        let index_ok = match table {
            Table::None => index == 0,
            Table::Mbr => (1..=MAX_MBR_INDEX).contains(&index),
            Table::Gpt => (1..=MAX_GPT_INDEX).contains(&index),
        };
        if !index_ok {
            return Err(LayoutError::Index(index));
        }
        if parts.iter().any(|p: &Part| p.index == index) {
            return Err(LayoutError::DuplicateIndex(index));
        }
        let end = start.checked_add(length);
        if length == 0 || start < lo || end.is_none_or(|end| end > hi) {
            return Err(LayoutError::Range { index, start, length });
        }
        if table == Table::None && (start != 0 || length != disk_sectors) {
            return Err(LayoutError::WholeDisk);
        }

        let class = match table {
            Table::None | Table::Mbr => {
                if !is_zero(&type_guid) || !is_zero(&part_guid) {
                    return Err(LayoutError::TypeFields(index));
                }
                if table == Table::None && mbr_type != 0 {
                    return Err(LayoutError::TypeFields(index));
                }
                if table == Table::Mbr && !MBR_PUBLIC_TYPES.contains(&mbr_type) {
                    return Err(LayoutError::Type(index));
                }
                Class::Public
            }
            Table::Gpt => {
                if mbr_type != 0 {
                    return Err(LayoutError::TypeFields(index));
                }
                if type_guid == GPT_BASIC_DATA {
                    Class::Public
                } else if type_guid == GPT_ANDROID_META {
                    Class::AndroidMeta
                } else if type_guid == GPT_ANDROID_EXPAND {
                    Class::AndroidExpand
                } else {
                    return Err(LayoutError::Type(index));
                }
            }
        };
        let fs_kind = match (class, fs_kind) {
            (Class::Public, 0 | crate::FS_VFAT | crate::FS_EXFAT) => fs_kind,
            (Class::AndroidMeta | Class::AndroidExpand, 0) => 0,
            _ => return Err(LayoutError::FsKind(index)),
        };
        // A filesystem on the whole disk is only reported when the VM found one.
        if table == Table::None && fs_kind == 0 {
            return Err(LayoutError::FsKind(index));
        }
        if fs_kind == 0 && (flags & 1 != 0 || serial != 0 || meta_bytes != 0 || label_len != 0) {
            return Err(LayoutError::TypeFields(index));
        }
        // Metadata the VM's kernel keeps for a filesystem is a small part of it: one FAT entry or bitmap bit per
        // cluster of at least 512 bytes.
        if meta_bytes > length.saturating_mul(512) / 128 {
            return Err(LayoutError::Meta(index));
        }
        let part_guid = match table {
            Table::Gpt => {
                if is_zero(&part_guid) {
                    return Err(LayoutError::Guid(index));
                }
                if parts.iter().any(|p: &Part| p.part_guid == Some(part_guid)) {
                    return Err(LayoutError::DuplicateGuid(index));
                }
                Some(part_guid)
            }
            _ => None,
        };
        let label = match check_label(&e[77..77 + label_len]) {
            Some(l) => l,
            None => {
                dropped_labels += 1;
                String::new()
            }
        };
        let fs_uuid = (flags & 1 != 0).then(|| format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff));
        parts.push(Part { index, class, start, length, fs_kind, fs_uuid, label, part_guid, meta_bytes });
    }

    // Adoptable storage as vold makes it: at most one metadata and one storage partition.
    if parts.iter().filter(|p| p.class == Class::AndroidExpand).count() > 1
        || parts.iter().filter(|p| p.class == Class::AndroidMeta).count() > 1
    {
        return Err(LayoutError::TooManyAdoptable);
    }
    let mut sorted: Vec<&Part> = parts.iter().collect();
    sorted.sort_by_key(|p| p.start);
    for w in sorted.windows(2) {
        if w[0].start + w[0].length > w[1].start {
            return Err(LayoutError::Overlap(w[0].index, w[1].index));
        }
    }
    Ok(Layout { table, disk_sectors, parts, dropped_labels })
}

/// fsvmd's probe output for vold (system/vold fs/Fsvm.cpp ParseLayout), from a checked layout. ASCII, one record per
/// line, fields separated by one space:
///
/// ```text
/// LAYOUT 1 <none|mbr|gpt> <count>
/// PART <index> <public|meta|expand> <start> <length> <vfat|exfat|-> <uuid|-> <part-guid|-> <meta-bytes> <label-hex|->
/// END
/// ```
pub fn probe_text(l: &Layout) -> String {
    use std::fmt::Write as _;
    let table = match l.table {
        Table::None => "none",
        Table::Mbr => "mbr",
        Table::Gpt => "gpt",
    };
    let mut out = format!("LAYOUT 1 {table} {}\n", l.parts.len());
    for p in &l.parts {
        let class = match p.class {
            Class::Public => "public",
            Class::AndroidMeta => "meta",
            Class::AndroidExpand => "expand",
        };
        let fs = match p.fs_kind {
            crate::FS_VFAT => "vfat",
            crate::FS_EXFAT => "exfat",
            _ => "-",
        };
        let guid = p.part_guid.as_ref().map(guid_text).unwrap_or_else(|| "-".into());
        let label = if p.label.is_empty() {
            "-".to_string()
        } else {
            p.label.bytes().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
        };
        let uuid = p.fs_uuid.as_deref().unwrap_or("-");
        let _ = writeln!(out, "PART {} {class} {} {} {fs} {uuid} {guid} {} {label}", p.index, p.start, p.length, p.meta_bytes);
    }
    out.push_str("END\n");
    out
}

/// One entry for `encode_layout`, as the guest writes it (used by tests and the guest's test double).
#[derive(Debug, Clone, Default)]
pub struct RawPart {
    pub index: u32,
    pub start: u64,
    pub length: u64,
    pub mbr_type: u8,
    pub type_guid: [u8; 16],
    pub part_guid: [u8; 16],
    pub fs_kind: u32,
    pub serial: Option<u32>,
    pub meta_bytes: u64,
    pub label: Vec<u8>,
}

pub fn encode_layout(disk_sectors: u64, table: u32, parts: &[RawPart]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&disk_sectors.to_le_bytes());
    b.extend_from_slice(&table.to_le_bytes());
    b.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    b.extend_from_slice(&[0u8; 16]);
    for p in parts {
        let mut e = [0u8; LAYOUT_ENTRY];
        e[0..4].copy_from_slice(&p.index.to_le_bytes());
        e[4..8].copy_from_slice(&(p.serial.is_some() as u32).to_le_bytes());
        e[8..16].copy_from_slice(&p.start.to_le_bytes());
        e[16..24].copy_from_slice(&p.length.to_le_bytes());
        e[24] = p.mbr_type;
        e[28..44].copy_from_slice(&p.type_guid);
        e[44..60].copy_from_slice(&p.part_guid);
        e[60..64].copy_from_slice(&p.fs_kind.to_le_bytes());
        e[64..68].copy_from_slice(&p.serial.unwrap_or(0).to_le_bytes());
        e[68..76].copy_from_slice(&p.meta_bytes.to_le_bytes());
        let l = p.label.len().min(MAX_LABEL_BYTES);
        e[76] = l as u8;
        e[77..77 + l].copy_from_slice(&p.label[..l]);
        b.extend_from_slice(&e);
    }
    b
}

/// VM memory for serving a partition, from the metadata its filesystem needs (phone measurements 2026-11-17: a 64 GB
/// FAT32 card with 4 KiB clusters, 64 MiB per FAT, timed out at 48 MiB and worked at 96 MiB).
///
/// - exFAT keeps its allocation bitmap in memory for as long as it is mounted, so the bitmap is added in full.
/// - FAT reads its table through the page cache, and the first free-space count reads all of it once. The check of a
///   dirty FAT volume (fsck_msdos, in the VM) holds the table and two cluster bitmaps. So the FAT counts with a
///   quarter more, up to 160 MiB.
///
/// Bounded to 96..=256 MiB whatever the card claims. A filesystem that needs more fails to mount in the VM, and the
/// card is reported as not opened.
pub const MIN_SERVE_MIB: u32 = 96;
pub const MAX_SERVE_MIB: u32 = 256;
pub const PROBE_MIB: u32 = 64;

pub fn serve_memory_mib(fs_kind: u32, meta_bytes: u64) -> u32 {
    let meta_mib = meta_bytes.div_ceil(1 << 20).min(1 << 20) as u32;
    let want = match fs_kind {
        crate::FS_EXFAT => 80 + meta_mib,
        _ => 64 + (meta_mib.saturating_mul(5) / 4).min(160),
    };
    want.clamp(MIN_SERVE_MIB, MAX_SERVE_MIB)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK: u64 = 64 << 21; // 64 GiB in sectors

    fn fat_part(index: u32, start: u64, length: u64) -> RawPart {
        RawPart {
            index,
            start,
            length,
            mbr_type: 0x0c,
            fs_kind: crate::FS_VFAT,
            serial: Some(0x6FFF_FAB8),
            meta_bytes: length * 4,
            label: b"CARD       ".to_vec(),
            ..Default::default()
        }
    }

    fn gpt(index: u32, start: u64, length: u64, ty: [u8; 16], unique: u8) -> RawPart {
        RawPart { index, start, length, type_guid: ty, part_guid: [unique; 16], ..Default::default() }
    }

    #[test]
    fn honest_mbr_and_gpt() {
        let b = encode_layout(DISK, 1, &[fat_part(1, 2048, DISK - 2048)]);
        let l = decode_layout(&b, DISK * 512, 512).unwrap();
        assert_eq!(l.table, Table::Mbr);
        assert_eq!(l.parts[0].fs_uuid.as_deref(), Some("6FFF-FAB8"));
        assert_eq!(l.parts[0].label, "CARD");
        assert_eq!(l.parts[0].class, Class::Public);

        // Adoptable storage as vold partitions it: metadata, then the encrypted rest.
        let meta = gpt(1, 2048, 32768, GPT_ANDROID_META, 1);
        let expand = gpt(2, 34816, DISK - 34816 - 33, GPT_ANDROID_EXPAND, 2);
        let l = decode_layout(&encode_layout(DISK, 2, &[meta, expand]), DISK * 512, 512).unwrap();
        assert_eq!(l.parts[1].class, Class::AndroidExpand);
        assert_eq!(guid_text(&l.parts[1].part_guid.unwrap()), "02020202-0202-0202-0202-020202020202");
    }

    #[test]
    fn guid_text_matches_sgdisk() {
        assert_eq!(guid_text(&GPT_ANDROID_EXPAND), "193D1EA4-B3CA-11E4-B075-10604B889DCF");
        assert_eq!(guid_text(&GPT_BASIC_DATA), "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }

    #[test]
    fn whole_disk_filesystem() {
        let p = RawPart { index: 0, start: 0, length: DISK, fs_kind: crate::FS_EXFAT, serial: Some(1), ..Default::default() };
        let l = decode_layout(&encode_layout(DISK, 0, &[p.clone()]), DISK * 512, 512).unwrap();
        assert_eq!(l.table, Table::None);
        assert_eq!(l.parts[0].fs_uuid.as_deref(), Some("0000-0001"));
        // Not the whole disk, or no filesystem: refused.
        let mut q = p.clone();
        q.length -= 1;
        assert!(decode_layout(&encode_layout(DISK, 0, &[q]), DISK * 512, 512).is_err());
        let mut q = p;
        q.fs_kind = 0;
        q.serial = None;
        assert!(decode_layout(&encode_layout(DISK, 0, &[q]), DISK * 512, 512).is_err());
        // An empty layout is fine: nothing Android can use.
        assert!(decode_layout(&encode_layout(DISK, 0, &[]), DISK * 512, 512).unwrap().parts.is_empty());
    }

    #[test]
    fn hostile_ranges() {
        let bad = [
            fat_part(1, 0, 100),                 // over the MBR itself
            fat_part(1, 2048, DISK),             // past the end
            fat_part(1, u64::MAX - 10, 100),     // wraps around
            fat_part(1, 2048, 0),                // empty
            fat_part(1, DISK, 1),                // starts at the end
        ];
        for p in bad {
            assert!(matches!(decode_layout(&encode_layout(DISK, 1, &[p.clone()]), DISK * 512, 512), Err(LayoutError::Range { .. })), "{p:?}");
        }
        // MBR logical partitions are numbered from 5, up to 36.
        assert!(decode_layout(&encode_layout(DISK, 1, &[fat_part(5, 2048, 4096)]), DISK * 512, 512).is_ok());
        assert!(matches!(decode_layout(&encode_layout(DISK, 1, &[fat_part(37, 2048, 4096)]), DISK * 512, 512), Err(LayoutError::Index(37))));
        // On a disk with 4096-byte blocks the GPT takes 48 sectors at the start and 40 at the end.
        assert_eq!((gpt_head_sectors(512), gpt_tail_sectors(512)), (34, 33));
        assert_eq!((gpt_head_sectors(4096), gpt_tail_sectors(4096)), (48, 40));
        let head = gpt(1, 34, 100, GPT_BASIC_DATA, 1);
        assert!(decode_layout(&encode_layout(DISK, 2, &[head.clone()]), DISK * 512, 512).is_ok());
        assert!(matches!(decode_layout(&encode_layout(DISK, 2, &[head]), DISK * 512, 4096), Err(LayoutError::Range { .. })));
        let tail = gpt(1, DISK - 133, 100, GPT_BASIC_DATA, 1);
        assert!(decode_layout(&encode_layout(DISK, 2, &[tail.clone()]), DISK * 512, 512).is_ok());
        assert!(matches!(decode_layout(&encode_layout(DISK, 2, &[tail]), DISK * 512, 4096), Err(LayoutError::Range { .. })));
        assert!(decode_layout(&encode_layout(DISK, 2, &[gpt(1, 48, 100, GPT_BASIC_DATA, 1)]), DISK * 512, 4096).is_ok());
        assert!(matches!(decode_layout(&encode_layout(DISK, 0, &[]), DISK * 512, 1024), Err(LayoutError::BlockSize(1024))));
        // GPT partitions must stay clear of both tables.
        let p = gpt(1, 2, 100, GPT_BASIC_DATA, 1);
        assert!(matches!(decode_layout(&encode_layout(DISK, 2, &[p]), DISK * 512, 512), Err(LayoutError::Range { .. })));
        let p = gpt(1, 2048, DISK - 2048, GPT_BASIC_DATA, 1);
        assert!(matches!(decode_layout(&encode_layout(DISK, 2, &[p]), DISK * 512, 512), Err(LayoutError::Range { .. })));
    }

    #[test]
    fn hostile_overlaps_and_duplicates() {
        let a = fat_part(1, 2048, 100_000);
        let b = fat_part(2, 50_000, 100_000);
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[a.clone(), b]), DISK * 512, 512), Err(LayoutError::Overlap(1, 2)));
        // The same range twice, under two numbers.
        let c = fat_part(3, 2048, 100_000);
        assert!(matches!(decode_layout(&encode_layout(DISK, 1, &[a.clone(), c]), DISK * 512, 512), Err(LayoutError::Overlap(..))));
        // Adjacent is fine.
        let d = fat_part(2, 102_048, 100);
        assert!(decode_layout(&encode_layout(DISK, 1, &[a.clone(), d]), DISK * 512, 512).is_ok());
        // The same number twice.
        let e = fat_part(1, 300_000, 100);
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[a, e]), DISK * 512, 512), Err(LayoutError::DuplicateIndex(1)));
        // Two adoptable partitions, or the same unique GUID twice.
        let x = gpt(1, 2048, 1000, GPT_ANDROID_EXPAND, 1);
        let y = gpt(2, 4096, 1000, GPT_ANDROID_EXPAND, 2);
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[x.clone(), y]), DISK * 512, 512), Err(LayoutError::TooManyAdoptable));
        let z = gpt(2, 4096, 1000, GPT_BASIC_DATA, 1);
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[x, z]), DISK * 512, 512), Err(LayoutError::DuplicateGuid(2)));
    }

    #[test]
    fn hostile_counts_and_sizes() {
        // Hundreds of entries: refused from the header, without reading them.
        let mut b = encode_layout(DISK, 2, &[]);
        b[12..16].copy_from_slice(&300u32.to_le_bytes());
        assert_eq!(decode_layout(&b, DISK * 512, 512), Err(LayoutError::Count(300)));
        // 17 well-formed entries: one too many.
        let many: Vec<RawPart> = (1..=17).map(|i| gpt(i, 2048 + i as u64 * 4096, 2048, GPT_BASIC_DATA, i as u8)).collect();
        assert!(decode_layout(&encode_layout(DISK, 2, &many), DISK * 512, 512).is_err());
        let sixteen: Vec<RawPart> = (1..=16).map(|i| gpt(i, 2048 + i as u64 * 4096, 2048, GPT_BASIC_DATA, i as u8)).collect();
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &sixteen), DISK * 512, 512).unwrap().parts.len(), 16);
        // A count that does not match the payload, trailing bytes, a disk of another size.
        let mut b = encode_layout(DISK, 1, &[fat_part(1, 2048, 100)]);
        b.push(0);
        assert_eq!(decode_layout(&b, DISK * 512, 512), Err(LayoutError::Size));
        let b = encode_layout(DISK, 1, &[fat_part(1, 2048, 100)]);
        assert!(matches!(decode_layout(&b, DISK * 512 + 512, 512), Err(LayoutError::DiskSize { .. })));
        assert!(matches!(decode_layout(&b, DISK * 512 + 1, 512), Err(LayoutError::DiskSize { .. })));
        assert!(matches!(decode_layout(&encode_layout(u64::MAX, 1, &[]), 0, 512), Err(LayoutError::DiskSize { .. })));
        assert_eq!(decode_layout(&b[..20], DISK * 512, 512), Err(LayoutError::Size));
        let mut r = b.clone();
        r[20] = 1;
        assert_eq!(decode_layout(&r, DISK * 512, 512), Err(LayoutError::Reserved));
    }

    #[test]
    fn hostile_types_and_fields() {
        // Partition numbers outside the table's range.
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[fat_part(37, 2048, 100)]), DISK * 512, 512), Err(LayoutError::Index(37)));
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[fat_part(0, 2048, 100)]), DISK * 512, 512), Err(LayoutError::Index(0)));
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[gpt(129, 2048, 100, GPT_BASIC_DATA, 1)]), DISK * 512, 512), Err(LayoutError::Index(129)));
        // Types Android does not use are refused, not passed on.
        let mut p = fat_part(1, 2048, 100);
        p.mbr_type = 0x83;
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[p]), DISK * 512, 512), Err(LayoutError::Type(1)));
        let linux = guid(0x0FC63DAF, 0x8483, 0x4772, [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4]);
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[gpt(1, 2048, 100, linux, 1)]), DISK * 512, 512), Err(LayoutError::Type(1)));
        // GPT fields on an MBR entry, an MBR type on a GPT entry, a zero unique GUID.
        let mut p = fat_part(1, 2048, 100);
        p.part_guid = [1; 16];
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[p]), DISK * 512, 512), Err(LayoutError::TypeFields(1)));
        let mut p = gpt(1, 2048, 100, GPT_BASIC_DATA, 1);
        p.mbr_type = 0x0c;
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[p]), DISK * 512, 512), Err(LayoutError::TypeFields(1)));
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[gpt(1, 2048, 100, GPT_BASIC_DATA, 0)]), DISK * 512, 512), Err(LayoutError::Guid(1)));
        // A filesystem on adoptable storage, an unknown filesystem kind, metadata larger than the partition.
        let mut p = gpt(1, 2048, 100, GPT_ANDROID_EXPAND, 1);
        p.fs_kind = crate::FS_VFAT;
        assert_eq!(decode_layout(&encode_layout(DISK, 2, &[p]), DISK * 512, 512), Err(LayoutError::FsKind(1)));
        let mut p = fat_part(1, 2048, 100);
        p.fs_kind = 7;
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[p]), DISK * 512, 512), Err(LayoutError::FsKind(1)));
        let mut p = fat_part(1, 2048, 1000);
        p.meta_bytes = 1000 * 512;
        assert_eq!(decode_layout(&encode_layout(DISK, 1, &[p]), DISK * 512, 512), Err(LayoutError::Meta(1)));
        // Unknown table kinds and flags.
        assert_eq!(decode_layout(&encode_layout(DISK, 3, &[]), DISK * 512, 512), Err(LayoutError::TableKind(3)));
        let mut b = encode_layout(DISK, 1, &[fat_part(1, 2048, 100)]);
        b[LAYOUT_HEADER + 4] = 2;
        assert_eq!(decode_layout(&b, DISK * 512, 512), Err(LayoutError::Reserved));
    }

    #[test]
    fn labels_are_checked_not_fatal() {
        for (raw, want) in [
            (b"MY CARD    ".to_vec(), Some("MY CARD")),
            ("Fotos 2026".as_bytes().to_vec(), Some("Fotos 2026")),
            (b"A/B".to_vec(), None),
            (b"x\x07".to_vec(), None),
            ("a\u{202E}b".as_bytes().to_vec(), None),
            (vec![0xff, 0x41], None),
        ] {
            let mut p = fat_part(1, 2048, 100);
            p.label = raw;
            let l = decode_layout(&encode_layout(DISK, 1, &[p]), DISK * 512, 512).unwrap();
            match want {
                Some(w) => assert_eq!(l.parts[0].label, w),
                None => assert_eq!((l.parts[0].label.as_str(), l.dropped_labels), ("", 1)),
            }
        }
        // Bytes after the label must be zero.
        let mut b = encode_layout(DISK, 1, &[fat_part(1, 2048, 100)]);
        b[LAYOUT_HEADER + 120] = 1;
        assert_eq!(decode_layout(&b, DISK * 512, 512), Err(LayoutError::Reserved));
    }

    #[test]
    fn probe_text_for_vold() {
        let meta = gpt(2, 6144, 2048, GPT_ANDROID_META, 2);
        let expand = gpt(3, 8192, 100_000, GPT_ANDROID_EXPAND, 3);
        let public = RawPart {
            index: 1,
            start: 2048,
            length: 4096,
            type_guid: GPT_BASIC_DATA,
            part_guid: [1; 16],
            fs_kind: crate::FS_EXFAT,
            serial: Some(0x6FFF_FAB8),
            meta_bytes: 125,
            label: b"Karte".to_vec(),
            ..Default::default()
        };
        let l = decode_layout(&encode_layout(DISK, 2, &[public, meta, expand]), DISK * 512, 512).unwrap();
        // The same text vold_tests parses (system/vold tests/Fsvm_test.cpp).
        assert_eq!(
            probe_text(&l),
            "LAYOUT 1 gpt 3\n\
             PART 1 public 2048 4096 exfat 6FFF-FAB8 01010101-0101-0101-0101-010101010101 125 4b61727465\n\
             PART 2 meta 6144 2048 - - 02020202-0202-0202-0202-020202020202 0 -\n\
             PART 3 expand 8192 100000 - - 03030303-0303-0303-0303-030303030303 0 -\n\
             END\n"
        );
        let none = decode_layout(&encode_layout(DISK, 0, &[]), DISK * 512, 512).unwrap();
        assert_eq!(probe_text(&none), "LAYOUT 1 none 0\nEND\n");
    }

    #[test]
    fn memory_is_bounded() {
        // 64 GB FAT32 with 4 KiB clusters: 64 MiB per FAT. 2 TB with 32 KiB clusters: 256 MiB.
        assert_eq!(serve_memory_mib(crate::FS_VFAT, 64 << 20), 144);
        assert_eq!(serve_memory_mib(crate::FS_VFAT, 1 << 20), 96);
        assert_eq!(serve_memory_mib(crate::FS_VFAT, 256 << 20), 224);
        assert_eq!(serve_memory_mib(crate::FS_VFAT, 1 << 30), 224);
        // 256 GB exFAT with 4 KiB clusters: 8 MiB bitmap. 2 TB with 4 KiB clusters: 64 MiB.
        assert_eq!(serve_memory_mib(crate::FS_EXFAT, 8 << 20), 96);
        assert_eq!(serve_memory_mib(crate::FS_EXFAT, 64 << 20), 144);
        assert_eq!(serve_memory_mib(crate::FS_EXFAT, u64::MAX), 256);
        assert_eq!(serve_memory_mib(0, 0), 96);
    }
}
