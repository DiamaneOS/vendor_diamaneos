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

//! The guest's LAYOUT replies, as `guest/table_test DIR` wrote them, decoded by Android's side. Run with
//! FSVM_GUEST_LAYOUTS=DIR. Without it the test only says it was skipped.

use fsvm_proto::layout::*;
use fsvm_proto::{FS_EXFAT, FS_VFAT};

const DISK_BYTES: u64 = 16 * 1024 * 1024;

fn load(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(format!("{dir}/{name}.layout")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn guest_replies_decode_as_expected() {
    let Ok(dir) = std::env::var("FSVM_GUEST_LAYOUTS") else {
        eprintln!("FSVM_GUEST_LAYOUTS not set, skipped");
        return;
    };
    let l = decode_layout(&load(&dir, "mbr_two_fat32"), DISK_BYTES, 512).unwrap();
    assert_eq!((l.table, l.parts.len()), (Table::Mbr, 2));
    assert_eq!(l.parts[0].fs_uuid.as_deref(), Some("6FFF-FAB8"));
    assert_eq!((l.parts[0].label.as_str(), l.parts[0].fs_kind), ("PHOTOS", FS_VFAT));

    let l = decode_layout(&load(&dir, "gpt_public_and_adoptable"), DISK_BYTES, 512).unwrap();
    assert_eq!(l.parts.iter().map(|p| p.class).collect::<Vec<_>>(), [Class::Public, Class::AndroidMeta, Class::AndroidExpand]);
    assert_eq!(l.parts[0].label, "Karte\u{e4}");
    assert_eq!(l.parts[0].fs_kind, FS_EXFAT);
    assert_eq!(guid_text(&l.parts[2].part_guid.unwrap()), "03030303-0303-0303-0303-030303030303");

    let l = decode_layout(&load(&dir, "whole_disk_exfat"), DISK_BYTES, 512).unwrap();
    assert_eq!((l.table, l.parts[0].index, l.parts[0].label.as_str()), (Table::None, 0, "\u{1F600}x"));
    assert_eq!(decode_layout(&load(&dir, "whole_disk_fat32"), DISK_BYTES, 512).unwrap().parts[0].fs_uuid.as_deref(), Some("CAFE-F00D"));
    assert_eq!(decode_layout(&load(&dir, "gpt_primary_broken_backup_used"), DISK_BYTES, 512).unwrap().parts.len(), 1);
    assert!(decode_layout(&load(&dir, "blank"), DISK_BYTES, 512).unwrap().parts.is_empty());
    assert!(decode_layout(&load(&dir, "mbr_bad_boot_indicator"), DISK_BYTES, 512).unwrap().parts.is_empty());
    let l = decode_layout(&load(&dir, "mbr_unknown_filesystem"), DISK_BYTES, 512).unwrap();
    assert_eq!((l.parts[0].fs_kind, l.parts[0].fs_uuid.clone()), (0, None));
    assert_eq!(decode_layout(&load(&dir, "exfat_bad_label"), DISK_BYTES, 512).unwrap().parts[0].label, "");

    // Logical partitions in an extended partition, numbered as Linux numbers them.
    let l = decode_layout(&load(&dir, "mbr_logical"), DISK_BYTES, 512).unwrap();
    assert_eq!(l.parts.iter().map(|p| p.index).collect::<Vec<_>>(), [1, 5, 7]);
    assert_eq!(l.parts[1].label, "LOGICAL");
    // A GPT read from 4096-byte blocks is checked with that block size's clearances.
    assert!(decode_layout(&load(&dir, "gpt_4k_blocks"), DISK_BYTES, 4096).is_ok());

    // Overlaps the guest reported as read are refused here.
    assert!(matches!(decode_layout(&load(&dir, "gpt_overlap"), DISK_BYTES, 512), Err(LayoutError::Overlap(..))));
    assert!(matches!(decode_layout(&load(&dir, "mbr_overlap"), DISK_BYTES, 512), Err(LayoutError::Overlap(..))));
    // The same replies against a disk of another size are refused too.
    assert!(matches!(decode_layout(&load(&dir, "mbr_two_fat32"), DISK_BYTES * 2, 512), Err(LayoutError::DiskSize { .. })));
}
