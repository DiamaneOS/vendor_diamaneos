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

//! Seed inputs from the protocol's own encoders: honest replies of every kind, an honest client session and an
//! honest FUSE session in the scripts' format (vm_replies.rs reply(), client_session(), fs_target.rs). The replay
//! test runs them and checks that the honest sessions go through, so a change of the script format that leaves the
//! seeds shallow fails there.

#![allow(dead_code)]

use fsvm_proto::layout::{self, RawPart};
use fsvm_proto::*;

/// Writes script bytes in the order vm_replies.rs Input reads them.
#[derive(Default)]
pub struct W(pub Vec<u8>);

impl W {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// Input::size() as a full u64.
    pub fn size(&mut self, v: u64) -> &mut Self {
        self.u8(7).u64(v)
    }
    /// A name from vm_replies::NAMES by its index.
    pub fn name(&mut self, index: u8) -> &mut Self {
        self.u8(index)
    }

    // --- Reply payloads, as natural_payload() reads them ---

    pub fn attr(&mut self, node: u64, dir: bool, size: u64) -> &mut Self {
        self.u8(2).u64(node).size(size).size(1_700_000_000).u8(0).u32(5).u8(if dir { 5 } else { 1 })
    }
    pub fn hello(&mut self, fs_kind: u8, flags: u8, root: u8) -> &mut Self {
        self.u8(1).u8(fs_kind).u8(1).u8(flags).u8(1).u8(1).u8(root - 1)
    }
    pub fn statfs(&mut self) -> &mut Self {
        self.size(1 << 24).size(1 << 23).size(1 << 22).u8(0).u8(3).u32(255)
    }
    /// One page, cookie 0: (name index, node, is a directory).
    pub fn dir_page(&mut self, entries: &[(u8, u64, bool)]) -> &mut Self {
        self.u8(0).u8(entries.len() as u8).u8(1).u8(1);
        for &(name, node, dir) in entries {
            self.attr(node, dir, 100).name(name).u8(1);
        }
        self
    }
    /// One FAT32 partition from sector 2048 to the end.
    pub fn mbr_layout(&mut self) -> &mut Self {
        self.u8(1).u8(1).u8(1).u8(4);
        self.u8(0).u8(0).u8(1); // start at 2048, to the end, FAT
        self.u8(1).u8(0).u8(3).u8(0).u8(1).u8(0).u32(0x6fff_fab8).u8(0).u8(1).name(3);
        self.u8(2)
    }
    pub fn read(&mut self, len: usize) -> &mut Self {
        self.u8(0).bytes(&vec![0x42; len])
    }
    pub fn write_all(&mut self) -> &mut Self {
        self.u8(1).u8(0).u32(0)
    }
    pub fn u64_reply(&mut self, v: u64) -> &mut Self {
        self.u8(1).u64(v)
    }
}

pub const DISK: u64 = 1 << 27;

fn frame(op: Op, id: u32, payload: &[u8]) -> Vec<u8> {
    let _ = op;
    let mut b = Vec::new();
    b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

fn attr(node: u64, kind: Kind, size: u64) -> Attr {
    Attr { node, kind, size, mtime_s: 1_700_000_000, mtime_ns: 5 }
}

/// Seeds of fsvm_proto_fuzzer (vm_replies::decoders): a selector byte, then a reply as the guest encodes it.
pub fn decoder_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut add = |name: &str, sel: u8, pre: &[u8], body: &[u8]| {
        let mut v = vec![sel];
        v.extend_from_slice(pre);
        v.extend_from_slice(body);
        out.push((name.to_string(), v));
    };
    add("attr-file", 0, &[], &encode_attr(&attr(7, Kind::File, 1234)));
    add("attr-dir", 0, &[], &encode_attr(&attr(9, Kind::Dir, 0)));
    let mut h = [0u8; HELLO_SIZE];
    h[0..4].copy_from_slice(&VERSION.to_le_bytes());
    h[4..8].copy_from_slice(&FS_EXFAT.to_le_bytes());
    h[8] = 5;
    h[16..24].copy_from_slice(&1u64.to_le_bytes());
    add("hello", 1, &[], &h);
    let mut s = [0u8; STATFS_SIZE];
    s[0..8].copy_from_slice(&1000u64.to_le_bytes());
    s[8..16].copy_from_slice(&500u64.to_le_bytes());
    s[16..24].copy_from_slice(&400u64.to_le_bytes());
    s[24..28].copy_from_slice(&32768u32.to_le_bytes());
    add("statfs", 2, &[], &s);
    let a = attr(5, Kind::File, 10);
    let page = encode_dir_page(
        3,
        &[(b"DCIM", attr(2, Kind::Dir, 0)), (b"photo.jpg", a), (b"PHOTO.JPG", a), (b"..", a), ("日本語".as_bytes(), a)],
    );
    add("dir-page", 3, &[2], &page);
    let mbr = layout::encode_layout(
        DISK,
        1,
        &[RawPart {
            index: 1,
            start: 2048,
            length: DISK - 2048,
            mbr_type: 0x0c,
            fs_kind: FS_VFAT,
            serial: Some(0x6fff_fab8),
            meta_bytes: 1 << 20,
            label: b"CARD       ".to_vec(),
            ..Default::default()
        }],
    );
    let mut pre = Vec::new();
    pre.push(7); // Input::size() as u64
    pre.extend_from_slice(&(DISK * 512).to_le_bytes());
    pre.push(0); // 512-byte blocks
    add("layout-mbr", 4, &pre, &mbr);
    let gpt = layout::encode_layout(
        DISK,
        2,
        &[
            RawPart { index: 1, start: 2048, length: 32768, type_guid: layout::GPT_ANDROID_META, part_guid: [1; 16], ..Default::default() },
            RawPart {
                index: 2,
                start: 34816,
                length: DISK - 34816 - 33,
                type_guid: layout::GPT_ANDROID_EXPAND,
                part_guid: [2; 16],
                ..Default::default()
            },
        ],
    );
    add("layout-gpt", 4, &pre, &gpt);
    let whole = layout::encode_layout(
        DISK,
        0,
        &[RawPart { index: 0, start: 0, length: DISK, fs_kind: FS_EXFAT, serial: Some(1), meta_bytes: 4096, ..Default::default() }],
    );
    add("layout-whole", 5, &pre, &whole);
    let mut h = Vec::new();
    h.extend_from_slice(&frame(Op::Read, 3, &[])[..RSP_HEADER]);
    h.extend_from_slice(&3u32.to_le_bytes());
    h.extend_from_slice(&MAX_IO.to_le_bytes());
    add("reply-header", 6, &[], &h);
    add("name", 7, &[], "\u{0645}\u{06CC}\u{200C}\u{062E}.txt".as_bytes());
    out
}

/// An honest client session (vm_replies::client_session): hello, layout, mount, lookups, a listing, I/O, a handle,
/// statfs, write back and unmount, every reply sound.
pub fn client_seed() -> Vec<u8> {
    let mut ops = W::default();
    // Each op: the op, the node (0: node 1), a name, then its own arguments.
    ops.u8(0).u8(0).name(0); // hello
    ops.u8(1).u8(0).name(0); // layout
    ops.u8(2).u8(0).name(0).u8(1).u64(2048).u64(DISK - 2048).u8(1).u8(1).u16(0); // mount, writable, FAT
    ops.u8(7).u8(0).name(3); // lookup DCIM
    ops.u8(8).u8(0).name(0); // getattr
    ops.u8(9).u8(0).name(0); // list
    ops.u8(10).u8(0).name(0).u32(4096).u64(0); // read
    ops.u8(12).u8(0).name(0).u32(4096).u64(0); // write
    ops.u8(14).u8(0).name(0).u8(0); // open for writing
    ops.u8(25).u8(0).name(0); // statfs
    ops.u8(28).u8(0).name(0); // dirty
    ops.u8(27).u8(0).name(0).u16(5000); // unmount
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).hello(0, 0, 1);
    s.u8(0).mbr_layout();
    s.u8(0).hello(1, 0, 1);
    s.u8(0).attr(2, true, 0);
    s.u8(0).attr(1, true, 0);
    s.u8(0).dir_page(&[(3, 2, true), (5, 3, false), (11, 4, false)]);
    s.u8(0).read(4096);
    s.u8(0).write_all();
    s.u8(0).u64_reply(77);
    s.u8(0).statfs();
    s.u8(0).u64_reply(0);
    s.u8(0); // unmount: empty payload
    s.u8(0); // a last byte, so the script has not ended at the unmount's reply
    s.0
}

/// An honest FUSE session (fs_target::fs_session): lookups, a listing, open, read, write, create, mkdir, rename,
/// unlink, statfs and the orderly stop.
pub fn fs_seed() -> Vec<u8> {
    let mut ops = W::default();
    // Each op: the op, the inode (0: the root), a handle (a raw u64 while none is open, else a byte below 32 and a raw
    // u64, or 32 and up and an index), then its own arguments.
    ops.u8(0).u8(0).u64(0).name(3); // lookup DCIM in the root
    ops.u8(15).u8(0).u64(0); // opendir root
    ops.u8(16).u8(0).u64(0).u8(16).u8(0).u16(4096).u16(0); // readdir through the listing's handle
    ops.u8(0).u8(0).u64(0).name(5); // lookup photo.jpg
    ops.u8(18).u8(0).u64(0); // statfs
    ops.u8(10).u8(0).u64(0).name(11).u32(0o2 as u32); // create 日本語
    ops.u8(6).u8(0).u8(32).u8(0).u8(0).u16(512).u64(0); // write 512 bytes through the new file's handle
    ops.u8(11).u8(0).u8(0).u64(0).name(0); // mkdir a
    ops.u8(18).u8(0).u8(0).u64(0); // statfs again
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(2, true, 0); // lookup DCIM
    s.u8(0).dir_page(&[(3, 2, true), (5, 3, false)]); // the listing
    s.u8(0).attr(3, false, 4096); // lookup photo.jpg
    s.u8(0).statfs();
    s.u8(0).attr(4, false, 0); // create
    s.u8(0).u64_reply(9); // open of the new file
    s.u8(0).write_all();
    s.u8(0).attr(5, true, 0); // mkdir
    s.u8(0).statfs();
    s.u8(0); // unmount at the orderly stop (its budget is too short to wait for the dirty data first)
    s.u8(0); // a last byte, so the script has not ended at the unmount's reply
    s.0
}

/// Finding (fixed): a create whose open failed kept the lookup map() counted, so the node outlived the kernel's last
/// forget and its inode came back for the same name.
pub fn fs_create_open_fails() -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(10).u8(0).u64(0).name(0).u32(2); // create "a": its open fails
    ops.u8(0).u8(0).u64(0).name(0); // lookup "a": the same node
    ops.u8(19).u8(16).u64(0).u8(0); // forget every lookup the kernel got
    ops.u8(0).u8(0).u64(0).name(0); // lookup "a" again: a new inode
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(5, false, 0); // create
    s.u8(9).u8(2).u8(5).u8(1); // open: EIO
    s.u8(0).attr(5, false, 0); // lookup
    s.u8(0).attr(5, false, 0); // lookup
    s.u8(0); // unmount at the orderly stop
    s.u8(0);
    s.0
}

/// Finding (review 1b H3): a file stays open while its VM is replaced, and a read through it went to whatever the new
/// VM holds under the file's name.
pub fn fs_reconnect_handle() -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(10).u8(0).u64(0).name(0).u32(2); // create "a", open for writing
    ops.u8(5).u8(16).u8(32).u8(0).u8(0).u64(0); // read through its handle: the VM goes, a new one serves
    ops.u8(5).u8(16).u8(32).u8(0).u8(0).u64(0); // read through the same handle in the new VM
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(5, false, 0); // create
    s.u8(0).u64_reply(9); // open of the new file
    s.u8(15); // the read: the VM closes the session
    s.u8(0).u8(0); // the new VM: mounted writable, root 1
    s.u8(0).attr(7, false, 100); // a lookup of "a" in the new VM: another file
    s.u8(0).u8(1).u16(4).bytes(b"NEW!"); // its data
    s.u8(0); // unmount at the orderly stop
    s.u8(0);
    s.0
}

/// Finding (review 1b M7): a file opened, then unlinked, came back through its handle as a directory.
pub fn fs_unlinked_handle_kind() -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(10).u8(0).u64(0).name(0).u32(2); // create "a", open for writing
    ops.u8(12).u8(0).u8(32).u8(0).name(0); // unlink "a"
    ops.u8(1).u8(1).u64(2).u8(32).u8(0).u8(1); // getattr of its inode through the open handle
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(5, false, 0); // create
    s.u8(0).u64_reply(9); // open of the new file
    s.u8(0); // unlink
    s.u8(0).attr(5, true, 0); // getattr through the handle: a directory
    s.u8(0); // unmount at the orderly stop
    s.u8(0);
    s.0
}

/// The VM breaks during OPEN of an inode that the kernel already looked up.
pub fn fs_midcall_open() -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(0).u8(0).u64(0).name(0);
    ops.u8(3).u8(16).u64(0).u32(0);
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(5, false, 8);
    s.u8(15);
    s.u8(0).u8(0);
    s.u8(0).attr(7, false, 11);
    s.u8(0).u64_reply(9);
    s.u8(0);
    s.0
}

/// TRUNCATE through an unlinked file's handle must keep the kind saved at OPEN.
pub fn fs_unlinked_truncate_kind() -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(10).u8(0).u64(0).name(0).u32(2);
    ops.u8(12).u8(0).u8(32).u8(0).name(0);
    ops.u8(2).u8(1).u64(2).u8(32).u8(0).u64(3).u64(1_700_000_100).u32(5).u32(8);
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    s.u8(0).attr(5, false, 8);
    s.u8(0).u64_reply(9);
    s.u8(0);
    s.u8(0).attr(1, false, 8);
    s.u8(0).attr(1, true, 0);
    s.u8(0);
    s.0
}

/// A modifying directory setattr cannot continue after its initial lookup or mutation loses the session.
pub fn fs_directory_timestamp(initial: bool) -> Vec<u8> {
    let mut ops = W::default();
    ops.u8(2).u8(0).u64(0).u64(0).u64(1_700_000_100).u32(0).u32(32);
    let mut s = W::default();
    s.u16(ops.0.len() as u16).bytes(&ops.0).u8(0).u8(0);
    if !initial { s.u8(0).attr(1, true, 0); }
    s.u8(15).u8(0).u8(0);
    s.u8(0).attr(1, true, 0);
    if initial { s.u8(0).attr(1, true, 0); }
    s.u8(0).u8(0);
    s.0
}

pub fn all() -> Vec<(String, String, Vec<u8>)> {
    let mut v: Vec<(String, String, Vec<u8>)> =
        decoder_seeds().into_iter().map(|(n, b)| ("proto".to_string(), format!("seed-{n}"), b)).collect();
    v.push(("client".into(), "seed-honest-session".into(), client_seed()));
    v.push(("fs".into(), "seed-honest-session".into(), fs_seed()));
    v.push(("fs".into(), "finding-create-open-fails".into(), fs_create_open_fails()));
    v.push(("fs".into(), "finding-reconnect-handle".into(), fs_reconnect_handle()));
    v.push(("fs".into(), "finding-unlinked-truncate-kind".into(), fs_unlinked_truncate_kind()));
    v.push(("fs".into(), "finding-directory-getattr".into(), fs_directory_timestamp(true)));
    v.push(("fs".into(), "finding-directory-mtime".into(), fs_directory_timestamp(false)));
    v.push(("fs".into(), "finding-midcall-open".into(), fs_midcall_open()));
    v.push(("fs".into(), "finding-unlinked-handle-kind".into(), fs_unlinked_handle_kind()));
    v
}
