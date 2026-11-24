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

//! The client against a hostile VM: a server thread on the other end of a socket pair plays each attack. The
//! client must never hang past its deadline, never accept more than a request allows, never panic, and break the
//! session on anything malformed.

use fsvm_proto::client::CallError;
use fsvm_proto::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

struct Req {
    op: u16,
    id: u32,
    len: u32,
}

fn read_req(s: &mut UnixStream) -> Option<Req> {
    let mut h = [0u8; REQ_HEADER];
    s.read_exact(&mut h).ok()?;
    let le32 = |at: usize| u32::from_le_bytes(h[at..at + 4].try_into().unwrap());
    let op = u16::from_le_bytes([h[4], h[5]]);
    let (id, name_len, len, name2_len) = (le32(8), le32(12), le32(40), le32(44));
    let mut rest = name_len as usize + name2_len as usize;
    if op == Op::Write as u16 {
        rest += len as usize;
    }
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).ok()?;
    Some(Req { op, id, len })
}

fn reply(s: &mut UnixStream, id: u32, status: i32, payload: &[u8]) {
    let mut b = Vec::new();
    b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&status.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    let _ = s.write_all(&b);
}

fn attr(node: u64, kind: Kind, size: u64) -> Attr {
    Attr { node, kind, size, mtime_s: 1_700_000_000, mtime_ns: 0 }
}

fn quick() -> Deadlines {
    Deadlines { hello: Duration::from_millis(600), meta: Duration::from_millis(600), io: Duration::from_millis(600), mutate: Duration::from_millis(600), mount: Duration::from_millis(600), listing: Duration::from_secs(30), operation: Duration::from_secs(30) }
}

/// Runs `server` against a fresh client and returns the client.
fn with_server<F>(server: F) -> Client<StreamTransport<UnixStream>>
where
    F: FnOnce(UnixStream) + Send + 'static,
{
    let (a, b) = UnixStream::pair().unwrap();
    thread::spawn(move || server(b));
    Client::new(StreamTransport(a), quick())
}

#[test]
fn honest_server_works() {
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            match r.op {
                x if x == Op::Getattr as u16 => reply(&mut s, r.id, 0, &encode_attr(&attr(2, Kind::File, 10))),
                x if x == Op::Read as u16 => reply(&mut s, r.id, 0, &vec![7u8; r.len.min(10) as usize]),
                x if x == Op::Write as u16 => {
                    let mut p = [0u8; 8];
                    p[0..4].copy_from_slice(&r.len.to_le_bytes());
                    reply(&mut s, r.id, 0, &p)
                }
                x if x == Op::Lookup as u16 => reply(&mut s, r.id, -errno::ENOENT, &[]),
                _ => reply(&mut s, r.id, -errno::EINVAL, &[]),
            }
        }
    });
    assert_eq!(c.getattr(2).unwrap().size, 10);
    assert_eq!(c.read(2, 0, 4096).unwrap().len(), 10);
    assert_eq!(c.write(2, 0, &[1, 2, 3]).unwrap(), 3);
    assert!(matches!(c.lookup(1, b"missing"), Err(CallError::Errno(e)) if e == errno::ENOENT));
    assert!(!c.is_broken());
}

#[test]
fn slow_drip_cannot_stretch_a_call() {
    // One byte every 100 ms: a per-read timeout of 600 ms would wait forever, the total deadline stops it.
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            let mut b = Vec::new();
            b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            b.extend_from_slice(&r.id.to_le_bytes());
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&(ATTR_SIZE as u32).to_le_bytes());
            b.extend_from_slice(&encode_attr(&attr(2, Kind::File, 1)));
            for byte in b {
                if s.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
    let t = Instant::now();
    assert!(matches!(c.getattr(2), Err(CallError::Broken(_))));
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
    // A broken session fails at once.
    let t = Instant::now();
    assert!(matches!(c.getattr(2), Err(CallError::Broken(_))));
    assert!(t.elapsed() < Duration::from_millis(50));
}

#[test]
fn silent_server_times_out() {
    let mut c = with_server(|mut s| {
        let _ = read_req(&mut s);
        thread::sleep(Duration::from_secs(5));
    });
    let t = Instant::now();
    assert!(matches!(c.statfs(), Err(CallError::Broken(_))));
    assert!(t.elapsed() < Duration::from_millis(1200));
}

#[test]
fn oversized_reply_is_refused_before_reading_it() {
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            // Claims 4 GiB for a 4 KiB read, then sends nothing more.
            let mut b = Vec::new();
            b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            b.extend_from_slice(&r.id.to_le_bytes());
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&u32::MAX.to_le_bytes());
            let _ = s.write_all(&b);
            thread::sleep(Duration::from_secs(5));
        }
    });
    let t = Instant::now();
    assert!(matches!(c.read(2, 0, 4096), Err(CallError::Broken(_))));
    assert!(t.elapsed() < Duration::from_millis(200), "refused from the header, not after a timeout");
}

#[test]
fn read_longer_than_asked_is_refused() {
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, 0, &vec![0u8; r.len as usize + 1]);
        }
    });
    assert!(matches!(c.read(2, 0, 100), Err(CallError::Broken(_))));
}

#[test]
fn write_count_beyond_request_is_refused() {
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            let mut p = [0u8; 8];
            p[0..4].copy_from_slice(&(r.len + 1).to_le_bytes());
            reply(&mut s, r.id, 0, &p);
        }
    });
    assert!(matches!(c.write(2, 0, &[1, 2, 3]), Err(CallError::Broken(_))));
}

#[test]
fn wrong_id_magic_and_status_break_the_session() {
    for attack in 0..4 {
        let mut c = with_server(move |mut s| {
            if let Some(r) = read_req(&mut s) {
                match attack {
                    0 => reply(&mut s, r.id + 1, 0, &encode_attr(&attr(2, Kind::File, 1))),
                    1 => {
                        let mut b = vec![0u8; RSP_HEADER];
                        b[0..4].copy_from_slice(&REQ_MAGIC.to_le_bytes());
                        let _ = s.write_all(&b);
                    }
                    2 => reply(&mut s, r.id, 17, &[]),
                    _ => reply(&mut s, r.id, -errno::ENOENT, &[1, 2, 3]),
                }
                thread::sleep(Duration::from_millis(300));
            }
        });
        assert!(matches!(c.getattr(2), Err(CallError::Broken(_))), "attack {attack}");
    }
}

#[test]
fn unknown_errno_becomes_eio() {
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, -95, &[]); // EOPNOTSUPP is not passed through
        }
    });
    assert!(matches!(c.getattr(2), Err(CallError::Errno(e)) if e == errno::EIO));
    assert!(!c.is_broken());
}

/// EMFILE reaches Android for OPEN only (the VM has no handle left, review 1b L2), any other call answers EIO.
#[test]
fn emfile_only_for_open() {
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, -errno::EMFILE, &[]);
        }
    });
    assert!(matches!(c.open_handle(2, false), Err(CallError::Errno(e)) if e == errno::EMFILE));
    assert!(matches!(c.getattr(2), Err(CallError::Errno(e)) if e == errno::EIO));
    assert!(matches!(c.read_handle(7, 0, 10), Err(CallError::Errno(e)) if e == errno::EIO));
    assert!(!c.is_broken());
}

/// One FUSE request's calls end within its operation deadline (review 1b M6): a call whose own deadline would pass it
/// is not sent, the session stays sound, and the calls that fit go through.
#[test]
fn operation_deadline_is_kept() {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut c = with_server(move |mut s| {
        while let Some(r) = read_req(&mut s) {
            let _ = tx.send(r.op);
            thread::sleep(Duration::from_millis(250));
            reply(&mut s, r.id, 0, &encode_attr(&attr(2, Kind::File, 1)));
        }
    });
    // meta is 600 ms and each lookup takes 250 ms: about six fit in 2 s, the next would end after it and is not sent.
    let start = Instant::now();
    c.op_deadline = Some(start + Duration::from_secs(2));
    let mut sent = 0;
    let end = loop {
        match c.lookup(1, b"a") {
            Ok(_) => sent += 1,
            Err(e) => break e,
        }
    };
    assert!(matches!(end, CallError::OutOfTime), "{end:?}");
    assert!(start.elapsed() < Duration::from_secs(2), "the operation took {:?}", start.elapsed());
    assert_eq!(rx.try_iter().count(), sent, "a call sent past the operation's end");
    assert!((4..=7).contains(&sent), "{sent} calls fit");
    assert!(!c.is_broken());
    // The next operation has its own time.
    c.op_deadline = None;
    assert!(c.lookup(1, b"a").is_ok());
}

#[test]
fn directory_listing_is_cleaned() {
    let mut c = with_server(|mut s| {
        let mut page = 0;
        while let Some(r) = read_req(&mut s) {
            assert_eq!(r.op, Op::Readdir as u16);
            let a = attr(9, Kind::File, 1);
            let body = if page == 0 {
                encode_dir_page(5, &[(b"DCIM", a), (b"dcim", a), ("bad\u{202E}gpj.exe".as_bytes(), a), (b"..", a), (b"ok", a)])
            } else {
                encode_dir_page(0, &[(b"OK", a), (b"last", a)])
            };
            page += 1;
            reply(&mut s, r.id, 0, &body);
        }
    });
    let l = c.list(1).unwrap();
    let names: Vec<&str> = l.entries.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["DCIM", "ok", "last"]);
    assert_eq!((l.dropped, l.duplicates), (2, 2));
}

#[test]
fn directory_cookie_must_advance() {
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            let a = attr(9, Kind::File, 1);
            reply(&mut s, r.id, 0, &encode_dir_page(3, &[(b"same", a)]));
        }
    });
    assert!(matches!(c.list(1), Err(CallError::Broken(_))));
}

#[test]
fn endless_directory_is_capped() {
    let mut c = with_server(|mut s| {
        let mut n = 0u64;
        while let Some(r) = read_req(&mut s) {
            let names: Vec<String> = (0..MAX_DIR_ENTRIES_PER_PAGE as u64).map(|i| format!("f{}", n * 1000 + i)).collect();
            let a = attr(9, Kind::File, 1);
            let entries: Vec<(&[u8], Attr)> = names.iter().map(|x| (x.as_bytes(), a)).collect();
            n += 1;
            reply(&mut s, r.id, 0, &encode_dir_page(n, &entries));
        }
    });
    c.deadlines.meta = Duration::from_secs(2);
    let l = c.list(1).unwrap();
    assert!(l.truncated);
    // The memory cap ends it before the entry cap.
    assert!(l.bytes <= MAX_LISTING_BYTES && l.entries.len() < MAX_DIR_ENTRIES);
    assert!(l.bytes + 100 > MAX_LISTING_BYTES);
}

#[test]
fn slow_directory_has_one_total_deadline() {
    let mut c = with_server(|mut s| {
        let mut n = 0u64;
        while let Some(r) = read_req(&mut s) {
            std::thread::sleep(Duration::from_millis(300));
            let name = format!("f{n}");
            n += 1;
            reply(&mut s, r.id, 0, &encode_dir_page(n, &[(name.as_bytes(), attr(9, Kind::File, 1))]));
        }
    });
    c.deadlines.meta = Duration::from_secs(1);
    c.deadlines.listing = Duration::from_secs(2);
    let t = std::time::Instant::now();
    let l = c.list(1);
    // Each page in time, but the whole listing is cut at its deadline: either shorter, or a broken session when the
    // deadline ended inside a page.
    assert!(t.elapsed() < Duration::from_secs(4));
    match l {
        Ok(l) => assert!(l.truncated && l.entries.len() < 10),
        Err(e) => assert!(matches!(e, CallError::Broken(_))),
    }
}

#[test]
fn outgoing_names_follow_the_same_rules() {
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, 0, &encode_attr(&attr(3, Kind::File, 0)));
        }
    });
    assert!(matches!(c.create(1, "x\u{202E}y".as_bytes(), true), Err(CallError::Errno(e)) if e == errno::EINVAL));
    assert!(matches!(c.lookup(1, b".."), Err(CallError::Errno(e)) if e == errno::ENOENT));
    assert!(c.create(1, b"ok.txt", true).is_ok());
    assert!(!c.is_broken());
}

/// A small deterministic generator, so the fuzz test needs no extra crates and repeats exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn random_replies_never_panic_or_hang() {
    for seed in 1..=300u64 {
        let mut c = with_server(move |mut s| {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            while let Some(r) = read_req(&mut s) {
                let mut b = Vec::new();
                // Mostly well framed replies with random contents, sometimes pure noise.
                let len = (rng.next() % 600) as usize;
                if rng.next() % 4 != 0 {
                    b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
                    b.extend_from_slice(&r.id.to_le_bytes());
                    let status = match rng.next() % 4 { 0 => -((rng.next() % 200) as i32), _ => 0 };
                    b.extend_from_slice(&status.to_le_bytes());
                    b.extend_from_slice(&(len as u32).to_le_bytes());
                }
                for _ in 0..len {
                    b.push(rng.next() as u8);
                }
                if s.write_all(&b).is_err() {
                    return;
                }
            }
        });
        c.deadlines = Deadlines { hello: Duration::from_millis(150), meta: Duration::from_millis(150), io: Duration::from_millis(150), mutate: Duration::from_millis(150), mount: Duration::from_millis(150), listing: Duration::from_secs(30), operation: Duration::from_secs(30) };
        let t = Instant::now();
        let _ = c.getattr(2);
        let _ = c.list(1);
        let _ = c.read(2, 0, 256);
        let _ = c.statfs();
        let _ = c.hello();
        let _ = c.layout(1 << 30, 512);
        let _ = c.mount(1, 2048, 4096, true, FS_VFAT, Duration::ZERO);
        assert!(t.elapsed() < Duration::from_secs(3), "seed {seed}");
    }
}

fn hello_payload(fs_kind: u32, read_only: bool) -> Vec<u8> {
    let mut h = vec![0u8; HELLO_SIZE];
    h[0..4].copy_from_slice(&VERSION.to_le_bytes());
    h[4..8].copy_from_slice(&fs_kind.to_le_bytes());
    h[8..12].copy_from_slice(&(read_only as u32).to_le_bytes());
    h[16..24].copy_from_slice(&1u64.to_le_bytes());
    h
}

fn hello_flags(fs_kind: u32, flags: u32) -> Vec<u8> {
    let mut h = hello_payload(fs_kind, false);
    h[8..12].copy_from_slice(&flags.to_le_bytes());
    h
}

const DISK_BYTES: u64 = 1 << 30;

fn fat(index: u32, start: u64, length: u64) -> layout::RawPart {
    layout::RawPart { index, start, length, mbr_type: 0x0c, fs_kind: FS_VFAT, serial: Some(0x1234_5678), ..Default::default() }
}

/// Serves one fixed LAYOUT payload, then answers MOUNT with `mount_reply`.
fn layout_server(payload: Vec<u8>, mount_reply: Vec<u8>) -> Client<StreamTransport<UnixStream>> {
    with_server(move |mut s| {
        while let Some(r) = read_req(&mut s) {
            match r.op {
                x if x == Op::Layout as u16 => reply(&mut s, r.id, 0, &payload),
                x if x == Op::Mount as u16 => reply(&mut s, r.id, 0, &mount_reply),
                x if x == Op::Hello as u16 => reply(&mut s, r.id, 0, &hello_payload(0, false)),
                _ => reply(&mut s, r.id, -errno::EINVAL, &[]),
            }
        }
    })
}

#[test]
fn honest_layout_and_mount() {
    let sectors = DISK_BYTES / 512;
    let p = layout::encode_layout(sectors, 1, &[fat(1, 2048, 100_000), fat(2, 200_000, 100_000)]);
    let mut c = layout_server(p, hello_payload(FS_VFAT, false));
    assert_eq!(c.hello().unwrap().fs_kind, 0);
    let l = c.layout(DISK_BYTES, 512).unwrap();
    assert_eq!(l.parts.len(), 2);
    assert_eq!(l.parts[1].fs_uuid.as_deref(), Some("1234-5678"));
    assert_eq!(c.mount(2, 200_000, 100_000, false, FS_VFAT, Duration::ZERO).unwrap().fs_kind, FS_VFAT);
    assert!(!c.is_broken());
}

#[test]
fn hostile_layouts_break_the_session() {
    let sectors = DISK_BYTES / 512;
    let overlap = layout::encode_layout(sectors, 1, &[fat(1, 2048, 100_000), fat(2, 50_000, 100_000)]);
    let out_of_range = layout::encode_layout(sectors, 1, &[fat(1, 2048, sectors)]);
    let other_disk = layout::encode_layout(sectors * 2, 1, &[fat(1, 2048, 100)]);
    let mut hundreds = layout::encode_layout(sectors, 2, &[]);
    hundreds[12..16].copy_from_slice(&500u32.to_le_bytes());
    for (what, p) in [("overlap", overlap), ("out of range", out_of_range), ("other disk", other_disk), ("hundreds", hundreds)] {
        let mut c = layout_server(p, hello_payload(FS_VFAT, false));
        assert!(matches!(c.layout(DISK_BYTES, 512), Err(CallError::Broken(_))), "{what}");
        // Nothing more is asked of a VM that lied about the disk.
        let t = Instant::now();
        assert!(matches!(c.mount(1, 2048, 100, true, 0, Duration::ZERO), Err(CallError::Broken(_))), "{what}");
        assert!(t.elapsed() < Duration::from_millis(50));
    }
}

#[test]
fn oversized_layout_is_refused_from_the_header() {
    let mut c = with_server(|mut s| {
        if let Some(r) = read_req(&mut s) {
            let mut b = Vec::new();
            b.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            b.extend_from_slice(&r.id.to_le_bytes());
            b.extend_from_slice(&0i32.to_le_bytes());
            b.extend_from_slice(&((layout::MAX_LAYOUT_PAYLOAD + 1) as u32).to_le_bytes());
            let _ = s.write_all(&b);
            thread::sleep(Duration::from_secs(5));
        }
    });
    let t = Instant::now();
    assert!(matches!(c.layout(DISK_BYTES, 512), Err(CallError::Broken(_))));
    assert!(t.elapsed() < Duration::from_millis(200));
}

#[test]
fn hostile_mount_replies_break_the_session() {
    let sectors = DISK_BYTES / 512;
    for (what, reply_payload, ro) in [
        ("no filesystem", hello_payload(0, false), false),
        ("other filesystem", hello_payload(FS_EXFAT, false), false),
        ("writable when read-only was asked", hello_payload(FS_VFAT, false), true),
        // Review 1b M1: the switch after a check would make the volume writable.
        ("a check pending when read-only was asked", hello_flags(FS_VFAT, 5), true),
        ("short", hello_payload(FS_VFAT, false)[..10].to_vec(), false),
    ] {
        let mut c = layout_server(layout::encode_layout(sectors, 1, &[fat(1, 2048, 100)]), reply_payload);
        assert!(matches!(c.mount(1, 2048, 100, ro, FS_VFAT, Duration::ZERO), Err(CallError::Broken(_))), "{what}");
    }
}

/// The check after the mount (protocol 6): an honest VM, then hostile answers to CHECK.
#[test]
fn check_after_mount() {
    let sectors = DISK_BYTES / 512;
    let layout_payload = layout::encode_layout(sectors, 1, &[fat(1, 2048, 100_000)]);
    // Honest: mounted read-only with the check pending, running twice, then passed, then the switch works.
    let p = layout_payload.clone();
    let mut c = with_server(move |mut s| {
        let mut polls = 0;
        while let Some(r) = read_req(&mut s) {
            match r.op {
                x if x == Op::Layout as u16 => reply(&mut s, r.id, 0, &p),
                x if x == Op::Mount as u16 => {
                    let mut h = hello_payload(FS_VFAT, true);
                    h[8] = 1 | 2 | 4;
                    reply(&mut s, r.id, 0, &h)
                }
                x if x == Op::Check as u16 && r.len == 0 => {
                    polls += 1;
                    let state: u32 = if polls < 3 { 0 } else { 1 };
                    let mut b = state.to_le_bytes().to_vec();
                    b.extend_from_slice(&1234u32.to_le_bytes());
                    reply(&mut s, r.id, 0, &b)
                }
                x if x == Op::Check as u16 => reply(&mut s, r.id, 0, &[]),
                _ => reply(&mut s, r.id, -errno::EINVAL, &[]),
            }
        }
    });
    c.layout(DISK_BYTES, 512).unwrap();
    let h = c.mount_check_later(1, 2048, 100_000, FS_VFAT).unwrap();
    assert!(h.check_pending && h.read_only && h.was_dirty);
    assert_eq!(c.check_poll().unwrap().0, CheckState::Running);
    assert_eq!(c.check_poll().unwrap().0, CheckState::Running);
    let (state, ran) = c.check_poll().unwrap();
    assert_eq!((state, ran), (CheckState::Passed, Duration::from_millis(1234)));
    c.check_switch(Duration::from_secs(15), Duration::from_secs(1)).unwrap();
    assert!(!c.is_broken());

    // Hostile: an unknown state, a short reply, a payload on the switch, pending while writable.
    let bad_state = 9u32.to_le_bytes().iter().chain(0u32.to_le_bytes().iter()).copied().collect::<Vec<u8>>();
    for (what, poll_reply) in [("state 9", bad_state), ("short", vec![1u8, 0, 0, 0])] {
        let mut c = with_server(move |mut s| {
            while let Some(r) = read_req(&mut s) {
                reply(&mut s, r.id, 0, &poll_reply)
            }
        });
        assert!(matches!(c.check_poll(), Err(CallError::Broken(_))), "{what}");
    }
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, 0, &[1])
        }
    });
    assert!(matches!(c.check_switch(Duration::ZERO, Duration::from_secs(1)), Err(CallError::Broken(_))));
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            let mut h = hello_payload(FS_VFAT, false);
            h[8] = 4; // pending, but writable
            reply(&mut s, r.id, 0, &h)
        }
    });
    assert!(matches!(c.mount_check_later(1, 2048, 100_000, FS_VFAT), Err(CallError::Broken(_))));
    // A switch that fails is an errno, the session stays.
    let mut c = with_server(|mut s| {
        while let Some(r) = read_req(&mut s) {
            reply(&mut s, r.id, -errno::EIO, &[])
        }
    });
    assert!(matches!(c.check_switch(Duration::ZERO, Duration::from_secs(1)), Err(CallError::Errno(e)) if e == errno::EIO));
    assert!(!c.is_broken());
}

/// A server that answers the first request (DISK) with `status` and `payload`, after checking it names `want_disk`
/// with this side's version. It records what it got.
fn disk_server(want_disk: u64, status: i32, payload: Vec<u8>) -> (Client<StreamTransport<UnixStream>>, std::sync::mpsc::Receiver<(u16, u64, u64)>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let c = with_server(move |mut s| {
        let mut h = [0u8; REQ_HEADER];
        if s.read_exact(&mut h).is_err() {
            return;
        }
        let op = u16::from_le_bytes([h[4], h[5]]);
        let id = u32::from_le_bytes(h[8..12].try_into().unwrap());
        let node = u64::from_le_bytes(h[16..24].try_into().unwrap());
        let arg = u64::from_le_bytes(h[32..40].try_into().unwrap());
        let _ = tx.send((op, node, arg));
        if op == Op::Disk as u16 && arg == want_disk {
            reply(&mut s, id, status, &payload);
        } else {
            reply(&mut s, id, -errno::EINVAL, &[]);
        }
        // Open until the client goes, as a VM's server is.
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest);
    });
    (c, rx)
}

#[test]
fn disk_is_named_first_with_the_version() {
    let (mut c, rx) = disk_server(2, 0, hello_payload(0, false));
    let h = c.select_disk(2).unwrap();
    assert_eq!(h.fs_kind, 0);
    assert_eq!(rx.recv().unwrap(), (Op::Disk as u16, VERSION as u64, 2));
    assert!(!c.is_broken());
}

#[test]
fn disk_refusals() {
    // The VM refuses this side's version, or has no such disk: an errno, nothing served.
    let (mut c, _rx) = disk_server(0, -71, vec![]);
    assert!(matches!(c.select_disk(0), Err(CallError::Errno(_))));
    let (mut c, _rx) = disk_server(1, 0, hello_payload(0, false));
    assert!(matches!(c.select_disk(0), Err(CallError::Errno(_))));
    // A VM of another version answers with its own: the session breaks.
    let mut old = hello_payload(0, false);
    old[0..4].copy_from_slice(&(VERSION - 1).to_le_bytes());
    let (mut c, _rx) = disk_server(0, 0, old);
    assert!(matches!(c.select_disk(0), Err(CallError::Broken(_))));
    assert!(c.is_broken());
    // A fresh server that claims a mounted filesystem: broken.
    let (mut c, _rx) = disk_server(0, 0, hello_payload(FS_VFAT, false));
    assert!(matches!(c.select_disk(0), Err(CallError::Broken(_))));
    // A longer answer than a HELLO is refused from the header.
    let mut long = hello_payload(0, false);
    long.push(0);
    let (mut c, _rx) = disk_server(0, 0, long);
    assert!(matches!(c.select_disk(0), Err(CallError::Broken(_))));
}


/// Every protocol operation normalizes a guest handle-limit error before it reaches FUSE.
#[test]
fn emfile_mapping_covers_every_operation() {
    use fsvm_proto::Op;
    for op in [Op::Hello, Op::Lookup, Op::Getattr, Op::Readdir, Op::Read, Op::Write,
        Op::Create, Op::Mkdir, Op::Unlink, Op::Rmdir, Op::Rename, Op::Truncate, Op::SetMtime,
        Op::Statfs, Op::Fsync, Op::Forget, Op::Layout, Op::Mount, Op::Unmount, Op::Dirty,
        Op::Open, Op::Close, Op::Check, Op::Disk, Op::Format] {
        let want = if op == Op::Open { errno::EMFILE } else { errno::EIO };
        assert_eq!(errno::for_op(op, errno::EMFILE), want, "{op:?}");
    }
}
