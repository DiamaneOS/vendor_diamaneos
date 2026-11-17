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
    Deadlines { hello: Duration::from_millis(600), meta: Duration::from_millis(600), io: Duration::from_millis(600) }
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
    assert_eq!(l.entries.len(), MAX_DIR_ENTRIES);
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
        c.deadlines = Deadlines { hello: Duration::from_millis(150), meta: Duration::from_millis(150), io: Duration::from_millis(150) };
        let t = Instant::now();
        let _ = c.getattr(2);
        let _ = c.list(1);
        let _ = c.read(2, 0, 256);
        let _ = c.statfs();
        let _ = c.hello();
        assert!(t.elapsed() < Duration::from_secs(2), "seed {seed}");
    }
}
