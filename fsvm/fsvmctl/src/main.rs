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

//! fsvmctl: a test client for the filesystem VM, through the same checking client fsvmd uses. Test builds only.
//!
//! ```text
//! fsvmctl CID [--disk-bytes N] [--block-size 512|4096] [--part I] [--ro] layout | hello | ls PATH | cat PATH | put LOCAL PATH | mkdir PATH |
//!         rm PATH | stat
//! ```
//! PATH is relative to the volume's root, "" or "/" for the root. `cat` writes the file to stdout. A fresh VM has
//! nothing mounted: fsvmctl reads the layout (checked against `--disk-bytes`, the image size) and mounts partition
//! `--part` (default: the first with a filesystem), read-only with `--ro`. `layout` only prints the checked layout.

use fsvm_proto::client::CallError;
use fsvm_proto::layout::guid_text;
use fsvm_proto::{Client, Deadlines, Kind, StreamTransport, MAX_IO, PORT};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process::exit;

fn connect(cid: u32) -> UnixStream {
    // SAFETY: plain socket calls on a new descriptor, checked below.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            eprintln!("socket: {}", std::io::Error::last_os_error());
            exit(2);
        }
        let mut a: libc::sockaddr_vm = std::mem::zeroed();
        a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        a.svm_cid = cid;
        a.svm_port = PORT;
        if libc::connect(fd, &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) < 0 {
            eprintln!("connect CID {cid}: {}", std::io::Error::last_os_error());
            exit(2);
        }
        UnixStream::from_raw_fd(fd)
    }
}

fn die(what: &str, e: CallError) -> ! {
    eprintln!("{what}: {e:?}");
    exit(1);
}

fn resolve(c: &mut Client<StreamTransport<UnixStream>>, root: u64, path: &str) -> (u64, Kind, u64) {
    let (mut node, mut kind, mut size) = (root, Kind::Dir, 0);
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let a = c.lookup(node, part.as_bytes()).unwrap_or_else(|e| die(part, e));
        (node, kind, size) = (a.node, a.kind, a.size);
    }
    (node, kind, size)
}

fn split(path: &str) -> (&str, &str) {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("", p),
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: fsvmctl CID [--disk-bytes N] [--block-size N] [--part I] [--ro] layout|hello|ls|cat|put|mkdir|rm|stat ...");
        exit(2);
    }
    let cid: u32 = args[1].parse().unwrap_or_else(|_| exit(2));
    let (mut disk_bytes, mut part, mut ro, mut block_size) = (0u64, None::<u32>, false, 512u32);
    while args.len() > 2 && args[2].starts_with("--") {
        let flag = args.remove(2);
        match flag.as_str() {
            "--ro" => ro = true,
            "--disk-bytes" => disk_bytes = args.remove(2).parse().unwrap_or_else(|_| exit(2)),
            "--block-size" => block_size = args.remove(2).parse().unwrap_or_else(|_| exit(2)),
            "--part" => part = Some(args.remove(2).parse().unwrap_or_else(|_| exit(2))),
            _ => exit(2),
        }
    }
    let mut c = Client::new(StreamTransport(connect(cid)), Deadlines::default());
    let mut hello = c.hello().unwrap_or_else(|e| die("hello", e));
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    if arg(2) == "layout" || hello.fs_kind == 0 {
        let t = std::time::Instant::now();
        let l = c.layout(disk_bytes, block_size).unwrap_or_else(|e| die("layout", e));
        if arg(2) == "layout" {
            println!("table {:?}, {} partitions, {} labels refused, {} ms", l.table, l.parts.len(), l.dropped_labels, t.elapsed().as_millis());
            for p in &l.parts {
                println!(
                    "part {} {:?} start {} length {} fs {} uuid {} label {:?} guid {} meta {}",
                    p.index, p.class, p.start, p.length, p.fs_kind, p.fs_uuid.as_deref().unwrap_or("-"), p.label,
                    p.part_guid.as_ref().map(guid_text).unwrap_or_else(|| "-".into()), p.meta_bytes
                );
            }
            return;
        }
        let p = match part {
            Some(i) => l.parts.iter().find(|p| p.index == i),
            None => l.parts.iter().find(|p| p.fs_kind != 0),
        }
        .unwrap_or_else(|| {
            eprintln!("no such partition with a filesystem");
            exit(1)
        });
        let t = std::time::Instant::now();
        hello = c.mount(p.index, p.start, p.length, ro, p.fs_kind, std::time::Duration::from_secs(20)).unwrap_or_else(|e| die("mount", e));
        eprintln!("mounted partition {} in {} ms", p.index, t.elapsed().as_millis());
    }
    match arg(2) {
        "hello" => println!("fs kind {} read-only {} root {}", hello.fs_kind, hello.read_only, hello.root),
        "stat" => {
            let s = c.statfs().unwrap_or_else(|e| die("statfs", e));
            println!("blocks {} free {} avail {} bsize {}", s.blocks, s.bfree, s.bavail, s.bsize);
        }
        "ls" => {
            let (node, _, _) = resolve(&mut c, hello.root, arg(3));
            let l = c.list(node).unwrap_or_else(|e| die("list", e));
            for (name, a) in &l.entries {
                println!("{} {} {} {}", if a.kind == Kind::Dir { 'd' } else { '-' }, a.size, a.mtime_s, name);
            }
            eprintln!("{} entries, {} refused, {} duplicates, truncated {}", l.entries.len(), l.dropped, l.duplicates, l.truncated);
        }
        "cat" => {
            let (node, kind, size) = resolve(&mut c, hello.root, arg(3));
            if kind != Kind::File {
                exit(1);
            }
            let mut out = std::io::stdout().lock();
            let mut off = 0u64;
            while off < size {
                let d = c.read(node, off, MAX_IO).unwrap_or_else(|e| die("read", e));
                if d.is_empty() {
                    break;
                }
                out.write_all(&d).unwrap();
                off += d.len() as u64;
            }
        }
        "put" => {
            let mut data = Vec::new();
            std::fs::File::open(arg(3)).and_then(|mut f| f.read_to_end(&mut data)).unwrap_or_else(|e| {
                eprintln!("{}: {e}", arg(3));
                exit(2)
            });
            let (dir, name) = split(arg(4));
            let (dnode, _, _) = resolve(&mut c, hello.root, dir);
            let a = c.create(dnode, name.as_bytes(), false).unwrap_or_else(|e| die("create", e));
            c.truncate(a.node, 0).unwrap_or_else(|e| die("truncate", e));
            let mut off = 0usize;
            while off < data.len() {
                let end = (off + MAX_IO as usize).min(data.len());
                let n = c.write(a.node, off as u64, &data[off..end]).unwrap_or_else(|e| die("write", e));
                if n == 0 {
                    eprintln!("write: no progress");
                    exit(1);
                }
                off += n as usize;
            }
            c.fsync(a.node, false).unwrap_or_else(|e| die("fsync", e));
            println!("wrote {} bytes", data.len());
        }
        "mkdir" => {
            let (dir, name) = split(arg(3));
            let (dnode, _, _) = resolve(&mut c, hello.root, dir);
            c.mkdir(dnode, name.as_bytes()).unwrap_or_else(|e| die("mkdir", e));
        }
        "rm" => {
            let (dir, name) = split(arg(3));
            let (dnode, _, _) = resolve(&mut c, hello.root, dir);
            let (_, kind, _) = resolve(&mut c, hello.root, arg(3));
            let r = if kind == Kind::Dir { c.rmdir(dnode, name.as_bytes()) } else { c.unlink(dnode, name.as_bytes()) };
            r.unwrap_or_else(|e| die("rm", e));
        }
        other => {
            eprintln!("unknown command {other}");
            exit(2);
        }
    }
}
