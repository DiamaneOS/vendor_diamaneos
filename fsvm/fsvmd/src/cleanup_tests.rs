// Copyright (C) 2026 DiamaneOS
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::{Read, Write};

struct Ended;
impl Session for Ended {
    fn restart(&mut self, _deadline: Instant) -> anyhow::Result<(Client<StreamTransport<UnixStream>>, Hello)> {
        anyhow::bail!("failed cleanup must not restart")
    }
    fn stop_vm(&mut self, _within: Duration) {}
    fn give_up(&mut self) {}
}

#[test]
fn shutdown_retains_unacknowledged_handle_custody() {
    let (a, mut peer) = UnixStream::pair().unwrap();
    let (eof_tx, eof) = mpsc::channel();
    let (finish, resume) = mpsc::channel();
    let guest = std::thread::spawn(move || {
        let handles = [17u64];
        let mut request = [0; 48];
        peer.read_exact(&mut request).unwrap();
        assert_eq!(u16::from_le_bytes(request[4..6].try_into().unwrap()), 22);
        // Withhold CLOSE and keep the handle after EOF until guest-side teardown is allowed.
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        eof_tx.send(handles[0]).unwrap();
        resume.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    let deadlines = fsvm_proto::Deadlines { meta: Duration::from_millis(10), io: Duration::from_millis(10), mutate: Duration::from_millis(10), ..Default::default() };
    let fs = FsvmFs::new(Client::new(StreamTransport(a), deadlines), 1, false, false, 0, false, false, Box::new(Ended));
    fs.state.lock().unwrap().remote_cleanup.push_back(RemoteCleanup::Close { generation: 0, handle: 17 });
    fs.cleanup.kick();
    assert_eq!(eof.recv_timeout(Duration::from_secs(2)).unwrap(), 17);
    let pending = {
        let state = fs.state.lock().unwrap();
        assert!(state.failed);
        state.remote_cleanup.front().copied()
    };
    finish.send(()).unwrap();
    guest.join().unwrap();
    drop(fs);
    assert!(matches!(pending, Some(RemoteCleanup::Close { generation: 0, handle: 17 })),
        "local shutdown discarded custody before the guest closed its handle");
}


#[test]
fn resource_pressure_refuses_create_and_mkdir_before_guest_mutation() {
    use fuse::filesystem::{Context, FileSystem};
    for nodes_full in [true, false] {
        let (a, mut peer) = UnixStream::pair().unwrap();
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests = observed.clone();
        let guest = std::thread::spawn(move || {
            let mut header = [0; 48];
            if peer.read_exact(&mut header).is_ok() { requests.fetch_add(1, Ordering::SeqCst); }
        });
        let fs = FsvmFs::new(Client::new(StreamTransport(a), fsvm_proto::Deadlines::default()),
            1, false, false, 0, false, false, Box::new(Ended));
        {
            let mut state = fs.state.lock().unwrap();
            if nodes_full {
                for id in 2..=32768 {
                    state.map(ROOT, format!("held{id}").as_bytes(), &Attr {
                        node: id, kind: Kind::File, size: 0, mtime_s: 0, mtime_ns: 0,
                    }).unwrap();
                }
            } else {
                for id in 1..=8192 { state.files.insert(id, OpenFile { generation: 0, guest: id, kind: Kind::File }); }
            }
        }
        let ctx = Context { uid: 0, gid: 0, pid: 1 };
        let create = fs.create(ctx, ROOT, c"new", 0o600, libc::O_RDWR as u32, 0, None);
        let create_errno = create.err().and_then(|e| e.raw_os_error());
        let mkdir_errno = if nodes_full {
            fs.mkdir(ctx, ROOT, c"dir", 0o700, 0, None).err().and_then(|e| e.raw_os_error())
        } else { None };
        drop(fs);
        guest.join().unwrap();
        assert_eq!(observed.load(Ordering::SeqCst), 0, "pressure reached a guest mutation");
        assert_eq!(create_errno, Some(if nodes_full { libc::EAGAIN } else { libc::EMFILE }));
        if nodes_full { assert_eq!(mkdir_errno, Some(libc::EAGAIN)); }
    }
}

#[test]
fn full_node_table_allows_a_validated_existing_lookup() {
    use fuse::filesystem::{Context, FileSystem};
    use fsvm_proto::{encode_attr, Op, RSP_MAGIC};

    let (a, mut peer) = UnixStream::pair().unwrap();
    let guest = std::thread::spawn(move || {
        for (name, node) in [(b"held2".as_slice(), 2), (b"new".as_slice(), 32769)] {
            let mut header = [0; 48];
            if peer.read_exact(&mut header).is_err() { return; }
            assert_eq!(u16::from_le_bytes(header[4..6].try_into().unwrap()), Op::Lookup as u16);
            let mut requested = vec![0; u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize];
            peer.read_exact(&mut requested).unwrap();
            assert_eq!(requested, name);
            let attr = encode_attr(&Attr { node, kind: Kind::File, size: 0, mtime_s: 0, mtime_ns: 0 });
            peer.write_all(&RSP_MAGIC.to_le_bytes()).unwrap();
            peer.write_all(&header[8..12]).unwrap();
            peer.write_all(&0u32.to_le_bytes()).unwrap();
            peer.write_all(&(attr.len() as u32).to_le_bytes()).unwrap();
            peer.write_all(&attr).unwrap();
        }
    });
    let fs = FsvmFs::new(Client::new(StreamTransport(a), fsvm_proto::Deadlines::default()),
        1, false, false, 0, false, false, Box::new(Ended));
    let existing = {
        let mut state = fs.state.lock().unwrap();
        for node in 2..=32768 {
            state.map(ROOT, format!("held{node}").as_bytes(),
                &Attr { node, kind: Kind::File, size: 0, mtime_s: 0, mtime_ns: 0 }).unwrap();
        }
        state.by_name[&(ROOT, b"held2".to_vec())]
    };
    let ctx = Context { uid: 0, gid: 0, pid: 1 };
    let repeat = fs.lookup(ctx, ROOT, c"held2").map(|entry| entry.inode);
    let new = fs.lookup(ctx, ROOT, c"new").err().and_then(|e| e.raw_os_error());
    let create = fs.create(ctx, ROOT, c"new", 0o600, libc::O_RDWR as u32, 0, None)
        .err().and_then(|e| e.raw_os_error());
    assert_eq!(fs.state.lock().unwrap().nodes.len(), 32768);
    drop(fs);
    guest.join().unwrap();
    assert_eq!(repeat.unwrap(), existing);
    assert_eq!(new, Some(libc::EAGAIN));
    assert_eq!(create, Some(libc::EAGAIN));
}
