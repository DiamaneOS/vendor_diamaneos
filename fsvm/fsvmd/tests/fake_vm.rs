// Copyright (C) 2026 DiamaneOS
// SPDX-License-Identifier: Apache-2.0

use fsvm_proto::{encode_attr, encode_dir_page, Attr, Kind, MAX_IO, RSP_MAGIC};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
const ROOT_GUEST: u64 = 1;

/// An honest filesystem VM in memory, speaking the protocol as guest/fsvm_guest.c does.
pub(crate) struct FakeVm {
    pub(crate) nodes: HashMap<u64, FakeNode>,
    pub(crate) handles: HashMap<u64, u64>,
    pub(crate) next: u64,
    /// A volume mounted read-only with a check pending (CHECK): the check runs one poll, then passes.
    pub(crate) check: Option<CheckPlan>,
    /// How long each LOOKUP takes (a slow card).
    pub(crate) lookup_delay: Duration,
    /// Handles the VM keeps (guest/fsvm_guest.c MAX_HANDLES): OPEN answers EMFILE beyond.
    pub(crate) max_handles: usize,
    /// Not honest: GETATTR through a handle answers a directory.
    pub(crate) handle_attr_dir: bool,
    pub(crate) wrong_attr_op: Option<u16>,
    /// End the session after receiving this operation, before sending its answer.
    pub(crate) lose_op: Option<u16>,
    pub(crate) live_handles: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub(crate) forget_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub(crate) close_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub(crate) switch_gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub(crate) close_never_reply: bool,
    pub(crate) forget_errno: Option<i32>,
    pub(crate) first_forget_delay: Option<Duration>,
    pub(crate) close_delay: Duration,
    pub(crate) mtime_counter: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

pub(crate) struct CheckPlan {
    pub(crate) polls: u32,
    /// The VM goes away at the switch, without an answer.
    pub(crate) lose_switch: bool,
    pub(crate) switch_delay: Duration,
    /// Set when the switch was asked for.
    pub(crate) switched: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// handle()'s answer for "end the session here".
pub(crate) const GONE: i32 = -1;

pub(crate) struct FakeNode {
    pub(crate) kind: Kind,
    pub(crate) parent: u64,
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub(crate) fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl FakeVm {
    pub(crate) fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(ROOT_GUEST, FakeNode { kind: Kind::Dir, parent: ROOT_GUEST, name: Vec::new(), data: Vec::new() });
        FakeVm { nodes, handles: HashMap::new(), next: 100, check: None, lookup_delay: Duration::ZERO, max_handles: 1024, handle_attr_dir: false, wrong_attr_op: None, lose_op: None, mtime_counter: None, live_handles: None, forget_counter: None, close_counter: None, switch_gate: None, close_never_reply: false, forget_errno: None, first_forget_delay: None, close_delay: Duration::ZERO }
    }

    /// A VM whose volume holds `files` (paths below the root, directories made on the way) with their data.
    pub(crate) fn with_files(files: &[(&str, &[u8])]) -> Self {
        let mut vm = FakeVm::new();
        for (path, data) in files {
            let mut parent = ROOT_GUEST;
            let parts: Vec<&str> = path.split('/').collect();
            for (i, part) in parts.iter().enumerate() {
                let last = i + 1 == parts.len();
                parent = match vm.child(parent, part.as_bytes()) {
                    Some(id) => id,
                    None => {
                        let id = vm.next;
                        vm.next += 1;
                        let kind = if last { Kind::File } else { Kind::Dir };
                        let data = if last { data.to_vec() } else { Vec::new() };
                        vm.nodes.insert(id, FakeNode { kind, parent, name: part.as_bytes().to_vec(), data });
                        id
                    }
                };
            }
        }
        vm
    }

    pub(crate) fn attr(&self, id: u64) -> Vec<u8> {
        let n = &self.nodes[&id];
        encode_attr(&Attr { node: id, kind: n.kind, size: n.data.len() as u64, mtime_s: 1_700_000_000, mtime_ns: 0 })
            .to_vec()
    }

    /// A node whose name went: an open file keeps it, without a name, as the guest's descriptors do.
    pub(crate) fn drop_node(&mut self, id: u64) {
        if self.handles.values().any(|&n| n == id) {
            let n = self.nodes.get_mut(&id).unwrap();
            n.parent = 0;
            n.name.clear();
        } else {
            self.nodes.remove(&id);
        }
    }

    pub(crate) fn child(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.nodes.iter().find(|(&id, n)| id != ROOT_GUEST && n.parent == parent && n.name == name).map(|(&id, _)| id)
    }

    pub(crate) fn serve(mut self, mut s: UnixStream) {
        struct EndCount(Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>);
        impl Drop for EndCount {
            fn drop(&mut self) { if let Some(n) = &self.0 { n.store(0, std::sync::atomic::Ordering::SeqCst); } }
        }
        let _end_count = EndCount(self.live_handles.clone());
        loop {
            let mut h = [0u8; 48];
            if s.read_exact(&mut h).is_err() {
                return;
            }
            let (op, flags, id) = (u16::from_le_bytes([h[4], h[5]]), u16::from_le_bytes([h[6], h[7]]), le32(&h, 8));
            let (name_len, node, node2, arg, len, name2_len) =
                (le32(&h, 12) as usize, le64(&h, 16), le64(&h, 24), le64(&h, 32), le32(&h, 40), le32(&h, 44) as usize);
            let mut name = vec![0u8; name_len];
            let mut name2 = vec![0u8; name2_len];
            let mut data = vec![0u8; if op == 6 { len as usize } else { 0 }];
            if s.read_exact(&mut name).is_err() || s.read_exact(&mut name2).is_err() || s.read_exact(&mut data).is_err() {
                return;
            }
            if self.lose_op == Some(op) {
                return;
            }
            if op == 22 && self.close_never_reply {
                if let Some(n) = &self.close_counter { n.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                continue;
            }
            let target = if node2 != 0 && matches!(op, 3 | 5 | 6 | 12 | 13 | 15) { self.handles.get(&node2).copied().unwrap_or(0) } else { node };
            let mut r = self.handle(op, flags, target, node2, arg, len, &name, &name2, &data);
            if node2 != 0 && ((op == 3 && self.handle_attr_dir) || self.wrong_attr_op == Some(op)) {
                if let Ok(p) = r.as_mut() {
                    p[28] = Kind::Dir as u8;
                }
            }
            if r == Err(GONE) {
                return;
            }
            let (status, payload) = match r {
                Ok(p) => (0i32, p),
                Err(e) => (-e, Vec::new()),
            };
            let mut out = Vec::with_capacity(16 + payload.len());
            out.extend_from_slice(&RSP_MAGIC.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&status.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&payload);
            if s.write_all(&out).is_err() {
                return;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handle(
        &mut self,
        op: u16,
        flags: u16,
        node: u64,
        node2: u64,
        arg: u64,
        len: u32,
        name: &[u8],
        name2: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, i32> {
        let exists = |vm: &FakeVm, id: u64| if vm.nodes.contains_key(&id) { Ok(()) } else { Err(libc::ESTALE) };
        match op {
            // GETATTR, LOOKUP
            3 => exists(self, node).map(|_| self.attr(node)),
            2 => {
                std::thread::sleep(self.lookup_delay);
                self.child(node, name).map(|id| self.attr(id)).ok_or(libc::ENOENT)
            }
            // READDIR: pages of whole entries within the protocol's limits, the cookie the index of the next entry.
            4 => {
                exists(self, node)?;
                let mut ids: Vec<u64> =
                    self.nodes.iter().filter(|(&id, n)| n.parent == node && id != ROOT_GUEST).map(|(&id, _)| id).collect();
                ids.sort_unstable();
                let mut entries: Vec<(&[u8], Attr)> = Vec::new();
                let (mut at, mut bytes) = (arg as usize, fsvm_proto::DIR_PAGE_HEADER);
                while at < ids.len() && entries.len() < fsvm_proto::MAX_DIR_ENTRIES_PER_PAGE as usize {
                    let n = &self.nodes[&ids[at]];
                    let size = fsvm_proto::ATTR_SIZE + 2 + n.name.len();
                    if bytes + size > fsvm_proto::MAX_DIR_PAYLOAD {
                        break;
                    }
                    bytes += size;
                    let a = Attr { node: ids[at], kind: n.kind, size: n.data.len() as u64, mtime_s: 0, mtime_ns: 0 };
                    entries.push((&n.name[..], a));
                    at += 1;
                }
                Ok(encode_dir_page(if at < ids.len() { at as u64 } else { 0 }, &entries))
            }
            // READ
            5 => {
                exists(self, node)?;
                assert!(len <= MAX_IO, "fsvmd asked for {len} bytes");
                let d = &self.nodes[&node].data;
                let start = (arg as usize).min(d.len());
                let end = (start + len as usize).min(d.len());
                Ok(d[start..end].to_vec())
            }
            // WRITE
            6 => {
                exists(self, node)?;
                assert!(data.len() <= MAX_IO as usize, "fsvmd wrote {} bytes", data.len());
                let d = &mut self.nodes.get_mut(&node).unwrap().data;
                let end = arg as usize + data.len();
                if d.len() < end {
                    d.resize(end, 0);
                }
                d[arg as usize..end].copy_from_slice(data);
                let mut p = (data.len() as u32).to_le_bytes().to_vec();
                p.extend_from_slice(&[0; 4]);
                Ok(p)
            }
            // CREATE, MKDIR
            7 | 8 => {
                exists(self, node)?;
                if let Some(id) = self.child(node, name) {
                    return if op == 7 && flags & 1 == 0 { Ok(self.attr(id)) } else { Err(libc::EEXIST) };
                }
                let id = self.next;
                self.next += 1;
                let kind = if op == 7 { Kind::File } else { Kind::Dir };
                self.nodes.insert(id, FakeNode { kind, parent: node, name: name.to_vec(), data: Vec::new() });
                Ok(self.attr(id))
            }
            // UNLINK, RMDIR
            9 | 10 => {
                let id = self.child(node, name).ok_or(libc::ENOENT)?;
                if op == 10 && self.nodes.values().any(|n| n.parent == id) {
                    return Err(libc::ENOTEMPTY);
                }
                self.drop_node(id);
                Ok(Vec::new())
            }
            // RENAME
            11 => {
                let id = self.child(node, name).ok_or(libc::ENOENT)?;
                exists(self, node2)?;
                if let Some(old) = self.child(node2, name2) {
                    self.drop_node(old);
                }
                let n = self.nodes.get_mut(&id).unwrap();
                n.parent = node2;
                n.name = name2.to_vec();
                Ok(Vec::new())
            }
            // TRUNCATE, SET_MTIME
            12 => {
                exists(self, node)?;
                self.nodes.get_mut(&node).unwrap().data.resize(arg as usize, 0);
                Ok(self.attr(node))
            }
            13 => {
                if let Some(count) = &self.mtime_counter { count.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                exists(self, node).map(|_| self.attr(node))
            },
            // STATFS: 4 GiB in 4 KiB blocks.
            14 => {
                let mut p = Vec::new();
                for v in [1u64 << 20, 1 << 19, 1 << 19] {
                    p.extend_from_slice(&v.to_le_bytes());
                }
                p.extend_from_slice(&4096u32.to_le_bytes());
                p.extend_from_slice(&[0; 4]);
                Ok(p)
            }
            // FSYNC, FORGET, UNMOUNT
            15 | 19 => Ok(Vec::new()),
            16 => {
                if let Some(n) = &self.forget_counter { n.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                if let Some(delay) = self.first_forget_delay.take() { std::thread::sleep(delay); }
                if let Some(errno) = self.forget_errno { return Err(errno); }
                Ok(Vec::new())
            }
            // DIRTY
            20 => Ok(0u64.to_le_bytes().to_vec()),
            // OPEN, CLOSE
            21 => {
                exists(self, node)?;
                if self.handles.len() >= self.max_handles {
                    return Err(libc::EMFILE);
                }
                let h = self.next;
                self.next += 1;
                self.handles.insert(h, node);
                if let Some(n) = &self.live_handles { n.store(self.handles.len(), std::sync::atomic::Ordering::SeqCst); }
                Ok(h.to_le_bytes().to_vec())
            }
            22 => {
                if let Some(n) = &self.close_counter { n.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
                std::thread::sleep(self.close_delay);
                self.handles.remove(&node2);
                if let Some(n) = &self.live_handles { n.store(self.handles.len(), std::sync::atomic::Ordering::SeqCst); }
                Ok(Vec::new())
            }
            // CHECK: poll (arg 0) or switch (arg 1). Writes are refused while it is pending.
            23 => {
                let plan = self.check.as_mut().ok_or(libc::EINVAL)?;
                if arg == 0 {
                    if self.switch_gate.as_ref().is_some_and(|gate| !gate.load(std::sync::atomic::Ordering::SeqCst)) {
                        return Ok(vec![0; 8]);
                    }
                    plan.polls += 1;
                    let state: u32 = if plan.polls > 1 { 1 } else { 0 };
                    let mut p = state.to_le_bytes().to_vec();
                    p.extend_from_slice(&(plan.polls * 1000).to_le_bytes());
                    return Ok(p);
                }
                plan.switched.store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(plan.switch_delay);
                if plan.lose_switch {
                    return Err(GONE);
                }
                self.check = None;
                Ok(Vec::new())
            }
            _ => Err(libc::EINVAL),
        }
    }
}


