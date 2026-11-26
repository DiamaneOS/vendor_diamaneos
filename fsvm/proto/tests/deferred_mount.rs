//! Normal deferred mounts retain only successful FAT timing for the serving client's repair decision.
use fsvm_proto::*;
use fsvm_proto::client::CallError;
use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

struct Replies { cases: VecDeque<(u32, i32)>, bytes: VecDeque<u8> }
impl Transport for Replies {
    fn send_by(&mut self, request: &[u8], _: Instant) -> io::Result<()> {
        let (kind, status) = self.cases.pop_front().unwrap();
        let id = u32::from_le_bytes(request[8..12].try_into().unwrap());
        let mut payload = Vec::new();
        if status == 0 {
            for n in [VERSION, kind, 0, 0] { payload.extend_from_slice(&n.to_le_bytes()); }
            payload.extend_from_slice(&1u64.to_le_bytes());
        }
        self.bytes.extend(RSP_MAGIC.to_le_bytes());
        self.bytes.extend(id.to_le_bytes());
        self.bytes.extend(status.to_le_bytes());
        self.bytes.extend((payload.len() as u32).to_le_bytes());
        self.bytes.extend(payload);
        Ok(())
    }
    fn recv_by(&mut self, out: &mut [u8], _: Instant) -> io::Result<()> {
        std::thread::sleep(Duration::from_millis(2));
        for byte in out { *byte = self.bytes.pop_front().unwrap(); }
        Ok(())
    }
}
fn client(cases: &[(u32, i32)]) -> Client<Replies> {
    Client::new(Replies { cases: cases.iter().copied().collect(), bytes: VecDeque::new() }, Deadlines::default())
}
#[test]
fn successful_fat_only_and_reuse_clears_old_timing() {
    let mut c = client(&[(FS_VFAT, 0), (FS_EXFAT, 0), (FS_VFAT, -5), (FS_VFAT, 0)]);
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
    c.mount_check_later(0, 0, 2_097_152_000, FS_VFAT).unwrap();
    assert!(c.deferred_fat_mount_elapsed >= Duration::from_millis(2));
    c.mount_check_later(0, 0, 2_097_152_000, FS_EXFAT).unwrap();
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
    c.deferred_fat_mount_elapsed = Duration::from_secs(99);
    assert!(matches!(c.mount_check_later(0, 0, 2_097_152_000, FS_VFAT), Err(CallError::Errno(5))));
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
    c.deferred_fat_mount_elapsed = Duration::from_secs(99);
    c.mount(0, 0, 2_097_152_000, false, FS_VFAT, Duration::from_secs(8)).unwrap();
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
}
#[test]
fn failed_unsent_and_replacement_mounts_do_not_retain_timing() {
    let mut c = client(&[(FS_VFAT, 0)]);
    c.deferred_fat_mount_elapsed = Duration::from_secs(99);
    c.op_deadline = Some(Instant::now());
    assert!(matches!(c.mount_check_later(0, 0, 2_097_152_000, FS_VFAT), Err(CallError::OutOfTime)));
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
    c.op_deadline = None;
    assert!(matches!(c.mount_check_later(0, 0, 2_097_152_000, FS_EXFAT), Err(CallError::Broken(_))));
    assert_eq!(c.deferred_fat_mount_elapsed, Duration::ZERO);
    let fresh = client(&[(FS_VFAT, 0)]);
    assert_eq!(fresh.deferred_fat_mount_elapsed, Duration::ZERO);
}
