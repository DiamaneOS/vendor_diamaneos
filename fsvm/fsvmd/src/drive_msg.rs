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

//! vold's requests to a drive's fsvmd (drive.rs) and their answers, checked here without any I/O so that the host
//! test (fsvmd_drive_msg_test) covers every case. vold holds its end of a SOCK_SEQPACKET socket pair (descriptor 3 of
//! `fsvmd --drive`) and sends one request per message, with its descriptors in SCM_RIGHTS, and waits for the answer
//! under its lock (system/vold fs/FsvmDrive.cpp). ASCII, fields separated by one space. Each request starts with its
//! ID (decimal, 1 to 4294967295, vold counts them), and its answer starts with the same ID: an answer vold stopped
//! waiting for never passes for the answer to a later request.
//!
//! ```text
//! <id> DISKS <n>                                + n descriptors: the drive's disks, in --disk order
//! <id> ATTACH <k> <gid> <owner-uid> <0|1 read-only> <vfat|exfat> <volume>
//!                                               + /dev/fuse (mounted by vold) and the pipe to vold
//! <id> DETACH <k> <0|1 orderly>
//! <id> FORMAT <k> <vfat|exfat>
//! <id> REPAIR <k>                               + the pipe the result goes to
//! <id> CANCEL <k>
//! ```
//!
//! Answers, one message each, after the ID: `K <errno>`, `A <k> <errno>`, `D <k> <status>` (0 written back, 3 not
//! written back, 1 never served), `F <k> <value>`, `R <k> <errno>`, `C <k> 0`. errno 0 is success. A format's value
//! is 0 with a newline and the probe text of the formatted disk after it (main.rs), FORMAT_UNVERIFIED (the format
//! tool succeeded, the new filesystem could not be read back), FORMAT_UNCERTAIN (the request to the VM broke off
//! after it was sent: whether the disk was formatted is not known), or an errno (not formatted, or the format tool
//! failed). Nothing else is ever sent to vold on this socket.

// Parts of this module serve only the host test.
#![allow(dead_code)]

use fsvm_proto::{FS_EXFAT, FS_VFAT};

/// Most disks of a drive's VM (vold's kMaxPublicPerDisk, fsvm_proto layout::MAX_DRIVE_DISKS).
pub const MAX_DISKS: usize = fsvm_proto::layout::MAX_DRIVE_DISKS;
/// The longest request: a volume ID is at most 64 bytes.
pub const MAX_REQUEST: usize = 256;
/// Most descriptors one request carries.
pub const MAX_FDS: usize = MAX_DISKS;
/// FORMAT answers besides 0 and an errno (above every errno, below vold's limit of 4095).
pub const FORMAT_UNVERIFIED: i32 = 4001;
pub const FORMAT_UNCERTAIN: i32 = 4002;
/// The result is uncertain, and the host observed the formatting VM exit.
pub const FORMAT_UNCERTAIN_STOPPED: i32 = 4003;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Disks { count: usize },
    Attach { disk: usize, gid: u32, owner_uid: u32, read_only: bool, fs: u32, volume: String },
    Detach { disk: usize, orderly: bool },
    Format { disk: usize, fs: u32 },
    Repair { disk: usize },
    Cancel { disk: usize },
}

impl Request {
    /// The descriptors the request must carry.
    pub fn fds(&self) -> usize {
        match self {
            Request::Disks { count } => *count,
            Request::Attach { .. } => 2,
            Request::Repair { .. } => 1,
            _ => 0,
        }
    }
}

fn number<T: std::str::FromStr>(s: &str) -> Result<T, String> {
    // Plain decimal digits only: no sign, no spaces, no leading zeros beyond "0" itself.
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err(format!("not a number: {s:?}"));
    }
    s.parse().map_err(|_| format!("out of range: {s}"))
}

fn flag(s: &str) -> Result<bool, String> {
    match s {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(format!("not 0 or 1: {s:?}")),
    }
}

fn fs_kind(s: &str) -> Result<u32, String> {
    match s {
        "vfat" => Ok(FS_VFAT),
        "exfat" => Ok(FS_EXFAT),
        _ => Err(format!("not a filesystem: {s:?}")),
    }
}

/// A volume or disk ID as vold makes them (`public:179,1`, `disk:179,0`): only for the logs and `ps`.
pub fn name(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 64 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b":,_-".contains(&b)) {
        return Err("not a volume ID".into());
    }
    Ok(s.to_string())
}

/// Parses and checks one request of `bytes` that came with `fds` descriptors, for a drive of `disks` disks (`disks`
/// 0 before DISKS, which must come first and only once: the caller tracks that). Returns its ID and the request.
pub fn parse(bytes: &[u8], fds: usize, disks: usize) -> Result<(u32, Request), String> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST {
        return Err(format!("{} bytes", bytes.len()));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not text".to_string())?;
    let (id, text) = text.split_once(' ').ok_or_else(|| "no request ID".to_string())?;
    let id: u32 = number(id)?;
    if id == 0 {
        return Err("request ID 0".into());
    }
    let f: Vec<&str> = text.split(' ').collect();
    let disk = |s: &str| -> Result<usize, String> {
        let k: usize = number(s)?;
        if k >= disks {
            return Err(format!("disk {k} of {disks}"));
        }
        Ok(k)
    };
    let r = match (f[0], f.len()) {
        ("DISKS", 2) => {
            let count: usize = number(f[1])?;
            if disks != 0 || count == 0 || count > MAX_DISKS {
                return Err(format!("{count} disks"));
            }
            Request::Disks { count }
        }
        ("ATTACH", 7) => Request::Attach {
            disk: disk(f[1])?,
            gid: number(f[2])?,
            owner_uid: number(f[3])?,
            read_only: flag(f[4])?,
            fs: fs_kind(f[5])?,
            volume: name(f[6])?,
        },
        ("DETACH", 3) => Request::Detach { disk: disk(f[1])?, orderly: flag(f[2])? },
        ("FORMAT", 3) => Request::Format { disk: disk(f[1])?, fs: fs_kind(f[2])? },
        ("REPAIR", 2) => Request::Repair { disk: disk(f[1])? },
        ("CANCEL", 2) => Request::Cancel { disk: disk(f[1])? },
        _ => return Err(format!("unknown request {:?}", f[0])),
    };
    if !matches!(r, Request::Disks { .. }) && disks == 0 {
        return Err("a request before DISKS".into());
    }
    if r.fds() != fds {
        return Err(format!("{fds} descriptors where {} belong", r.fds()));
    }
    Ok((id, r))
}

/// The answer to request `id`, `r`: the ID, its letter, the disk, and `value` (an errno, a DETACH status or a FORMAT
/// value).
pub fn answer(id: u32, r: &Request, value: i32) -> String {
    match r {
        Request::Disks { .. } => format!("{id} K {value}"),
        Request::Attach { disk, .. } => format!("{id} A {disk} {value}"),
        Request::Detach { disk, .. } => format!("{id} D {disk} {value}"),
        Request::Format { disk, .. } => format!("{id} F {disk} {value}"),
        Request::Repair { disk } => format!("{id} R {disk} {value}"),
        Request::Cancel { disk } => format!("{id} C {disk} {value}"),
    }
}

/// One `--disk <bytes>:<vfat|exfat|->:<meta-bytes>` of `fsvmd --drive`: a public partition of the drive, as a disk of
/// its own (its range on Android), with the filesystem the probe found and the metadata that sizes the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpec {
    pub bytes: u64,
    pub fs: u32,
    pub meta_bytes: u64,
}

pub fn parse_disk(s: &str) -> Result<DiskSpec, String> {
    let f: Vec<&str> = s.split(':').collect();
    if f.len() != 3 {
        return Err(format!("--disk {s}"));
    }
    let digits = |x: &str| -> Result<u64, String> {
        if x.is_empty() || x.len() > 20 || !x.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("--disk {s}"));
        }
        x.parse().map_err(|_| format!("--disk {s}"))
    };
    let bytes = digits(f[0])?;
    if bytes < 512 || bytes % 512 != 0 {
        return Err(format!("--disk {s}: not whole sectors"));
    }
    let fs = if f[1] == "-" { 0 } else { fs_kind(f[1])? };
    Ok(DiskSpec { bytes, fs, meta_bytes: digits(f[2])? })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request alone, for the checks below that are not about its ID.
    fn parse(bytes: &[u8], fds: usize, disks: usize) -> Result<Request, String> {
        let mut with_id = b"7 ".to_vec();
        with_id.extend_from_slice(bytes);
        super::parse(&with_id, fds, disks).map(|(id, r)| {
            assert_eq!(id, 7);
            r
        })
    }

    #[test]
    fn requests() {
        assert_eq!(parse(b"DISKS 2", 2, 0), Ok(Request::Disks { count: 2 }));
        assert_eq!(
            parse(b"ATTACH 1 1023 10075 0 vfat public:179,2", 2, 2),
            Ok(Request::Attach { disk: 1, gid: 1023, owner_uid: 10075, read_only: false, fs: FS_VFAT, volume: "public:179,2".into() })
        );
        assert_eq!(parse(b"DETACH 0 1", 0, 2), Ok(Request::Detach { disk: 0, orderly: true }));
        assert_eq!(parse(b"FORMAT 1 exfat", 0, 2), Ok(Request::Format { disk: 1, fs: FS_EXFAT }));
        assert_eq!(parse(b"REPAIR 0", 1, 1), Ok(Request::Repair { disk: 0 }));
        assert_eq!(parse(b"CANCEL 0", 0, 1), Ok(Request::Cancel { disk: 0 }));
    }

    /// Every request carries an ID, and its answer the same one: a late answer cannot pass for a later request's.
    #[test]
    fn request_ids() {
        assert_eq!(super::parse(b"1 FORMAT 0 vfat", 0, 1), Ok((1, Request::Format { disk: 0, fs: FS_VFAT })));
        assert_eq!(super::parse(b"4294967295 CANCEL 0", 0, 1), Ok((u32::MAX, Request::Cancel { disk: 0 })));
        assert!(super::parse(b"FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"0 FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"01 FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"-1 FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"4294967296 FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"1  FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"x FORMAT 0 vfat", 0, 1).is_err());
        assert!(super::parse(b"1", 0, 1).is_err());
        let (a, b) = (super::parse(b"5 FORMAT 0 vfat", 0, 1).unwrap(), super::parse(b"6 FORMAT 0 vfat", 0, 1).unwrap());
        assert_ne!(answer(a.0, &a.1, 0), answer(b.0, &b.1, 0));
        assert_eq!(answer(6, &b.1, FORMAT_UNCERTAIN), "6 F 0 4002");
        assert_eq!(answer(6, &b.1, FORMAT_UNCERTAIN_STOPPED), "6 F 0 4003");
    }

    #[test]
    fn refused() {
        // DISKS first and once, at most MAX_DISKS.
        assert!(parse(b"ATTACH 0 1023 0 0 vfat public:179,1", 2, 0).is_err());
        assert!(parse(b"DISKS 2", 2, 2).is_err());
        assert!(parse(b"DISKS 0", 0, 0).is_err());
        assert!(parse(b"DISKS 5", 5, 0).is_err());
        // A disk the drive does not have.
        assert!(parse(b"DETACH 2 1", 0, 2).is_err());
        assert!(parse(b"REPAIR 4", 1, 2).is_err());
        // Descriptors must match.
        assert!(parse(b"ATTACH 0 1023 0 0 vfat public:179,1", 1, 1).is_err());
        assert!(parse(b"ATTACH 0 1023 0 0 vfat public:179,1", 3, 1).is_err());
        assert!(parse(b"DETACH 0 1", 1, 1).is_err());
        assert!(parse(b"DISKS 2", 1, 0).is_err());
        assert!(parse(b"REPAIR 0", 0, 1).is_err());
        // Malformed fields.
        assert!(parse(b"DETACH 0 2", 0, 1).is_err());
        assert!(parse(b"DETACH -0 1", 0, 1).is_err());
        assert!(parse(b"DETACH 00 1", 0, 1).is_err());
        assert!(parse(b"DETACH +0 1", 0, 1).is_err());
        assert!(parse(b"DETACH 0 1 ", 0, 1).is_err());
        assert!(parse(b"DETACH  0 1", 0, 1).is_err());
        assert!(parse(b"FORMAT 0 ntfs", 0, 1).is_err());
        assert!(parse(b"ATTACH 0 1023 0 0 - public:179,1", 2, 1).is_err());
        assert!(parse(b"ATTACH 0 99999999999 0 0 vfat public:179,1", 2, 1).is_err());
        assert!(parse(b"ATTACH 0 1023 0 0 vfat ../x", 2, 1).is_err());
        assert!(parse(b"ATTACH 0 1023 0 0 vfat a\nb", 2, 1).is_err());
        assert!(parse("ATTACH 0 1023 0 0 vfat pübl".as_bytes(), 2, 1).is_err());
        assert!(parse(b"DETACH", 0, 1).is_err());
        assert!(parse(b"", 0, 1).is_err());
        assert!(parse(&[b'D'; MAX_REQUEST + 1], 0, 1).is_err());
        assert!(parse(b"KILL 0", 0, 1).is_err());
        assert!(parse(&[0xff, 0xfe], 0, 1).is_err());
    }

    #[test]
    fn answers() {
        assert_eq!(answer(1, &Request::Disks { count: 1 }, 0), "1 K 0");
        assert_eq!(answer(2, &Request::Detach { disk: 1, orderly: true }, 3), "2 D 1 3");
        assert_eq!(answer(3, &Request::Attach { disk: 0, gid: 0, owner_uid: 0, read_only: false, fs: 1, volume: "v".into() }, 11), "3 A 0 11");
        assert_eq!(answer(4, &Request::Format { disk: 2, fs: 1 }, 0), "4 F 2 0");
        assert_eq!(answer(5, &Request::Repair { disk: 0 }, 16), "5 R 0 16");
        assert_eq!(answer(6, &Request::Cancel { disk: 3 }, 0), "6 C 3 0");
        assert_eq!(answer(7, &Request::Format { disk: 0, fs: 1 }, FORMAT_UNVERIFIED), "7 F 0 4001");
    }

    #[test]
    fn names() {
        assert_eq!(name("disk:179,0"), Ok("disk:179,0".into()));
        assert!(name("").is_err());
        assert!(name("disk 1").is_err());
        assert!(name(&"d".repeat(65)).is_err());
    }

    #[test]
    fn disks() {
        assert_eq!(parse_disk("1048576:vfat:4096"), Ok(DiskSpec { bytes: 1 << 20, fs: FS_VFAT, meta_bytes: 4096 }));
        assert_eq!(parse_disk("512:-:0"), Ok(DiskSpec { bytes: 512, fs: 0, meta_bytes: 0 }));
        assert_eq!(parse_disk("1024:exfat:0").unwrap().fs, FS_EXFAT);
        assert!(parse_disk("1000:vfat:0").is_err());
        assert!(parse_disk("0:vfat:0").is_err());
        assert!(parse_disk("1024:ntfs:0").is_err());
        assert!(parse_disk("1024:vfat").is_err());
        assert!(parse_disk("1024:vfat:0:1").is_err());
        assert!(parse_disk("-1024:vfat:0").is_err());
        assert!(parse_disk("1024:vfat: 1").is_err());
    }
}
