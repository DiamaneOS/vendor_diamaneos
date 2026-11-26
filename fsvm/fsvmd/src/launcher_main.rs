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

//! fsvmd_launcher: the fsvmd service init runs (fsvmd.rc). See launcher.rs.

mod launcher;

use anyhow::{ensure, Result};
use log::error;

/// CAP_SYS_NICE: the VM manager and crosvm in the virtualization APEX carry it as a file capability with the effective
/// bit (its canned_fs_config), and the kernel refuses to execute such a file (EPERM) when the bounding set lacks it.
/// So it is the one capability the bounding set keeps (fsvmd.rc `capabilities SYS_NICE`). Every other set is empty.
const BOUNDING: u64 = 1 << 23;

/// init raises the service's capabilities (fsvmd.rc) as ambient ones. The service drops them from every set but the
/// bounding set at once, so it and every fsvmd it starts run without any.
fn drop_capabilities() -> Result<()> {
    // SAFETY: prctl with these arguments only clears this process's ambient set.
    let r = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    ensure!(r == 0, "clearing the ambient capabilities: {}", std::io::Error::last_os_error());
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header { version: 0x2008_0522, pid: 0 }; // _LINUX_CAPABILITY_VERSION_3
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: capset reads the header and two data structs of capability version 3, both valid for the call.
    let r = unsafe { libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) };
    ensure!(r == 0, "dropping the capabilities: {}", std::io::Error::last_os_error());
    Ok(())
}

/// Every capability set is empty but the bounding set, which holds BOUNDING only.
fn check_capabilities(status: &str) -> Result<()> {
    let mut seen = 0;
    for line in status.lines() {
        for set in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            if let Some(v) = line.strip_prefix(set) {
                let want = if set == "CapBnd:" { BOUNDING } else { 0 };
                ensure!(u64::from_str_radix(v.trim(), 16)? == want, "running with capabilities ({set}{v}), refusing");
                seen += 1;
            }
        }
    }
    ensure!(seen == 5, "capability sets missing from /proc/self/status");
    Ok(())
}

/// `--slot <slot>`, the one argument fsvmd.rc passes.
fn slot() -> Result<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(args.len() == 2 && args[0] == "--slot", "usage: fsvmd_launcher --slot <slot>");
    Ok(args[1].clone())
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("fsvmd_launcher").with_max_level(log::LevelFilter::Info),
    );
    let started = drop_capabilities()
        .and_then(|_| check_capabilities(&std::fs::read_to_string("/proc/self/status")?))
        .and_then(|_| slot())
        .and_then(|slot| launcher::run(&slot));
    if let Err(e) = started {
        error!("{e:?}");
        std::process::exit(1);
    }
}
