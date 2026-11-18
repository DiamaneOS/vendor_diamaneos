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

/// The service holds no capabilities (fsvmd.rc `capabilities` with none), and refuses to run with any.
fn check_no_capabilities() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let mut seen = 0;
    for line in status.lines() {
        for set in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            if let Some(v) = line.strip_prefix(set) {
                ensure!(u64::from_str_radix(v.trim(), 16)? == 0, "running with capabilities ({set}), refusing");
                seen += 1;
            }
        }
    }
    ensure!(seen == 5, "capability sets missing from /proc/self/status");
    Ok(())
}

fn main() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("fsvmd_launcher").with_max_level(log::LevelFilter::Info),
    );
    if let Err(e) = check_no_capabilities().and_then(|_| launcher::run()) {
        error!("{e:?}");
        std::process::exit(1);
    }
}
