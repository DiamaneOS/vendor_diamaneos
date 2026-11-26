// Copyright (C) 2026 DiamaneOS
// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[path = "../src/fs.rs"]
mod fs;
#[allow(dead_code)]
mod fake_vm;
mod cleanup_dispatch;

fn main() {
    match cleanup_dispatch::run().and_then(|()| cleanup_dispatch::run_rereview()) {
        Ok(()) => println!("FSVMD-CLEANUP-DISPATCH-PASS"),
        Err(e) => { eprintln!("FSVMD-CLEANUP-DISPATCH-FAIL: {e}"); std::process::exit(1); }
    }
}
