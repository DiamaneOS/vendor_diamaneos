// Copyright (C) 2026 DiamaneOS
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

/// One retry when a connection fails because its previously live VM ended.
#[derive(Default)]
pub struct DeadVmRetry {
    used: bool,
}

impl DeadVmRetry {
    pub fn after_connect_failure(&mut self, ended: bool, deadline: Instant) -> bool {
        if self.used || !ended || Instant::now() >= deadline {
            return false;
        }
        self.used = true;
        true
    }
}
