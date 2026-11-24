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

//! The checking client of fsvm_proto against a filesystem VM that answers from a fuzzed script
//! (vm_replies::client_session).

#![no_main]

mod vm_replies;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    vm_replies::client_session(data);
});
