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

//! Writes the seed inputs (../src/seeds.rs) into a corpus folder, one file per seed under proto/, client/ and fs/,
//! after running the decoder and client seeds through their targets. With a second folder, fsvmd's reports of the
//! seed layouts go there as vold's fuzzer corpus (system/vold tests/fsvm_layout_corpus).
//! `cargo run -- ../corpus [VOLD_CORPUS]`.

#[path = "../../src/seeds.rs"]
mod seeds;
#[path = "../../src/vm_replies.rs"]
mod vm_replies;

fn main() {
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: fsvm_fuzz_seeds CORPUS_DIR [VOLD_CORPUS]"));
    if let Some(v) = std::env::args().nth(2) {
        std::fs::create_dir_all(&v).expect("vold corpus folder");
        std::env::set_var("FSVM_PROBE_REPORT_DIR", v);
    }
    for (target, name, data) in seeds::all() {
        match target.as_str() {
            "proto" => assert!(vm_replies::decoders(&data), "decoder seed {name} refused"),
            "client" => {
                let (answered, broken) = vm_replies::client_session(&data);
                assert!(!broken && answered == 12, "client seed {name}: {answered} answered, broken {broken}");
            }
            _ => {}
        }
        let dir = out.join(&target);
        std::fs::create_dir_all(&dir).expect("corpus folder");
        std::fs::write(dir.join(&name), &data).expect("seed file");
        println!("{target}/{name}: {} bytes", data.len());
    }
}
