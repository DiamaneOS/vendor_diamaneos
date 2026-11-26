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

//! The fuzz targets' corpora as regression tests: every input the fuzzers kept (corpus/proto, corpus/client,
//! corpus/fs, installed beside this test) runs through its target again, and the seeds from the protocol's encoders
//! must be accepted and the honest sessions go through. A missing corpus fails the test.

#[allow(dead_code)]
#[path = "../../fsvmd/src/fs.rs"]
mod fs;
mod fs_target;
mod seeds;
mod vm_replies;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

fn corpus(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let exe = std::env::current_exe().expect("own path");
    let mut places: Vec<PathBuf> = exe.ancestors().skip(1).take(3).map(|d| d.join("corpus").join(target)).collect();
    places.push(PathBuf::from("corpus").join(target));
    let dir = places
        .iter()
        .find(|d| d.is_dir())
        .unwrap_or_else(|| panic!("no corpus/{target} beside {} or in the working directory", exe.display()));
    let mut v: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("corpus folder")
        .map(|e| e.expect("corpus entry").path())
        .filter(|p| p.is_file())
        .map(|p| {
            let b = std::fs::read(&p).expect("corpus file");
            (p, b)
        })
        .collect();
    v.sort();
    assert!(v.len() >= 10, "corpus/{target} holds only {} inputs", v.len());
    v
}

fn replay(target: &str, f: impl Fn(&[u8])) {
    let inputs = corpus(target);
    for (path, data) in &inputs {
        if catch_unwind(AssertUnwindSafe(|| f(data))).is_err() {
            panic!("{} fails its target", path.display());
        }
    }
    println!("corpus/{target}: {} inputs replayed", inputs.len());
}

#[test]
fn proto_corpus() {
    replay("proto", |d| {
        vm_replies::decoders(d);
    });
}

#[test]
fn client_corpus() {
    replay("client", |d| {
        vm_replies::client_session(d);
    });
}

#[test]
fn fs_corpus() {
    replay("fs", |d| {
        fs_target::fs_session(d);
    });
}

#[test]
fn seeds_are_sound_and_go_deep() {
    for (target, name, data) in seeds::all() {
        match target.as_str() {
            "proto" => assert!(vm_replies::decoders(&data), "decoder seed {name} refused"),
            "client" => {
                let (answered, broken) = vm_replies::client_session(&data);
                assert!(!broken && answered == 12, "client seed {name}: {answered} answered, broken {broken}");
            }
            _ if name.starts_with("finding-") => {
                fs_target::fs_session(&data);
            }
            _ => {
                let ok = fs_target::fs_session(&data);
                assert!(ok >= 9, "FUSE seed {name}: {ok} calls succeeded");
            }
        }
    }
}
