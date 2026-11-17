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

//! fsvmd: serves one removable volume (SD card, USB drive) to Android through FUSE, with the filesystem itself
//! parsed only inside a protected VM. vold starts it for each public volume:
//!
//! ```text
//! fsvmd --volume <id> --gid <gid> [--read-only] [--memory-mib <n>]
//! ```
//!
//! with three descriptors: 3, the volume's block device (vold_device), 4, the /dev/fuse descriptor vold mounted at
//! /mnt/media_rw/<uuid>, and 5, a pipe. fsvmd writes one byte `R` to the pipe once the VM serves the volume. If the
//! VM does not come up, fsvmd exits without writing and vold does not mount the volume: there is no other path.

mod fs;
mod vm;

use anyhow::{bail, ensure, Context, Result};
use fsvm_proto::{Client, Deadlines, StreamTransport, MAX_IO, PORT};
use log::{error, info};
use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::time::Duration;

const VOLUME_FD: i32 = 3;
const FUSE_FD: i32 = 4;
const READY_FD: i32 = 5;
const DEFAULT_MEMORY_MIB: i32 = 96;

struct Args {
    volume: String,
    gid: u32,
    read_only: bool,
    memory_mib: i32,
}

fn parse_args() -> Result<Args> {
    let mut a = Args { volume: String::new(), gid: u32::MAX, read_only: false, memory_mib: DEFAULT_MEMORY_MIB };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--volume" => a.volume = it.next().context("--volume")?,
            "--gid" => a.gid = it.next().context("--gid")?.parse()?,
            "--read-only" => a.read_only = true,
            "--memory-mib" => a.memory_mib = it.next().context("--memory-mib")?.parse()?,
            _ => bail!("unknown argument {arg}"),
        }
    }
    ensure!(!a.volume.is_empty() && a.gid != u32::MAX, "--volume and --gid are required");
    ensure!((64..=512).contains(&a.memory_mib), "--memory-mib out of range");
    Ok(a)
}

/// fsvmd holds no capabilities. vold starts it as the system user, and a uid change drops them.
fn check_no_capabilities() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("CapEff:") {
            ensure!(u64::from_str_radix(v.trim(), 16)? == 0, "running with capabilities, refusing");
            return Ok(());
        }
    }
    bail!("no CapEff in /proc/self/status")
}

/// Takes ownership of an inherited descriptor.
fn inherited(fd: i32) -> Result<File> {
    // SAFETY: fcntl F_GETFD only reads the descriptor flags of `fd`.
    ensure!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0, "descriptor {fd} not inherited");
    // SAFETY: vold hands these descriptors to fsvmd and nothing else in this process uses them.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn run() -> Result<()> {
    check_no_capabilities()?;
    let args = parse_args()?;
    let volume = inherited(VOLUME_FD)?;
    let fuse_dev = inherited(FUSE_FD)?;
    let mut ready = inherited(READY_FD)?;
    ensure!(volume.metadata()?.file_type().is_block_device(), "descriptor 3 is not a block device");
    ensure!(fuse_dev.metadata()?.file_type().is_char_device(), "descriptor 4 is not /dev/fuse");

    info!("volume {}: starting the filesystem VM", args.volume);
    let vm = vm::Vm::start(volume, !args.read_only, args.memory_mib)?;
    let stream = vm.connect(PORT, Duration::from_secs(15))?;
    let mut client = Client::new(StreamTransport(stream), Deadlines::default());
    let hello = client.hello().map_err(|e| anyhow::anyhow!("hello: {e:?}"))?;
    let read_only = args.read_only || hello.read_only;
    info!("volume {}: VM serves filesystem kind {}, read-only {}", args.volume, hello.fs_kind, read_only);

    ready.write_all(b"R").context("telling vold")?;
    drop(ready);

    let filesystem = fs::FsvmFs::new(client, hello.root, read_only, args.gid);
    let mut config = fuse::FuseConfig::new();
    config.dev_fuse(fuse_dev).max_read(MAX_IO).max_write(MAX_IO).num_threads(1);
    let r = config.enter_message_loop(filesystem);
    info!("volume {}: FUSE loop ended: {r:?}", args.volume);
    drop(vm);
    Ok(())
}

fn main() {
    android_logger::init_once(android_logger::Config::default().with_tag("fsvmd").with_max_level(log::LevelFilter::Info));
    if let Err(e) = run() {
        error!("{e:?}");
        std::process::exit(1);
    }
}
