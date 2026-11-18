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

//! fsvmd: SD cards, USB drives and OBB images for Android, with their partition tables and filesystems parsed only
//! inside a protected VM. vold starts it in one of three modes:
//!
//! ```text
//! fsvmd --probe --disk-bytes <n>
//! fsvmd --volume <id> --gid <gid> --disk-bytes <n> --partition <i> --start <s> --length <l> --fs <vfat|exfat|->
//!       --meta-bytes <m> [--read-only]
//! fsvmd --obb --volume <id> --gid <gid> --disk-bytes <n>
//! ```
//!
//! Descriptors: 3 is the whole disk (a vold block device) or the OBB file, read-only for probe and OBB. 4 is the
//! /dev/fuse descriptor vold mounted (not for probe). 5 is a pipe to vold.
//!
//! - Probe: the VM reads the partition table. fsvmd checks the layout (fsvm_proto::layout) and writes it to the pipe
//!   in the line format below, then stops the VM. vold creates volumes from it, and adds the one adoptable storage
//!   partition to Android's kernel from it.
//! - Serve: the VM mounts one partition, which must still be where the probe found it, and fsvmd serves it through
//!   FUSE. It writes one byte `R` to the pipe once the VM serves the volume.
//! - OBB: the same for an app's OBB image, read-only, which must be a filesystem without a partition table.
//!
//! If the VM does not come up or anything it says is refused, fsvmd exits without writing and vold does not mount
//! the volume: there is no other path.
//!
//! Probe output, ASCII, one record per line, fields separated by one space, at most 16 partitions:
//!
//! ```text
//! LAYOUT 1 <none|mbr|gpt> <count>
//! PART <index> <public|meta|expand> <start> <length> <vfat|exfat|-> <uuid|-> <part-guid|-> <meta-bytes> <label-hex|->
//! END
//! ```

mod fs;
mod vm;

use anyhow::{anyhow, bail, ensure, Context, Result};
use fsvm_proto::layout::{self, Class, Table};
use fsvm_proto::{Client, Deadlines, StreamTransport, FS_EXFAT, FS_VFAT, MAX_IO, PORT};
use log::{error, info, warn};
use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const DISK_FD: i32 = 3;
const FUSE_FD: i32 = 4;
const PIPE_FD: i32 = 5;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Probe,
    Serve,
    Obb,
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    volume: String,
    gid: u32,
    read_only: bool,
    disk_bytes: u64,
    partition: u32,
    start: u64,
    length: u64,
    fs: u32,
    meta_bytes: u64,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        mode: Mode::Serve,
        volume: String::new(),
        gid: u32::MAX,
        read_only: false,
        disk_bytes: 0,
        partition: u32::MAX,
        start: 0,
        length: 0,
        fs: u32::MAX,
        meta_bytes: 0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().with_context(|| arg.clone());
        match arg.as_str() {
            "--probe" => a.mode = Mode::Probe,
            "--obb" => a.mode = Mode::Obb,
            "--volume" => a.volume = val()?,
            "--gid" => a.gid = val()?.parse()?,
            "--read-only" => a.read_only = true,
            "--disk-bytes" => a.disk_bytes = val()?.parse()?,
            "--partition" => a.partition = val()?.parse()?,
            "--start" => a.start = val()?.parse()?,
            "--length" => a.length = val()?.parse()?,
            "--meta-bytes" => a.meta_bytes = val()?.parse()?,
            "--fs" => {
                a.fs = match val()?.as_str() {
                    "vfat" => FS_VFAT,
                    "exfat" => FS_EXFAT,
                    "-" => 0,
                    other => bail!("--fs {other}"),
                }
            }
            _ => bail!("unknown argument {arg}"),
        }
    }
    ensure!(a.disk_bytes > 0 && a.disk_bytes % 512 == 0, "--disk-bytes must be a positive multiple of 512");
    match a.mode {
        Mode::Probe => {}
        Mode::Serve => ensure!(
            !a.volume.is_empty() && a.gid != u32::MAX && a.partition != u32::MAX && a.length > 0 && a.fs != u32::MAX,
            "--volume, --gid, --partition, --start, --length and --fs are required"
        ),
        Mode::Obb => ensure!(!a.volume.is_empty() && a.gid != u32::MAX, "--volume and --gid are required"),
    }
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

/// Takes ownership of an inherited descriptor and marks it close-on-exec, so that the VM manager fsvmd starts gets
/// only what fsvmd passes it over binder.
fn inherited(fd: i32) -> Result<File> {
    // SAFETY: fcntl F_GETFD only reads the descriptor flags of `fd`.
    ensure!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0, "descriptor {fd} not inherited");
    // SAFETY: F_SETFD only changes the descriptor flags of `fd`.
    ensure!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0, "descriptor {fd}: F_SETFD");
    // SAFETY: vold hands these descriptors to fsvmd and nothing else in this process uses them.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The open flags of a descriptor. Probe and OBB disks must be read-only.
fn access_mode(f: &File) -> Result<i32> {
    use std::os::fd::AsRawFd;
    // SAFETY: fcntl F_GETFL only reads the status flags of a descriptor this process owns.
    let fl = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
    ensure!(fl >= 0, "F_GETFL: {}", std::io::Error::last_os_error());
    Ok(fl & libc::O_ACCMODE)
}

type VmClient = Client<StreamTransport<UnixStream>>;

/// vold waits 23 s for a probe and 33 s for a mount, and holds its lock meanwhile (system/vold fs/Fsvm.cpp), so
/// fsvmd finishes within these, whatever the VM does.
const PROBE_BUDGET: Duration = Duration::from_secs(20);
const SERVE_BUDGET: Duration = Duration::from_secs(30);
/// At most this long for a writable mount's filesystem check, within the budget.
const CHECK_MAX: Duration = Duration::from_secs(14);
/// Kept for the mount itself and the first free-space count.
const MOUNT_MIN: Duration = Duration::from_secs(8);

fn left(deadline: Instant) -> Result<Duration> {
    let now = Instant::now();
    ensure!(now < deadline, "out of time");
    Ok(deadline - now)
}

/// Starts the VM, connects and checks the protocol version, all before `deadline`. A VM that cannot start is retried
/// a few times: a protected VM start can be refused while memory is scattered, right after boot.
fn start_vm(disk: &File, writable: bool, memory_mib: u32, deadline: Instant) -> Result<(vm::Vm, VmClient)> {
    let mut last = anyhow!("not started");
    for (attempt, wait) in [0u64, 1, 2].into_iter().enumerate() {
        if wait > 0 {
            if left(deadline)? <= Duration::from_secs(wait + 5) {
                break;
            }
            std::thread::sleep(Duration::from_secs(wait));
        }
        let vm = match vm::Vm::start(disk.try_clone()?, writable, memory_mib) {
            Ok(vm) => vm,
            Err(e) => {
                warn!("filesystem VM start {} failed: {e:?}", attempt + 1);
                last = e;
                continue;
            }
        };
        let stream = vm.connect(PORT, left(deadline)?.min(Duration::from_secs(8)))?;
        let mut deadlines = Deadlines::default();
        deadlines.hello = deadlines.hello.min(left(deadline)?);
        let mut client = Client::new(StreamTransport(stream), deadlines);
        let hello = client.hello().map_err(|e| anyhow!("hello: {e:?}"))?;
        ensure!(hello.fs_kind == 0, "a fresh VM claims a mounted filesystem");
        return Ok((vm, client));
    }
    Err(last)
}

fn probe(args: &Args, disk: File, mut pipe: File) -> Result<()> {
    ensure!(access_mode(&disk)? == libc::O_RDONLY, "the probe disk must be read-only");
    let deadline = Instant::now() + PROBE_BUDGET;
    let (vm, mut client) = start_vm(&disk, false, layout::PROBE_MIB, deadline)?;
    client.deadlines.hello = client.deadlines.hello.min(left(deadline)?);
    let l = client.layout(args.disk_bytes).map_err(|e| anyhow!("layout: {e:?}"))?;
    drop(vm);
    if l.dropped_labels > 0 {
        warn!("{} volume labels refused", l.dropped_labels);
    }
    info!("disk layout: {:?}, {} partitions", l.table, l.parts.len());
    pipe.write_all(layout::probe_text(&l).as_bytes()).context("telling vold")?;
    Ok(())
}

/// One served volume: what it takes to bring a VM up for it, first at mount and again when a session breaks.
struct Served {
    disk: File,
    obb: bool,
    read_only: bool,
    memory: u32,
    disk_bytes: u64,
    partition: u32,
    start: u64,
    length: u64,
    fs: u32,
    volume: String,
    vm: Option<vm::Vm>,
}

impl Served {
    /// Starts a VM, checks the partition is still where the probe found it, checks and mounts it.
    fn bring_up(&mut self, budget: Duration) -> Result<(VmClient, fsvm_proto::Hello)> {
        // The old VM goes first, so that its memory is free for the new one.
        self.vm = None;
        let deadline = Instant::now() + budget;
        info!("volume {}: starting the filesystem VM with {} MiB", self.volume, self.memory);
        let (vm, mut client) = start_vm(&self.disk, !self.read_only, self.memory, deadline)?;
        client.deadlines.hello = client.deadlines.hello.min(left(deadline)?);
        let l = client.layout(self.disk_bytes).map_err(|e| anyhow!("layout: {e:?}"))?;
        let part = if self.obb {
            ensure!(l.table == Table::None && l.parts.len() == 1, "an OBB must be one filesystem without a partition table");
            l.parts[0].clone()
        } else {
            l.parts
                .iter()
                .find(|p| p.index == self.partition && p.start == self.start && p.length == self.length)
                .cloned()
                .ok_or_else(|| anyhow!("partition {} is no longer where the probe found it", self.partition))?
        };
        ensure!(part.class == Class::Public, "partition {} is not a public volume", part.index);
        ensure!(part.fs_kind != 0, "no FAT or exFAT filesystem on partition {}", part.index);
        ensure!(self.obb || self.fs == 0 || part.fs_kind == self.fs, "the filesystem changed since the probe");
        let remaining = left(deadline)?;
        ensure!(remaining > MOUNT_MIN, "no time left to mount");
        let check = if self.read_only { Duration::ZERO } else { CHECK_MAX.min(remaining - MOUNT_MIN) };
        client.deadlines.mount = remaining - check;
        let hello = client
            .mount(part.index, part.start, part.length, self.read_only, part.fs_kind, check)
            .map_err(|e| anyhow!("mount: {e:?}"))?;
        client.deadlines = Deadlines::default();
        self.vm = Some(vm);
        Ok((client, hello))
    }
}

impl fs::Session for Served {
    fn restart(&mut self) -> Result<(VmClient, u64, bool)> {
        let (client, hello) = self.bring_up(SERVE_BUDGET)?;
        Ok((client, hello.root, hello.read_only))
    }
}

fn serve(args: &Args, disk: File, mut pipe: File) -> Result<()> {
    let fuse_dev = inherited(FUSE_FD)?;
    ensure!(fuse_dev.metadata()?.file_type().is_char_device(), "descriptor 4 is not /dev/fuse");
    let obb = args.mode == Mode::Obb;
    if obb {
        ensure!(access_mode(&disk)? == libc::O_RDONLY, "an OBB must be opened read-only");
        ensure!(disk.metadata()?.file_type().is_file(), "descriptor 3 is not a file");
        // The VM sees whole sectors. An OBB's signature footer after the image is not part of the filesystem.
        ensure!(disk.metadata()?.len() & !511 == args.disk_bytes, "the OBB changed size");
    }
    // The memory follows the metadata the filesystem needs. For an OBB it is not known before the VM reads it, and
    // OBB images are small.
    let mut served = Served {
        disk,
        obb,
        read_only: args.read_only || obb,
        memory: if obb { layout::MIN_SERVE_MIB } else { layout::serve_memory_mib(args.fs, args.meta_bytes) },
        disk_bytes: args.disk_bytes,
        partition: args.partition,
        start: args.start,
        length: args.length,
        fs: args.fs,
        volume: args.volume.clone(),
        vm: None,
    };
    let (client, hello) = served.bring_up(SERVE_BUDGET)?;
    let read_only = served.read_only || hello.read_only;
    info!("volume {}: VM serves filesystem kind {}, read-only {}", args.volume, hello.fs_kind, read_only);

    pipe.write_all(b"R").context("telling vold")?;
    drop(pipe);

    let filesystem = fs::FsvmFs::new(client, hello.root, read_only, args.gid, obb, Box::new(served));
    let mut config = fuse::FuseConfig::new();
    config.dev_fuse(fuse_dev).max_read(MAX_IO).max_write(MAX_IO).num_threads(1);
    let r = config.enter_message_loop(filesystem);
    info!("volume {}: FUSE loop ended: {r:?}", args.volume);
    Ok(())
}

fn run() -> Result<()> {
    check_no_capabilities()?;
    let args = parse_args()?;
    let disk = inherited(DISK_FD)?;
    let pipe = inherited(PIPE_FD)?;
    let ft = disk.metadata()?.file_type();
    match args.mode {
        Mode::Obb => ensure!(ft.is_file(), "descriptor 3 is not a file"),
        _ => ensure!(ft.is_block_device(), "descriptor 3 is not a block device"),
    }
    match args.mode {
        Mode::Probe => probe(&args, disk, pipe),
        Mode::Serve | Mode::Obb => serve(&args, disk, pipe),
    }
}

fn main() {
    android_logger::init_once(android_logger::Config::default().with_tag("fsvmd").with_max_level(log::LevelFilter::Info));
    if let Err(e) = run() {
        error!("{e:?}");
        std::process::exit(1);
    }
}
