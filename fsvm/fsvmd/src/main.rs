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
//! inside a protected VM. init runs the fsvmd service (`fsvmd_launcher`, fsvmd.rc, launcher.rs), which starts one
//! fsvmd for each request of vold's, in one of three modes:
//!
//! ```text
//! fsvmd --probe --disk-bytes <n> --block-size <512|4096>
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
mod seccomp;
mod vm;

use anyhow::{anyhow, bail, ensure, Context, Result};
use fsvm_proto::layout::{self, Class, Table};
use fsvm_proto::{Client, Deadlines, StreamTransport, FS_EXFAT, FS_VFAT, PORT};
use log::{error, info, warn};
use std::fs::File;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, Ordering};
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
    block_size: u32,
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
        block_size: 512,
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
            "--block-size" => a.block_size = val()?.parse()?,
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
    ensure!(a.block_size == 512 || a.block_size == 4096, "--block-size must be 512 or 4096");
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

/// fsvmd holds no capabilities: the service drops all it got from init and every fsvmd it starts inherits that. The
/// bounding set keeps CAP_SYS_NICE only, which the VM manager's file capability needs to be executed at all
/// (launcher_main.rs). Anything else is refused here.
const BOUNDING: u64 = 1 << 23;

fn check_no_capabilities() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")?;
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

/// The write end of the pipe SIGTERM wakes the closing thread through (watch_sigterm).
static TERM_PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sigterm(sig: libc::c_int) {
    let fd = TERM_PIPE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SIGUSR1 is vold's request to write back now, with the full time (several volumes stop together).
        let b: &[u8; 1] = if sig == libc::SIGUSR1 { b"W" } else { b"T" };
        // SAFETY: write is async-signal-safe, on a pipe this process created and never closes.
        unsafe { libc::write(fd, b.as_ptr().cast(), 1) };
    }
}

/// vold's stop of a fsvmd that did not end on its own after its FUSE mount went: the volume is written back and
/// unmounted in the VM if that is still possible in the time vold gives, then fsvmd exits and the VM stops.
fn watch_sigterm(closer: fs::Closer) -> Result<()> {
    let mut p = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into `p`.
    ensure!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } == 0, "pipe2");
    // SAFETY: p[0] is a new descriptor that nothing else owns.
    let mut rd = unsafe { File::from_raw_fd(p[0]) };
    TERM_PIPE.store(p[1], Ordering::Relaxed);
    // SAFETY: a zeroed sigaction with only the handler set, for SIGTERM. Handlers reset to the default on exec, so
    // the VM manager fsvmd starts is not affected.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigterm as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        ensure!(libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) == 0, "sigaction");
        ensure!(libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) == 0, "sigaction");
    }
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        let _ = rd.read(&mut b);
        // A write back request gets the whole orderly stop's time, a stop request what is left of vold's.
        let (lock_wait, max) = if b[0] == b'W' {
            warn!("vold asks for a write back: the volume goes, writing back before the VM stops");
            (CLOSE_LOCK_WAIT, CLOSE_MAX)
        } else {
            warn!("stopped by vold: writing back before the VM stops");
            (Duration::from_millis(300), Duration::from_millis(1500))
        };
        match closer.close(lock_wait, max) {
            // The stop after the FUSE loop runs already and decides the exit. vold's kill covers a hang.
            fs::Closed::InProgress => {}
            c => exit_for(c),
        }
    });
    Ok(())
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

/// vold waits 23 s for a probe and 37 s for a mount, and holds its lock meanwhile (system/vold fs/Fsvm.cpp), so
/// fsvmd finishes within these, whatever the VM does.
const PROBE_BUDGET: Duration = Duration::from_secs(20);
/// The probe VM gets this long to end after its answer.
const PROBE_VM_END: Duration = Duration::from_millis(2500);
const SERVE_BUDGET: Duration = Duration::from_secs(34);
/// The orderly stop after vold unmounted the volume: a call still running gets CLOSE_LOCK_WAIT to end, then the VM
/// writes back as long as its dirty data keeps going down, and unmounts, all within CLOSE_MAX, and stops (3 s). vold
/// waits 26 s for fsvmd to end on its own (fs/Fsvm.cpp kSyncMs).
const CLOSE_LOCK_WAIT: Duration = Duration::from_secs(2);
const CLOSE_MAX: Duration = Duration::from_secs(20);
/// Kept for the mount itself and the first free-space count. A volume marked dirty is checked after the mount, read-
/// only until the check passes (fs::FsvmFs::spawn_checker), so nothing of the check counts against vold's lock.
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
        let vm = match vm::Vm::start(manager()?, disk.try_clone()?, writable, memory_mib) {
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
    let l = client.layout(args.disk_bytes, args.block_size).map_err(|e| anyhow!("layout: {e:?}"))?;
    if l.dropped_labels > 0 {
        warn!("{} volume labels refused", l.dropped_labels);
    }
    info!("disk layout: {:?}, {} partitions", l.table, l.parts.len());
    pipe.write_all(layout::probe_text(&l).as_bytes()).context("telling vold")?;
    drop(pipe);
    // The probe VM ends before fsvmd does, so its memory is back (in the pool) when vold starts the next VM. vold
    // waits 3 s for this exit (fs/Fsvm.cpp Probe).
    vm.stop_and_wait(PROBE_VM_END);
    Ok(())
}

/// One served volume: what it takes to bring a VM up for it, first at mount and again when a session breaks.
struct Served {
    disk: File,
    obb: bool,
    read_only: bool,
    memory: u32,
    disk_bytes: u64,
    block_size: u32,
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
        let l = client.layout(self.disk_bytes, self.block_size).map_err(|e| anyhow!("layout: {e:?}"))?;
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
        client.deadlines.mount = remaining;
        let hello = if self.read_only {
            client.mount(part.index, part.start, part.length, true, part.fs_kind, Duration::ZERO)
        } else {
            client.mount_check_later(part.index, part.start, part.length, part.fs_kind)
        }
        .map_err(|e| anyhow!("mount: {e:?}"))?;
        client.deadlines = Deadlines::default();
        self.vm = Some(vm);
        Ok((client, hello))
    }
}

impl fs::Session for Served {
    fn restart(&mut self) -> Result<(VmClient, fsvm_proto::Hello)> {
        self.bring_up(SERVE_BUDGET)
    }

    fn stop_vm(&mut self, within: Duration) {
        if let Some(vm) = self.vm.take() {
            vm.stop_and_wait(within);
        }
    }
}

/// fsvmd's exit status when it could not write the volume back before it ended (vold fs/Fsvm.h kExitNotWrittenBack).
const EXIT_NOT_WRITTEN_BACK: i32 = 3;

fn exit_for(c: fs::Closed) -> ! {
    std::process::exit(if c == fs::Closed::Clean { 0 } else { EXIT_NOT_WRITTEN_BACK })
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
        memory: if obb { obb_memory_mib(args.disk_bytes) } else { layout::serve_memory_mib(args.fs, args.meta_bytes) },
        disk_bytes: args.disk_bytes,
        block_size: args.block_size,
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
    if hello.was_dirty {
        warn!("volume {}: the filesystem was not cleanly unmounted before (the VM checks it)", args.volume);
    }

    // R: served as asked. c: asked writable, served read-only while the VM checks it, then W (writable now) or F (it
    // stays read-only) follow on the same pipe. r: asked writable and served read-only by the VM (a write-protected
    // card, or its driver found an error). vold reports r and F as mounted read-only.
    let ready: &[u8] = if hello.check_pending {
        b"c"
    } else if read_only && !served.read_only {
        b"r"
    } else {
        b"R"
    };
    pipe.write_all(ready).context("telling vold")?;
    if hello.check_pending {
        warn!("volume {}: marked dirty, served read-only while the VM checks it", args.volume);
    }

    let filesystem =
        fs::FsvmFs::new(client, hello.root, read_only, args.gid, obb, hello.check_pending, Box::new(served));
    if !obb {
        // The pipe stays open for the check's end (also for a check a new VM starts after a broken session).
        let pipe = std::sync::Mutex::new(pipe);
        filesystem.spawn_checker(Box::new(move |writable| {
            let _ = pipe.lock().map(|mut p| p.write_all(if writable { b"W" } else { b"F" }));
        }));
    } else {
        drop(pipe);
    }
    let closer = filesystem.closer();
    watch_sigterm(filesystem.closer())?;
    let r = fs::serve_fuse(fuse_dev, filesystem);
    info!("volume {}: FUSE loop ended: {r:?}", args.volume);
    // vold unmounted the volume. Everything is written back and the filesystem unmounted in the VM (marked clean),
    // and the VM stopped, before this process ends. vold waits for this (fs/Fsvm.cpp Stop) and learns from the exit
    // status whether it worked.
    match closer.close(CLOSE_LOCK_WAIT, CLOSE_MAX) {
        fs::Closed::InProgress => loop {
            // vold's stop request came first: its thread finishes and exits.
            std::thread::sleep(Duration::from_secs(3600));
        },
        c => exit_for(c),
    }
}

/// The VM manager, started before the seccomp filter (run).
static MANAGER: std::sync::OnceLock<vm::Manager> = std::sync::OnceLock::new();

fn manager() -> Result<&'static vm::Manager> {
    MANAGER.get().ok_or_else(|| anyhow!("no VM manager"))
}

fn run() -> Result<()> {
    check_no_capabilities()?;
    // The service is kept from the low memory killer. Its fsvmd processes, and the VM managers and crosvm they start,
    // are not: back to the default.
    if let Err(e) = std::fs::write("/proc/self/oom_score_adj", "0") {
        warn!("oom_score_adj: {e}");
    }
    let args = parse_args()?;
    check_binary(&args)?;
    let disk = inherited(DISK_FD)?;
    let pipe = inherited(PIPE_FD)?;
    let ft = disk.metadata()?.file_type();
    match args.mode {
        Mode::Obb => ensure!(ft.is_file(), "descriptor 3 is not a file"),
        _ => ensure!(ft.is_block_device(), "descriptor 3 is not a block device"),
    }
    // The VM manager first, then the filter: it and crosvm start without it (they need exec and their file
    // capability), fsvmd itself never starts another program after this. Nothing vold handed over reaches the VM
    // manager but over binder: /dev/fuse (taken later, in serve) is close-on-exec before it starts.
    // SAFETY: F_SETFD only changes the descriptor flags of FUSE_FD, which vold handed to this process or left closed.
    unsafe { libc::fcntl(FUSE_FD, libc::F_SETFD, libc::FD_CLOEXEC) };
    let _ = MANAGER.set(vm::Manager::spawn()?);
    let how = seccomp::install_for_fsvmd()?;
    info!("seccomp filter on ({how} anything else)");
    match args.mode {
        Mode::Probe => probe(&args, disk, pipe),
        Mode::Serve | Mode::Obb => serve(&args, disk, pipe),
    }
}

/// An OBB VM's memory from the image's size: OBBs are FAT images of a few hundred MiB, whose FAT is small. Up to 2 GiB
/// the probe VM's size does, larger ones get a serving VM's least.
fn obb_memory_mib(disk_bytes: u64) -> u32 {
    if disk_bytes <= 2 << 30 { layout::PROBE_MIB } else { layout::MIN_SERVE_MIB }
}

/// fsvmd for OBB images runs from its own binary (`fsvmd_obb`, its own SELinux domain without card access and
/// outside the VM memory pool), and only for OBB images. fsvmd serves cards and probes them, never OBB images.
fn check_binary(args: &Args) -> Result<()> {
    let name = std::env::args().next().unwrap_or_default();
    let is_obb_binary = name.ends_with("/fsvmd_obb") || name == "fsvmd_obb";
    ensure!(is_obb_binary == (args.mode == Mode::Obb), "{name} does not serve this mode");
    Ok(())
}

fn main() {
    android_logger::init_once(android_logger::Config::default().with_tag("fsvmd").with_max_level(log::LevelFilter::Info));
    if let Err(e) = run() {
        error!("{e:?}");
        std::process::exit(1);
    }
}
