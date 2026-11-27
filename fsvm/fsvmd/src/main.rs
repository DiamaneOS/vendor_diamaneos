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
//! fsvmd for each request of vold's, in one of these modes:
//!
//! ```text
//! fsvmd --probe --disk-bytes <n> --block-size <512|4096>
//! fsvmd --volume <id> --gid <gid> --disk-bytes <n> --partition <i> --start <s> --length <l> --fs <vfat|exfat|->
//!       --meta-bytes <m> [--owner-uid <uid>] [--read-only]
//! fsvmd --obb --volume <id> --gid <gid> --disk-bytes <n>
//! fsvmd --repair --volume <id> --gid <gid> --disk-bytes <n> --block-size <b> --partition <i> --start <s>
//!       --length <l> --fs <vfat|exfat> [--meta-bytes <m>]
//! fsvmd --drive <disk id> --block-size <b> --disk <bytes>:<vfat|exfat|->:<meta-bytes> [--disk ...] [--read-only]
//! ```
//!
//! Descriptors: 3 is the whole disk (a vold block device) or the OBB file, read-only for probe and OBB. 4 is the
//! /dev/fuse descriptor vold mounted (not for probe). 5 is a pipe to vold. A drive gets only 3: its end of a socket
//! pair, over which vold hands it the partitions' ranges, mounts and repairs (drive.rs, drive_msg.rs).
//!
//! - Drive: one VM serves every public partition of one drive, each partition a disk of the VM and a range of its
//!   own on Android, each with its own FUSE mount, check, repair and read-only state. All disks are given at the
//!   VM's start. A partition's broken session gets a new session in the same VM: the other partitions keep theirs.
//!   A partition is formatted in the drive's VM too, so that no mkfs runs on Android.
//! - Probe: the VM reads the partition table. fsvmd checks the layout (fsvm_proto::layout) and writes it to the pipe
//!   in the line format below, then stops the VM. vold creates volumes from it, and sets up a device-mapper range for
//!   each partition it serves.
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

mod drive;
mod reconnect;
mod drive_msg;
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
    /// Repairs the volume in the VM with no time limit (`--repair`), while vold keeps it from apps.
    Repair,
    /// Serves every public partition of one drive from one VM (`--drive`, drive.rs).
    Drive,
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    volume: String,
    gid: u32,
    owner_uid: u32,
    read_only: bool,
    disk_bytes: u64,
    block_size: u32,
    partition: u32,
    start: u64,
    length: u64,
    fs: u32,
    meta_bytes: u64,
    /// A drive's partitions, each a disk of its VM (`--disk`).
    disks: Vec<drive_msg::DiskSpec>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        mode: Mode::Serve,
        volume: String::new(),
        gid: u32::MAX,
        owner_uid: 0,
        read_only: false,
        disk_bytes: 0,
        block_size: 512,
        partition: u32::MAX,
        start: 0,
        length: 0,
        fs: u32::MAX,
        meta_bytes: 0,
        disks: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().with_context(|| arg.clone());
        match arg.as_str() {
            "--probe" => a.mode = Mode::Probe,
            "--obb" => a.mode = Mode::Obb,
            "--drive" => {
                a.mode = Mode::Drive;
                a.volume = drive_msg::name(&val()?).map_err(|e| anyhow!(e))?;
            }
            "--disk" => a.disks.push(drive_msg::parse_disk(&val()?).map_err(|e| anyhow!(e))?),
            "--repair" => a.mode = Mode::Repair,
            "--volume" => a.volume = val()?,
            "--gid" => a.gid = val()?.parse()?,
            "--owner-uid" => a.owner_uid = val()?.parse()?,
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
    ensure!(a.block_size == 512 || a.block_size == 4096, "--block-size must be 512 or 4096");
    ensure!((a.mode == Mode::Drive) != a.disks.is_empty(), "--disk is for --drive, which needs one");
    if a.mode == Mode::Drive {
        ensure!(a.disks.len() <= drive_msg::MAX_DISKS, "{} disks, at most {}", a.disks.len(), drive_msg::MAX_DISKS);
        ensure!(a.disk_bytes == 0 && a.partition == u32::MAX, "a drive takes --disk only");
        return Ok(a);
    }
    ensure!(a.disk_bytes > 0 && a.disk_bytes % 512 == 0, "--disk-bytes must be a positive multiple of 512");
    match a.mode {
        Mode::Probe => {}
        Mode::Serve | Mode::Repair => ensure!(
            !a.volume.is_empty() && a.gid != u32::MAX && a.partition != u32::MAX && a.length > 0 && a.fs != u32::MAX,
            "--volume, --gid, --partition, --start, --length and --fs are required"
        ),
        Mode::Obb => ensure!(!a.volume.is_empty() && a.gid != u32::MAX, "--volume and --gid are required"),
        Mode::Drive => {}
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
    let mut rd = stop_signals()?;
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        let _ = rd.read(&mut b);
        let (lock_wait, max) = stop_times(b[0]);
        match closer.close(lock_wait, max) {
            // The stop after the FUSE loop runs already and decides the exit. vold's kill covers a hang.
            fs::Closed::InProgress => {}
            c => exit_for(c),
        }
    });
    Ok(())
}

/// The times of an orderly stop for what `stop_signals` read: a write back request (`W`) gets the whole orderly
/// stop's time, a stop request what is left of vold's.
fn stop_times(what: u8) -> (Duration, Duration) {
    if what == b'W' {
        warn!("vold asks for a write back: the volume goes, writing back before the VM stops");
        (CLOSE_LOCK_WAIT, CLOSE_MAX)
    } else {
        warn!("stopped by vold: writing back before the VM stops");
        (Duration::from_millis(300), Duration::from_millis(1500))
    }
}

/// SIGTERM (vold's stop) and SIGUSR1 (vold's write back request) as `T` and `W` on the pipe this returns.
fn stop_signals() -> Result<File> {
    let mut p = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into `p`.
    ensure!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } == 0, "pipe2");
    // SAFETY: p[0] is a new descriptor that nothing else owns.
    let rd = unsafe { File::from_raw_fd(p[0]) };
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
    Ok(rd)
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

/// Starts the VM with `disks`, connects to the server of disk `index` and checks the protocol version, before
/// `deadline` less `keep`, the time the caller needs after the start. Each try waits for the VM as long as that
/// allows: a VM on ordinary memory may spend most of it in its memory lend (vm::Vm::connect). A VM refused at its
/// start (no pool room, and its ordinary memory too scattered or past the budget of pieces of all running VMs) ends
/// the tries with NoRoom. A VM that ended before it answered for another reason is tried again while there is time,
/// up to `tries`.
fn start_vm(
    disks: &[File],
    writable: bool,
    memory_mib: u32,
    deadline: Instant,
    keep: Duration,
    tries: usize,
    index: u32,
) -> Result<(vm::Vm, VmClient)> {
    let mut last = anyhow!("not started");
    for (attempt, wait) in [0u64, 1, 2].into_iter().take(tries).enumerate() {
        if wait > 0 {
            if left(deadline)? <= keep + Duration::from_secs(wait + 5) {
                break;
            }
            std::thread::sleep(Duration::from_secs(wait));
        }
        ensure!(left(deadline)? > keep, "no time left to start the VM");
        let volumes = disks.iter().map(|d| d.try_clone()).collect::<std::io::Result<Vec<File>>>()?;
        let vm = match vm::Vm::start(manager()?, volumes, writable, memory_mib) {
            Ok(vm) => vm,
            Err(e) => {
                warn!("filesystem VM start {} failed: {e:?}", attempt + 1);
                last = e;
                continue;
            }
        };
        let stream = match vm.connect(PORT, left(deadline)?.saturating_sub(keep)) {
            Ok(stream) => stream,
            Err(e) => {
                warn!("filesystem VM start {} did not answer: {e:?}", attempt + 1);
                let refused = vm.refused_at_start();
                // Stop the old VM within the request's remaining time before another try.
                vm.stop_and_wait(PROBE_VM_END.min(deadline.saturating_duration_since(Instant::now())));
                if refused {
                    // No pool room, and its ordinary memory would pass the budget of pieces of all running VMs (the
                    // kernel's vm_pieces_max) or the hypervisor's: the same again until a VM ends. vold waits for room.
                    error!("the VM of {memory_mib} MiB was refused at its start: no room for it now");
                    return Err(anyhow!(NoRoom));
                }
                last = e;
                continue;
            }
        };
        return Ok((vm, select_disk(stream, index, deadline)?));
    }
    Err(last)
}

/// A new session with the server of disk `index` of the running VM `vm`: a drive's partition whose session broke, a
/// format or a repair. The VM ends the disk's earlier server first.
fn connect_disk(vm: &vm::Vm, index: u32, deadline: Instant, keep: Duration) -> Result<VmClient> {
    ensure!(left(deadline)? > keep, "no time left to connect to the VM");
    let stream = vm.connect(PORT, left(deadline)?.saturating_sub(keep))?;
    select_disk(stream, index, deadline)
}

/// Names the disk this session serves, with the protocol version (Client::select_disk).
fn select_disk(stream: UnixStream, index: u32, deadline: Instant) -> Result<VmClient> {
    let mut deadlines = Deadlines::default();
    deadlines.hello = deadlines.hello.min(left(deadline)?);
    let mut client = Client::new(StreamTransport(stream), deadlines);
    client.select_disk(index).map_err(|e| anyhow!("disk {index}: {e:?}"))?;
    Ok(client)
}

/// A VM refused at its start for want of memory. fsvmd then ends with EXIT_NO_ROOM and vold waits for room.
#[derive(Debug)]
struct NoRoom;

impl std::fmt::Display for NoRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no room for the filesystem VM")
    }
}

impl std::error::Error for NoRoom {}

/// fsvmd's exit status when its VM was refused at its start for want of memory (vold fs/Fsvm.h kExitNoRoom).
const EXIT_NO_ROOM: i32 = 5;

/// vold waits 45 s for a format in a drive's VM (fs/FsvmDrive.cpp, kFormatTimeoutMs) and holds its lock meanwhile, as
/// it did for mkfs on Android.
const FORMAT_BUDGET: Duration = Duration::from_secs(40);

/// The VM of a repair: the size of the volume's serving VM, which ran the same check to its end before vold asked for
/// the repair (fs.rs, a check that found errors too late to repair them while apps wait). Without the volume's metadata
/// size, FAT starts at the serving minimum and other filesystems at the maximum. An unfinished check retries at the maximum
/// size (repair).
fn repair_memory_mib(args: &Args) -> u32 {
    if args.meta_bytes == 0 && args.fs != FS_VFAT {
        layout::MAX_SERVE_MIB
    } else {
        layout::serve_memory_mib(args.fs, args.meta_bytes)
    }
}

/// What a start leaves before the deadline for the work after it: the probe's answer and a repair's look at the disk,
/// the format itself, and a serving VM's partition check and MOUNT_MIN.
const PROBE_KEEP: Duration = Duration::from_secs(3);
const FORMAT_KEEP: Duration = Duration::from_secs(25);
const SERVE_KEEP: Duration = Duration::from_secs(10);

/// A repair with no time limit: the VM checks and repairs the volume (as a mount with a check, with no budget), mounts
/// it writable and unmounts it cleanly. vold has taken the volume from apps for it and waits outside its lock. "OK" on
/// the pipe when the volume is clean now, else exit EXIT_NOT_REPAIRED (a check that failed, too little memory for
/// the card's table: the volume stays read-only then). vold may stop it at any time (an eject): nothing half-mounted
/// stays, and the volume keeps its dirty mark for the next mount.
fn repair(args: &Args, disk: File, mut pipe: File) -> Result<()> {
    ensure!(access_mode(&disk)? == libc::O_RDWR, "a repair needs the disk writable");
    let first = repair_memory_mib(args);
    let mut repaired = repair_in_vm(args, &disk, first)?;
    if repaired == Repair::NotFinished && first < layout::MAX_SERVE_MIB {
        // With no time limit, a check that did not finish was killed in the VM, out of memory for the card's table.
        warn!("the check did not finish in {first} MiB, once more in {} MiB", layout::MAX_SERVE_MIB);
        repaired = repair_in_vm(args, &disk, layout::MAX_SERVE_MIB)?;
    }
    if repaired != Repair::Done {
        warn!("volume {} was not repaired, it stays read-only", args.volume);
        std::process::exit(EXIT_NOT_REPAIRED);
    }
    info!("volume {} repaired in the VM", args.volume);
    pipe.write_all(b"OK\n").context("telling vold")?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Repair {
    Done,
    /// Mounted read-only: the check did not finish (its checker was killed, or the card is write-protected).
    NotFinished,
    Failed,
}

/// One repair in a VM of `memory_mib`. The VM is gone again when it returns.
fn repair_in_vm(args: &Args, disk: &File, memory_mib: u32) -> Result<Repair> {
    let deadline = Instant::now() + SERVE_BUDGET;
    let (vm, client) = start_vm(std::slice::from_ref(disk), true, memory_mib, deadline, PROBE_KEEP, 3, 0)?;
    info!("repairing volume {} in the VM ({memory_mib} MiB), no time limit", args.volume);
    let result = repair_on(client, args.disk_bytes, args.block_size, (args.partition, args.start, args.length), args.fs, deadline)?;
    vm.stop_and_wait(PROBE_VM_END);
    Ok(result)
}

/// The repair itself, on a session with the volume's disk (its own VM, or a drive's): the partition must still be
/// where the probe found it, then a writable mount whose check may take as long as it needs, and an unmount that
/// marks it clean.
fn repair_on(
    mut client: VmClient,
    disk_bytes: u64,
    block_size: u32,
    (index, start, length): (u32, u64, u64),
    fs: u32,
    deadline: Instant,
) -> Result<Repair> {
    client.deadlines.hello = client.deadlines.hello.min(left(deadline)?);
    let l = client.layout(disk_bytes, block_size).map_err(|e| anyhow!("layout: {e:?}"))?;
    let part = l
        .parts
        .iter()
        .find(|p| p.index == index && p.start == start && p.length == length)
        .cloned()
        .ok_or_else(|| anyhow!("partition {index} is no longer where the probe found it"))?;
    ensure!(part.fs_kind != 0 && (fs == 0 || part.fs_kind == fs), "the filesystem changed since the probe");
    let check = Duration::from_millis(u32::MAX as u64);
    let hello = client.mount(part.index, part.start, part.length, false, part.fs_kind, check);
    Ok(match hello {
        Ok(h) if !h.read_only => {
            if client.unmount(Duration::from_secs(20)).is_ok() {
                Repair::Done
            } else {
                Repair::Failed
            }
        }
        Ok(_) => Repair::NotFinished,
        Err(e) => {
            warn!("the repair did not end with a mount: {e:?}");
            Repair::Failed
        }
    })
}

/// fsvmd's exit status when a repair did not leave the volume clean (vold treats any non-zero status of a repair as
/// not repaired).
const EXIT_NOT_REPAIRED: i32 = 4;

fn probe(args: &Args, disk: File, mut pipe: File) -> Result<()> {
    ensure!(access_mode(&disk)? == libc::O_RDONLY, "the probe disk must be read-only");
    let deadline = Instant::now() + PROBE_BUDGET;
    let (vm, mut client) =
        start_vm(std::slice::from_ref(&disk), false, layout::PROBE_MIB, deadline, PROBE_KEEP, 3, 0)?;
    client.deadlines.hello = client.deadlines.hello.min(left(deadline)?);
    let l = client.layout(args.disk_bytes, args.block_size).map_err(|e| anyhow!("layout: {e:?}"))?;
    if l.dropped_labels > 0 {
        warn!("{} volume labels refused", l.dropped_labels);
    }
    info!("disk layout: {:?}, {} partitions", l.table, l.parts.len());
    pipe.write_all(layout::probe_text(&l).as_bytes()).context("telling vold")?;
    drop(pipe);
    // The probe VM ends before fsvmd does, so its memory is back (in the pool) when vold starts the next VM. vold
    // waits up to 10 s for this exit (fs/Fsvm.cpp Probe, kVmEndMs), and the answer counts either way.
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
    fn bring_up(&mut self, deadline: Instant) -> Result<(VmClient, fsvm_proto::Hello)> {
        // The old VM goes first, so that its memory is free for the new one.
        self.vm = None;
        left(deadline)?;
        info!("volume {}: starting the filesystem VM with {} MiB", self.volume, self.memory);
        // An OBB VM never waits for a place: refused at its start, the mount fails at once (vold reports Android's
        // OBB error).
        // A large VM refused for its pieces is refused again: one try, then the smallest serving VM below.
        let tries = if self.obb || self.memory > layout::MIN_SERVE_MIB { 1 } else { 3 };
        let disks = std::slice::from_ref(&self.disk);
        let (vm, client) = match start_vm(disks, !self.read_only, self.memory, deadline, SERVE_KEEP, tries, 0) {
            Ok(started) => started,
            // A VM sized for the check of a large card that cannot start (no pool room, and ordinary memory refused
            // for its pieces): served from the smallest serving VM instead. A clean volume needs no more. A dirty one's
            // check cannot finish there, so it stays read-only with its notice and is never writable unchecked.
            Err(e) if !self.obb && self.memory > layout::MIN_SERVE_MIB => {
                warn!(
                    "volume {}: a VM of {} MiB did not start ({e:?}), serving it from {} MiB, where a check that needs \
                     more memory cannot finish",
                    self.volume,
                    self.memory,
                    layout::MIN_SERVE_MIB
                );
                start_vm(disks, !self.read_only, layout::MIN_SERVE_MIB, deadline, SERVE_KEEP, 1, 0)?
            }
            Err(e) => return Err(e),
        };
        let spec = MountSpec {
            obb: self.obb,
            read_only: self.read_only,
            disk_bytes: self.disk_bytes,
            block_size: self.block_size,
            partition: self.partition,
            start: self.start,
            length: self.length,
            fs: self.fs,
        };
        let mounted = mount_on(client, &spec, deadline)?;
        self.vm = Some(vm);
        Ok(mounted)
    }
}

/// What a session mounts: the partition the probe found, as vold names it.
struct MountSpec {
    obb: bool,
    read_only: bool,
    disk_bytes: u64,
    block_size: u32,
    partition: u32,
    start: u64,
    length: u64,
    fs: u32,
}

/// On a fresh session with the volume's disk: checks the partition is still where the probe found it, with the
/// filesystem it found, and mounts it (a volume marked dirty read-only at once, checked afterwards), before
/// `deadline`.
fn mount_on(mut client: VmClient, m: &MountSpec, deadline: Instant) -> Result<(VmClient, fsvm_proto::Hello)> {
    client.deadlines.hello = client.deadlines.hello.min(left(deadline)?);
    let l = client.layout(m.disk_bytes, m.block_size).map_err(|e| anyhow!("layout: {e:?}"))?;
    let part = if m.obb {
        ensure!(l.table == Table::None && l.parts.len() == 1, "an OBB must be one filesystem without a partition table");
        l.parts[0].clone()
    } else {
        l.parts
            .iter()
            .find(|p| p.index == m.partition && p.start == m.start && p.length == m.length)
            .cloned()
            .ok_or_else(|| anyhow!("partition {} is no longer where the probe found it", m.partition))?
    };
    ensure!(part.class == Class::Public, "partition {} is not a public volume", part.index);
    ensure!(part.fs_kind != 0, "no FAT or exFAT filesystem on partition {}", part.index);
    ensure!(m.obb || m.fs == 0 || part.fs_kind == m.fs, "the filesystem changed since the probe");
    let remaining = left(deadline)?;
    ensure!(remaining > MOUNT_MIN, "no time left to mount");
    client.deadlines.mount = remaining;
    let hello = if m.read_only {
        client.mount(part.index, part.start, part.length, true, part.fs_kind, Duration::ZERO)
    } else {
        client.mount_check_later(part.index, part.start, part.length, part.fs_kind)
    }
    .map_err(|e| anyhow!("mount: {e:?}"))?;
    client.deadlines = Deadlines::default();
    Ok((client, hello))
}

/// The pipe to vold of a served volume. A drive's partition closes it when it ends (vold's Watch then knows), so it
/// can be taken away from the checker that writes to it.
pub type Pipe = std::sync::Arc<std::sync::Mutex<Option<File>>>;

/// Writes `what` to vold's pipe, while it is open.
pub fn tell(pipe: &Pipe, what: &[u8]) -> std::io::Result<()> {
    match pipe.lock().map_err(|_| std::io::Error::other("pipe lock"))?.as_mut() {
        Some(p) => p.write_all(what),
        None => Err(std::io::ErrorKind::BrokenPipe.into()),
    }
}

/// A volume served from now on: tells vold how (`R`, `r` or `c`), and returns the FUSE side with its checker running
/// and its pipe kept for the check's end. `listings`: the card's listing memory (a drive's, shared by its partitions).
#[allow(clippy::too_many_arguments)]
fn start_serving(
    client: VmClient,
    hello: fsvm_proto::Hello,
    asked_read_only: bool,
    gid: u32,
    owner_uid: u32,
    obb: bool,
    volume: &str,
    session: Box<dyn fs::Session>,
    pipe: &Pipe,
    listings: std::sync::Arc<fs::Listings>,
) -> Result<fs::FsvmFs> {
    let read_only = asked_read_only || hello.read_only;
    info!("volume {volume}: VM serves filesystem kind {}, read-only {read_only}", hello.fs_kind);
    if hello.was_dirty {
        warn!("volume {volume}: the filesystem was not cleanly unmounted before (the VM checks it)");
    }
    // R: served writable. r: served read-only for good (asked read-only, a write-protected card, or the VM's driver
    // found an error). c: asked writable, served read-only while the VM checks it, then W (writable now) or F (it
    // stays read-only) follow on the same pipe, and c again when a new VM after a broken session checks the volume
    // again. vold reports r, c and F as mounted read-only. A volume asked read-only is never checked.
    let ready = fs::ready_letter(asked_read_only, &hello);
    tell(pipe, &[ready]).context("telling vold")?;
    if ready == b'c' {
        warn!("volume {volume}: marked dirty, served read-only while the VM checks it");
    }
    let filesystem =
        fs::FsvmFs::new(client, hello.root, asked_read_only, read_only, gid, obb, hello.check_pending, session)
            .with_owner(owner_uid)
            .with_listings(listings);
    if !obb {
        // The pipe stays open for the check's end (also for a check a new session starts after a broken one).
        let pipe = pipe.clone();
        filesystem.spawn_checker(Box::new(move |what: u8| {
            let _ = tell(&pipe, &[what]);
        }));
    } else if let Ok(mut p) = pipe.lock() {
        p.take();
    }
    Ok(filesystem)
}

impl fs::Session for Served {
    fn restart(&mut self, deadline: Instant) -> Result<(VmClient, fsvm_proto::Hello)> {
        self.bring_up(deadline)
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

fn serve(args: &Args, disk: File, pipe: File) -> Result<()> {
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
    let (client, hello) = served.bring_up(Instant::now() + SERVE_BUDGET)?;
    let asked_read_only = served.read_only;
    let pipe: Pipe = std::sync::Arc::new(std::sync::Mutex::new(Some(pipe)));
    let filesystem = start_serving(
        client,
        hello,
        asked_read_only,
        args.gid,
        args.owner_uid,
        obb,
        &args.volume,
        Box::new(served),
        &pipe,
        Default::default(),
    )?;
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
    let ft = disk.metadata()?.file_type();
    match args.mode {
        Mode::Obb => ensure!(ft.is_file(), "descriptor 3 is not a file"),
        // A drive's disks come over vold's socket (drive.rs), descriptors 4 and 5 stay closed.
        Mode::Drive => ensure!(ft.is_socket(), "descriptor 3 is not vold's socket"),
        _ => ensure!(ft.is_block_device(), "descriptor 3 is not a block device"),
    }
    let pipe = if args.mode == Mode::Drive { None } else { Some(inherited(PIPE_FD)?) };
    // The VM manager first, then the filter: it and crosvm start without it (they need exec and their file
    // capability), fsvmd itself never starts another program after this. Nothing vold handed over reaches the VM
    // manager but over binder: /dev/fuse (taken later, in serve) is close-on-exec before it starts.
    // SAFETY: F_SETFD only changes the descriptor flags of FUSE_FD, which vold handed to this process or left closed.
    unsafe { libc::fcntl(FUSE_FD, libc::F_SETFD, libc::FD_CLOEXEC) };
    let manager = vm::Manager::spawn()?;
    let how = seccomp::install_for_fsvmd(manager.pid())?;
    let _ = MANAGER.set(manager);
    info!("seccomp filter on ({how} anything else)");
    let Some(pipe) = pipe else {
        return drive::run(&args.volume, &args.disks, args.block_size, !args.read_only, disk);
    };
    match args.mode {
        Mode::Probe => probe(&args, disk, pipe),
        Mode::Repair => repair(&args, disk, pipe),
        Mode::Serve | Mode::Obb => serve(&args, disk, pipe),
        Mode::Drive => unreachable!("handled above"),
    }
}

/// An OBB VM's memory from the image's size: OBBs are FAT images of a few hundred MiB, whose FAT is small. Up to 2 GiB
/// the probe VM's size does, larger ones get a serving VM's least.
fn obb_memory_mib(disk_bytes: u64) -> u32 {
    if disk_bytes <= 2 << 30 { layout::PROBE_MIB } else { layout::MIN_SERVE_MIB }
}

/// fsvmd for OBB images runs from its own binary (`fsvmd_obb`, its own SELinux domain without card access), and only
/// for OBB images. fsvmd serves cards and probes them, never OBB images.
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
        std::process::exit(if e.chain().any(|c| c.is::<NoRoom>()) { EXIT_NO_ROOM } else { 1 });
    }
}
