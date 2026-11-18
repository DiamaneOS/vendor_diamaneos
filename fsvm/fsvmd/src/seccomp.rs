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

//! fsvmd's seccomp filter. fsvmd installs it once its VM manager runs (vm::Manager, spawned before the filter, so
//! neither the VM manager nor the crosvm it starts inherits the filter or loses its file capability to
//! no_new_privs), and every thread of fsvmd gets it (TSYNC). From then on fsvmd may only:
//!
//! - make the system calls in `ALLOWED`: what serving FUSE, talking to the VM over vsock and to its VM manager over
//!   RPC binder, logging and the allocator need. fsvmd starts no program after this (no execve, no fork: clone only
//!   with CLONE_THREAD) and opens no socket but a Unix one (liblog's).
//! - signal itself and nothing else: kill, tgkill, rt_sigqueueinfo and rt_tgsigqueueinfo only with its own pid,
//!   pidfd_send_signal only through a pidfd it holds (pidfd_open and pidfd_getfd are refused, so it holds none but
//!   those of its own children), tkill never. One exception, its own child's: kill of the VM manager's process group,
//!   which vmclient sends when the VM manager ended, so that its crosvm goes too. Signals to anything else are
//!   refused with EPERM on every build.
//! - use ioctl only for the descriptor flags and FIONREAD.
//!
//! Anything else: the process is killed on user builds (fail closed: vold sees fsvmd end and reports the card as not
//! opened), and logged (audit type 1326) and allowed on debuggable builds, so that a phone run collects what is
//! missing (scripts/p3-phone.sh reads the log).
//!
//! Where the list comes from: the FUSE and protocol path was traced on the host (fsvmd/tests/fuse_host.rs runs the
//! real FsvmFs on a real FUSE mount with this filter, unknown calls reported to a supervisor through
//! SECCOMP_RET_USER_NOTIF and let through, `--trace` prints every call made), the rest from the code that runs after
//! the filter: vmclient and libbinder's RPC (socket I/O on the session's Unix sockets, descriptors in SCM_RIGHTS,
//! poll and eventfd wakeups, futex), the VM start (open of the kernel and initramfs, memfd_create and ftruncate for
//! the instance disk), liblog (socket, connect and writev on logd's socket), bionic and the scudo allocator (mmap,
//! madvise, prctl for VMA names, getrandom, getcpu), Rust's std threads (clone, sigaltstack, set_robust_list).

// Parts of this module serve only the host tests (fsvmd_fuse_test, fsvmd_seccomp_test).
#![allow(dead_code)]

use anyhow::{ensure, Result};

/// One BPF instruction (struct sock_filter).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ERRNO: u32 = 0x0005_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_LOG: u32 = 0x7ffc_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;

/// Offsets in struct seccomp_data.
const NR: u32 = 0;
const ARCH: u32 = 4;
const fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64

/// Newer calls, numbered alike on every architecture since Linux 5.1 (not in every libc crate).
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_CLONE3: libc::c_long = 435;
const SYS_PIDFD_GETFD: libc::c_long = 438;

/// The system calls fsvmd makes after the filter, by name for the logs and tests.
pub const ALLOWED: &[(libc::c_long, &str)] = &[
    // Memory: bionic, scudo, Rust's std.
    (libc::SYS_brk, "brk"),
    (libc::SYS_mmap, "mmap"),
    (libc::SYS_munmap, "munmap"),
    (libc::SYS_mremap, "mremap"),
    (libc::SYS_mprotect, "mprotect"),
    (libc::SYS_madvise, "madvise"),
    (libc::SYS_prctl, "prctl"),
    (libc::SYS_getrandom, "getrandom"),
    (libc::SYS_getcpu, "getcpu"),
    // Threads and their sync: RPC binder's threads, the checker and the stop watcher.
    (libc::SYS_futex, "futex"),
    (libc::SYS_set_robust_list, "set_robust_list"),
    (libc::SYS_set_tid_address, "set_tid_address"),
    (libc::SYS_sched_yield, "sched_yield"),
    (libc::SYS_sched_getaffinity, "sched_getaffinity"),
    (libc::SYS_gettid, "gettid"),
    (libc::SYS_getpid, "getpid"),
    (libc::SYS_getppid, "getppid"),
    (libc::SYS_getuid, "getuid"),
    (libc::SYS_geteuid, "geteuid"),
    (libc::SYS_getgid, "getgid"),
    (libc::SYS_getegid, "getegid"),
    (libc::SYS_prlimit64, "prlimit64"),
    (libc::SYS_exit, "exit"),
    (libc::SYS_exit_group, "exit_group"),
    (libc::SYS_restart_syscall, "restart_syscall"),
    // Signals: handlers and masks. Sending is in `build`.
    (libc::SYS_rt_sigaction, "rt_sigaction"),
    (libc::SYS_rt_sigprocmask, "rt_sigprocmask"),
    (libc::SYS_rt_sigreturn, "rt_sigreturn"),
    (libc::SYS_sigaltstack, "sigaltstack"),
    (SYS_PIDFD_SEND_SIGNAL, "pidfd_send_signal"),
    // The VM manager fsvmd started before the filter, if it ends.
    (libc::SYS_wait4, "wait4"),
    (libc::SYS_waitid, "waitid"),
    // Time.
    (libc::SYS_clock_gettime, "clock_gettime"),
    (libc::SYS_clock_getres, "clock_getres"),
    (libc::SYS_clock_nanosleep, "clock_nanosleep"),
    (libc::SYS_nanosleep, "nanosleep"),
    (libc::SYS_gettimeofday, "gettimeofday"),
    // Descriptors: /dev/fuse, the vsock and RPC sockets, the pipes to vold, the kernel, initramfs and instance disk.
    (libc::SYS_read, "read"),
    (libc::SYS_write, "write"),
    (libc::SYS_readv, "readv"),
    (libc::SYS_writev, "writev"),
    (libc::SYS_pread64, "pread64"),
    (libc::SYS_pwrite64, "pwrite64"),
    (libc::SYS_lseek, "lseek"),
    (libc::SYS_close, "close"),
    (libc::SYS_dup, "dup"),
    (libc::SYS_dup3, "dup3"),
    (libc::SYS_fcntl, "fcntl"),
    (libc::SYS_openat, "openat"),
    #[cfg(target_arch = "aarch64")]
    (79, "newfstatat"),
    #[cfg(target_arch = "x86_64")]
    (libc::SYS_newfstatat, "newfstatat"),
    #[cfg(target_arch = "aarch64")]
    (80, "fstat"),
    #[cfg(target_arch = "x86_64")]
    (libc::SYS_fstat, "fstat"),
    (libc::SYS_statx, "statx"),
    (libc::SYS_memfd_create, "memfd_create"),
    #[cfg(target_arch = "aarch64")]
    (46, "ftruncate"),
    #[cfg(target_arch = "x86_64")]
    (libc::SYS_ftruncate, "ftruncate"),
    (libc::SYS_pipe2, "pipe2"),
    (libc::SYS_eventfd2, "eventfd2"),
    (libc::SYS_ppoll, "ppoll"),
    (libc::SYS_pselect6, "pselect6"),
    (libc::SYS_epoll_create1, "epoll_create1"),
    (libc::SYS_epoll_ctl, "epoll_ctl"),
    (libc::SYS_epoll_pwait, "epoll_pwait"),
    // Sockets: the vsock its VM manager made, RPC binder's Unix sockets, liblog's. socket itself is in `build`.
    (libc::SYS_connect, "connect"),
    (libc::SYS_sendmsg, "sendmsg"),
    (libc::SYS_recvmsg, "recvmsg"),
    (libc::SYS_sendto, "sendto"),
    (libc::SYS_recvfrom, "recvfrom"),
    (libc::SYS_setsockopt, "setsockopt"),
    (libc::SYS_getsockopt, "getsockopt"),
    (libc::SYS_getsockname, "getsockname"),
    (libc::SYS_getpeername, "getpeername"),
    (libc::SYS_shutdown, "shutdown"),
    (libc::SYS_socketpair, "socketpair"),
    // Restartable sequences, should the C library register them for a thread.
    #[cfg(target_arch = "aarch64")]
    (293, "rseq"),
    #[cfg(target_arch = "x86_64")]
    (334, "rseq"),
    #[cfg(target_arch = "x86_64")]
    (libc::SYS_poll, "poll"),
    #[cfg(target_arch = "x86_64")]
    (libc::SYS_arch_prctl, "arch_prctl"),
];

/// ioctl commands allowed: descriptor flags and the bytes waiting on a socket.
const IOCTLS: &[u32] = &[0x5421 /* FIONBIO */, 0x541B /* FIONREAD */, 0x5451 /* FIOCLEX */, 0x5450 /* FIONCLEX */];

/// The filter for a process `pid` whose children lead the process groups `groups` (its VM manager). `default` is
/// what happens to any other call: RET_KILL_PROCESS on user builds, RET_LOG on debuggable builds, RET_USER_NOTIF in
/// the host test.
pub fn build(pid: u32, groups: &[u32], default: u32) -> Vec<Insn> {
    build_with(pid, groups, default, ALLOWED)
}

/// The same with another list (the host test's trace runs with none).
pub fn build_with(pid: u32, groups: &[u32], default: u32, allowed: &[(libc::c_long, &str)]) -> Vec<Insn> {
    let ld = |k| Insn { code: BPF_LD_W_ABS, jt: 0, jf: 0, k };
    let ret = |k| Insn { code: BPF_RET_K, jt: 0, jf: 0, k };
    let jeq = |k, jt, jf| Insn { code: BPF_JEQ_K, jt, jf, k };
    let deny = RET_ERRNO | libc::EPERM as u32;
    let mut p = vec![ld(ARCH), jeq(AUDIT_ARCH, 1, 0), ret(RET_KILL_PROCESS), ld(NR)];
    // Signals with a pid in the first argument: only fsvmd's own, and for kill its VM manager's process group (a
    // negative pid).
    let groups: Vec<u32> = groups.iter().map(|g| (*g as i32).wrapping_neg() as u32).collect();
    for nr in [libc::SYS_kill, libc::SYS_tgkill, libc::SYS_rt_sigqueueinfo, libc::SYS_rt_tgsigqueueinfo] {
        let mut targets = vec![pid];
        if nr == libc::SYS_kill {
            targets.extend(&groups);
        }
        let n = targets.len();
        p.extend([jeq(nr as u32, 0, (n + 3) as u8), ld(arg_lo(0))]);
        for (i, t) in targets.iter().enumerate() {
            p.push(jeq(*t, (n - i) as u8, 0));
        }
        p.extend([ret(deny), ret(RET_ALLOW)]);
    }
    // Never: a thread id may be any process's, and pidfds of other processes.
    for nr in [libc::SYS_tkill, SYS_PIDFD_OPEN, SYS_PIDFD_GETFD] {
        p.extend([jeq(nr as u32, 0, 1), ret(deny)]);
    }
    // Threads only, no new process. clone3 passes its flags in memory, which a filter cannot read: ENOSYS, so libc
    // uses clone.
    p.extend([
        jeq(libc::SYS_clone as u32, 0, 4),
        ld(arg_lo(0)),
        Insn { code: BPF_JSET_K, jt: 0, jf: 1, k: libc::CLONE_THREAD as u32 },
        ret(RET_ALLOW),
        ret(default),
    ]);
    p.extend([jeq(SYS_CLONE3 as u32, 0, 1), ret(RET_ERRNO | libc::ENOSYS as u32)]);
    // Unix sockets only.
    p.extend([jeq(libc::SYS_socket as u32, 0, 4), ld(arg_lo(0)), jeq(libc::AF_UNIX as u32, 0, 1), ret(RET_ALLOW), ret(default)]);
    // ioctl: the few commands above.
    p.extend([jeq(libc::SYS_ioctl as u32, 0, (IOCTLS.len() + 3) as u8), ld(arg_lo(1))]);
    for (i, cmd) in IOCTLS.iter().enumerate() {
        p.push(jeq(*cmd, (IOCTLS.len() - i) as u8, 0));
    }
    p.extend([ret(default), ret(RET_ALLOW)]);
    for (nr, _) in allowed {
        p.extend([jeq(*nr as u32, 0, 1), ret(RET_ALLOW)]);
    }
    p.push(ret(default));
    p
}

/// The name of a system call in ALLOWED or a special rule, for logs.
pub fn name(nr: libc::c_long) -> String {
    ALLOWED.iter().find(|(n, _)| *n == nr).map(|(_, s)| s.to_string()).unwrap_or_else(|| format!("#{nr}"))
}

#[repr(C)]
struct Prog {
    len: u16,
    filter: *const Insn,
}

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;

/// Installs `filter` with `flags`. Returns what seccomp returned (a listener descriptor with NEW_LISTENER).
pub fn install(filter: &[Insn], flags: libc::c_uint) -> Result<libc::c_long> {
    ensure!(filter.len() < u16::MAX as usize, "filter too long");
    // SAFETY: prctl with these arguments only sets no_new_privs for this process.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    ensure!(r == 0, "no_new_privs: {}", std::io::Error::last_os_error());
    let prog = Prog { len: filter.len() as u16, filter: filter.as_ptr() };
    // SAFETY: seccomp reads the program, which stays valid for the call. The kernel copies it.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog as *const Prog) };
    ensure!(r >= 0, "seccomp: {}", std::io::Error::last_os_error());
    Ok(r)
}

/// Whether this is a debuggable build (ro.debuggable=1): the filter then logs instead of killing.
#[cfg(target_os = "android")]
pub fn debuggable() -> bool {
    let mut v = [0u8; 92]; // PROP_VALUE_MAX
    // SAFETY: __system_property_get writes at most PROP_VALUE_MAX bytes into `v`, NUL-terminated.
    let n = unsafe { libc::__system_property_get(c"ro.debuggable".as_ptr(), v.as_mut_ptr().cast()) };
    n == 1 && v[0] == b'1'
}

#[cfg(not(target_os = "android"))]
pub fn debuggable() -> bool {
    true
}

/// The children of this process (its VM manager), from /proc.
fn own_children() -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        for t in tasks.flatten() {
            if let Ok(c) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(c.split_whitespace().filter_map(|p| p.parse::<u32>().ok()));
            }
        }
    }
    out
}

/// fsvmd's own filter: kill on user builds, log on debuggable builds, on every thread. Its VM manager runs already.
pub fn install_for_fsvmd() -> Result<&'static str> {
    let debuggable = debuggable();
    let default = if debuggable { RET_LOG } else { RET_KILL_PROCESS };
    let children = own_children();
    ensure!(children.len() <= 4, "{} children before the filter", children.len());
    install(&build(std::process::id(), &children, default), SECCOMP_FILTER_FLAG_TSYNC)?;
    Ok(if debuggable { "logging" } else { "killing" })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the program on one call, as the kernel would: the action it returns.
    fn eval(p: &[Insn], nr: libc::c_long, args: [u64; 6]) -> u32 {
        let field = |k: u32| -> u32 {
            match k {
                NR => nr as u32,
                ARCH => AUDIT_ARCH,
                k if (16..64).contains(&k) && k % 8 == 0 => args[((k - 16) / 8) as usize] as u32,
                k => panic!("load at {k}"),
            }
        };
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = p[pc];
            pc += 1;
            match i.code {
                BPF_LD_W_ABS => a = field(i.k),
                BPF_JEQ_K => pc += if a == i.k { i.jt } else { i.jf } as usize,
                BPF_JSET_K => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
                BPF_RET_K => return i.k,
                c => panic!("code {c:#x}"),
            }
        }
    }

    #[test]
    fn what_the_filter_decides() {
        let me = 4242u64;
        let p = build(me as u32, &[5000], RET_KILL_PROCESS);
        let eperm = RET_ERRNO | libc::EPERM as u32;
        let call = |nr, args| eval(&p, nr, args);
        // Signals: itself only, on every build.
        assert_eq!(call(libc::SYS_kill, [me, 15, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_kill, [1, 15, 0, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_kill, [u32::MAX as u64, 9, 0, 0, 0, 0]), eperm); // -1: every process
        assert_eq!(call(libc::SYS_kill, [0, 9, 0, 0, 0, 0]), eperm); // its process group
        // The VM manager's process group (vmclient's killpg after the VM manager ended), and no other.
        assert_eq!(call(libc::SYS_kill, [(-5000i32) as u32 as u64, 9, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_kill, [5000, 9, 0, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_kill, [(-5001i32) as u32 as u64, 9, 0, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_tgkill, [(-5000i32) as u32 as u64, 1, 9, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_tgkill, [me, 4243, 6, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_tgkill, [7, 7, 9, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_tkill, [me, 9, 0, 0, 0, 0]), eperm);
        assert_eq!(call(libc::SYS_rt_sigqueueinfo, [8, 9, 0, 0, 0, 0]), eperm);
        assert_eq!(call(SYS_PIDFD_OPEN, [1, 0, 0, 0, 0, 0]), eperm);
        assert_eq!(call(SYS_PIDFD_SEND_SIGNAL, [5, 15, 0, 0, 0, 0]), RET_ALLOW);
        // Threads, never processes.
        let thread = (libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u64;
        assert_eq!(call(libc::SYS_clone, [thread, 0, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_clone, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(call(SYS_CLONE3, [0; 6]), RET_ERRNO | libc::ENOSYS as u32);
        assert_eq!(call(libc::SYS_execve, [0; 6]), RET_KILL_PROCESS);
        // Unix sockets only, and the few ioctls.
        assert_eq!(call(libc::SYS_socket, [libc::AF_UNIX as u64, 2, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_socket, [libc::AF_INET as u64, 2, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(call(libc::SYS_socket, [libc::AF_VSOCK as u64, 1, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(call(libc::SYS_ioctl, [3, 0x5421, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_ioctl, [3, 0x541B, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(call(libc::SYS_ioctl, [3, 0x40086602, 0, 0, 0, 0]), RET_KILL_PROCESS);
        // The list, and nothing beyond it.
        for (nr, name) in ALLOWED {
            assert_eq!(call(*nr, [0; 6]), RET_ALLOW, "{name}");
        }
        for nr in [libc::SYS_ptrace, libc::SYS_mount, libc::SYS_unshare, libc::SYS_bpf, libc::SYS_execveat] {
            assert_eq!(call(nr, [0; 6]), RET_KILL_PROCESS, "{nr}");
        }
        // Debuggable builds log instead of killing, and still refuse signals to others.
        let d = build(me as u32, &[], RET_LOG);
        assert_eq!(eval(&d, libc::SYS_execve, [0; 6]), RET_LOG);
        assert_eq!(eval(&d, libc::SYS_kill, [1, 9, 0, 0, 0, 0]), eperm);
    }

    #[test]
    fn jumps_stay_inside_the_program() {
        let p = build(1234, &[1300], RET_KILL_PROCESS);
        for (i, insn) in p.iter().enumerate() {
            if insn.code == BPF_JEQ_K || insn.code == BPF_JSET_K {
                assert!(i + 1 + (insn.jt as usize) < p.len() && i + 1 + (insn.jf as usize) < p.len(), "jump at {i}");
            }
        }
        assert_eq!(p.last().unwrap().k, RET_KILL_PROCESS);
        let mut nrs: Vec<_> = ALLOWED.iter().map(|(n, _)| *n).collect();
        nrs.sort();
        nrs.dedup();
        assert_eq!(nrs.len(), ALLOWED.len(), "a call listed twice");
        // Process creation, program start and debugging are never on the list.
        for nr in [libc::SYS_execve, libc::SYS_execveat, libc::SYS_ptrace, libc::SYS_process_vm_readv,
                   libc::SYS_process_vm_writev, libc::SYS_kill, libc::SYS_tkill, SYS_PIDFD_OPEN,
                   libc::SYS_mount, libc::SYS_unshare, libc::SYS_setns, libc::SYS_bpf, libc::SYS_perf_event_open] {
            assert!(!nrs.contains(&nr), "{nr} must not be allowed outright");
        }
    }
}
