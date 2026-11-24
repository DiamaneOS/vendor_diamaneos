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

//! Starts the filesystem VM: a raw protected VM with the guest kernel and the fsvm initramfs from the
//! virtualization APEX, its disks first (the whole disk of a probe, an OBB image, or each public partition of one
//! drive), all given at its start, and a fresh instance disk in memory last.

use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
    CpuOptions::CpuOptions, CpuOptions::CpuTopology::CpuTopology, DiskImage::DiskImage,
    IVirtualizationService::IVirtualizationService, Partition::Partition, PartitionType::PartitionType,
    VirtualMachineConfig::VirtualMachineConfig, VirtualMachineRawConfig::VirtualMachineRawConfig,
};
use anyhow::{bail, Context, Result};
use binder::{ParcelFileDescriptor, Strong};
use log::{info, warn};
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
use vmclient::{DeathReason, VirtualizationService, VmInstance};

/// The guest kernel and initramfs. Both ship in the virtualization APEX, where release signing signs the kernel
/// again with the key pvmfw trusts. The kernel's footer covers the initramfs, so pvmfw refuses either if changed.
const KERNEL: &str = "/apex/com.android.virt/etc/fs/fsvm_kernel";
const INITRD: &str = "/apex/com.android.virt/etc/fsvm_initrd.img";
/// The instance disk pvmfw needs for a protected VM. The VM keeps no state, so a fresh one each start.
const INSTANCE_SIZE: i64 = 10 << 20;

/// fsvmd's VM manager: started once, before fsvmd's seccomp filter (seccomp.rs), so that neither it nor the crosvm it
/// starts inherits the filter, and kept for fsvmd's life. Every VM fsvmd starts (the first, and new ones after a
/// broken session) comes from it.
pub struct Manager {
    service: VirtualizationService,
    manager: Strong<dyn IVirtualizationService>,
}

impl Manager {
    pub fn spawn() -> Result<Manager> {
        let service = VirtualizationService::new().context("starting the VM manager")?;
        let manager = service.connect().context("connecting to the VM manager")?;
        Ok(Manager { service, manager })
    }

    /// The VM manager's pid, from its spawn: the leader of the process group vmclient kills when the VM manager ended.
    /// /proc cannot say it: the VM manager runs with a file capability and fsvmd with none, so /proc (hidepid) hides it.
    pub fn pid(&self) -> u32 {
        self.service.pid()
    }
}

pub struct Vm {
    instance: VmInstance,
}

fn memfd(name: &CStr) -> Result<File> {
    // SAFETY: memfd_create takes a NUL-terminated name and flags and returns a new descriptor or -1.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        bail!("memfd_create: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fd is a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Vm {
    /// Starts the VM with `volumes` as its disks, vda first, all writable or none.
    pub fn start(m: &Manager, volumes: Vec<File>, writable: bool, memory_mib: u32) -> Result<Vm> {
        let manager = &m.manager;
        if volumes.is_empty() {
            bail!("a VM without a disk");
        }

        let instance_image = memfd(c"fsvm-instance")?;
        instance_image.set_len(INSTANCE_SIZE as u64)?;
        manager
            .initializeWritablePartition(
                &ParcelFileDescriptor::new(instance_image.try_clone()?),
                INSTANCE_SIZE,
                PartitionType::ANDROID_VM_INSTANCE,
            )
            .context("instance disk")?;
        let instance_id = manager.allocateInstanceId().context("instance id")?;

        // vda, vdb...: the volumes. The VM manager passes each to crosvm as a raw disk, never a guessed format.
        let mut disks: Vec<DiskImage> = volumes
            .into_iter()
            .map(|v| DiskImage { image: Some(ParcelFileDescriptor::new(v)), writable, partitions: vec![], id: None })
            .collect();
        // Last: the instance disk, which no connection can name (fsvmd asks only for the volumes).
        disks.push(DiskImage {
            image: None,
            writable: true,
            partitions: vec![Partition {
                label: "vm-instance".into(),
                image: Some(ParcelFileDescriptor::new(instance_image)),
                writable: true,
                guid: None,
            }],
            id: None,
        });
        let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
            name: "fsvm".into(),
            instanceId: instance_id,
            kernel: Some(ParcelFileDescriptor::new(File::open(KERNEL).context(KERNEL)?)),
            initrd: Some(ParcelFileDescriptor::new(File::open(INITRD).context(INITRD)?)),
            params: None,
            disks,
            protectedVm: true,
            memoryMib: memory_mib as i32,
            cpuOptions: CpuOptions { cpuTopology: CpuTopology::CpuCount(1) },
            platformVersion: "~1.0".into(),
            ..Default::default()
        });
        let instance = VmInstance::create(manager.as_ref(), &config, None, None, None, None)
            .context("creating the VM")?;
        instance.start(None).context("starting the VM")?;
        info!("filesystem VM started, CID {}, {} MiB", instance.cid(), memory_mib);
        Ok(Vm { instance })
    }

    /// Connects to the VM's server, retrying while it boots. Before the guest runs, crosvm lends all of the VM's
    /// memory to the hypervisor: memory from the pool at once, ordinary memory at about a millisecond for each
    /// physically separate piece, so up to about 20 s once free memory is scattered. A VM that ended meanwhile (its
    /// start refused, or the guest stopped) ends the wait at once.
    pub fn connect(&self, port: u32, within: Duration) -> Result<UnixStream> {
        let started = Instant::now();
        let deadline = started + within;
        let mut said: Option<Instant> = None;
        loop {
            match self.instance.connect_vsock(port) {
                Ok(pfd) => {
                    if said.is_some() {
                        info!("VM answered after {:?}", started.elapsed());
                    }
                    // SAFETY: the descriptor comes from the VM manager and is owned only by `pfd`, which gives it
                    // up here. std only reads, writes and sets socket timeouts on it, which work on vsock.
                    return Ok(unsafe { UnixStream::from_raw_fd(pfd.into_raw_fd()) });
                }
                Err(e) => {
                    if let Some(reason) = self.instance.wait_for_death_with_timeout(Duration::from_millis(100)) {
                        bail!("the VM ended after {:?} before it answered: {reason:?}", started.elapsed());
                    }
                    if Instant::now() >= deadline {
                        bail!("VM did not answer within {within:?}: {e:?}");
                    }
                    // One line at the first miss and one every 5 s, not one per try.
                    let due = match said {
                        None => true,
                        Some(at) => at.elapsed() >= Duration::from_secs(5),
                    };
                    if due {
                        warn!("VM not answering yet after {:?}: {e:?}", started.elapsed());
                        said = Some(Instant::now());
                    }
                }
            }
        }
    }

    /// Whether the VM ended because its start was refused (crosvm failed to make the VM: no pool room, and its
    /// ordinary memory past the budget of pieces of all running VMs).
    pub fn refused_at_start(&self) -> bool {
        self.instance.wait_for_death_with_timeout(Duration::ZERO) == Some(DeathReason::StartFailed)
    }

    /// Whether the VM ended, for whatever reason.
    pub fn ended(&self) -> bool {
        self.instance.wait_for_death_with_timeout(Duration::ZERO).is_some()
    }

    pub fn stop(&self) {
        if let Err(e) = self.instance.stop() {
            warn!("stopping the VM: {e:?}");
        }
    }

    /// Stops the VM and waits up to `within` for an affirmative child exit.
    pub fn stop_and_wait(&self, within: Duration) -> bool {
        self.stop();
        let reason = self.instance.wait_for_death_with_timeout(within);
        // These reasons come from virtmgr's successful crosvm child wait. Manager death and
        // InfrastructureError (including a failed child wait) carry no such evidence.
        let stopped = matches!(
            reason,
            Some(DeathReason::Killed | DeathReason::Shutdown | DeathReason::Reboot |
                DeathReason::Crash | DeathReason::Hangup)
        );
        if !stopped {
            warn!("the VM's exit was not confirmed within {within:?}: {reason:?}");
        }
        stopped
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.stop();
    }
}
