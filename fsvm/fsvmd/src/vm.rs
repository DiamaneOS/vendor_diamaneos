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

//! Starts the filesystem VM: a raw protected VM with our guest kernel and the fsvm initramfs from the
//! virtualization APEX, the volume as its first disk, and a fresh instance disk in memory.

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
use vmclient::{VirtualizationService, VmInstance};

/// The guest kernel and initramfs. Both ship in the virtualization APEX, where release signing signs the kernel
/// again with the key pvmfw trusts. The kernel's footer covers the initramfs, so pvmfw refuses either if changed.
const KERNEL: &str = "/apex/com.android.virt/etc/fs/fsvm_kernel";
const INITRD: &str = "/apex/com.android.virt/etc/fsvm_initrd.img";
/// The instance disk pvmfw needs for a protected VM. The VM keeps no state, so a fresh one each start.
const INSTANCE_SIZE: i64 = 10 << 20;

pub struct Vm {
    instance: VmInstance,
    // Keeps the VM manager process alive for as long as the VM runs.
    _service: VirtualizationService,
    _manager: Strong<dyn IVirtualizationService>,
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
    /// Starts the VM with `volume` as its first disk.
    pub fn start(volume: File, writable: bool, memory_mib: i32) -> Result<Vm> {
        let service = VirtualizationService::new().context("starting the VM manager")?;
        let manager = service.connect().context("connecting to the VM manager")?;

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

        let config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
            name: "fsvm".into(),
            instanceId: instance_id,
            kernel: Some(ParcelFileDescriptor::new(File::open(KERNEL).context(KERNEL)?)),
            initrd: Some(ParcelFileDescriptor::new(File::open(INITRD).context(INITRD)?)),
            params: None,
            disks: vec![
                // vda: the volume. The VM manager passes it to crosvm as a raw disk, never a guessed format.
                DiskImage { image: Some(ParcelFileDescriptor::new(volume)), writable, partitions: vec![], id: None },
                // vdb: the instance disk.
                DiskImage {
                    image: None,
                    writable: true,
                    partitions: vec![Partition {
                        label: "vm-instance".into(),
                        image: Some(ParcelFileDescriptor::new(instance_image)),
                        writable: true,
                        guid: None,
                    }],
                    id: None,
                },
            ],
            protectedVm: true,
            memoryMib: memory_mib,
            cpuOptions: CpuOptions { cpuTopology: CpuTopology::CpuCount(1) },
            platformVersion: "~1.0".into(),
            ..Default::default()
        });
        let instance = VmInstance::create(manager.as_ref(), &config, None, None, None, None)
            .context("creating the VM")?;
        instance.start(None).context("starting the VM")?;
        info!("filesystem VM started, CID {}, {} MiB", instance.cid(), memory_mib);
        Ok(Vm { instance, _service: service, _manager: manager })
    }

    /// Connects to the VM's server, retrying while it boots.
    pub fn connect(&self, port: u32, within: Duration) -> Result<UnixStream> {
        let deadline = Instant::now() + within;
        loop {
            match self.instance.connect_vsock(port) {
                Ok(pfd) => {
                    // SAFETY: the descriptor comes from the VM manager and is owned only by `pfd`, which gives it
                    // up here. std only reads, writes and sets socket timeouts on it, which work on vsock.
                    return Ok(unsafe { UnixStream::from_raw_fd(pfd.into_raw_fd()) });
                }
                Err(e) if Instant::now() < deadline => {
                    warn!("VM not answering yet: {e:?}");
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => bail!("VM did not answer within {within:?}: {e:?}"),
            }
        }
    }

    pub fn stop(&self) {
        if let Err(e) = self.instance.stop() {
            warn!("stopping the VM: {e:?}");
        }
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.stop();
    }
}
