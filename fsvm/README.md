# fsvm: SD cards and USB drives mounted in a protected VM

Android's kernel does not parse the filesystem of an SD card or USB drive. A small protected VM with its own Linux
kernel mounts it, and `fsvmd` serves the files to Android through FUSE after checking everything the VM sends.

```
card -> vold (opens the block device, runs fsck in fsck_untrusted, mounts FUSE)
     -> fsvmd (system user, no capabilities, SELinux domain fsvmd)
     -> protected VM: our guest kernel parses FAT or exFAT, fsvm_guest_init serves files over vsock
     -> fsvmd checks every reply (fsvm_proto) -> FUSE at /mnt/media_rw/<uuid> -> MediaProvider's FUSE as before
```

## Layout

- `proto/`: the protocol and the checking client (`libfsvm_proto`), with unit tests and tests against a hostile
  server (`cargo test` on any machine, `fsvm_proto_test` and `fsvm_proto_hostile_test` in the tree).
- `fsvmd/`: the daemon vold starts for each public volume.
- `guest/`: the VM's `/init` (`fsvm_guest_init`, static) and its initramfs (`fsvm_guest_initrd`).
- `Android.bp`.

The guest kernel and its signing live in `packages/modules/Virtualization` (`guest/diamaneos`), so that release
signing signs the kernel again with the key pvmfw trusts. vold's side is `fs/Fsvm.cpp` in `system/vold`.

## Rules

- **Fail closed:** if the VM does not serve the volume, the volume is not mounted. No code path mounts FAT or exFAT
  in Android's kernel on a build with `diamaneos.fs_in_vm`. No setting turns it off.
- **Nothing unchecked:** names must pass `proto/src/names.rs`, sizes, times, counts and lengths are bounded, every
  call has a total deadline, and owner, group and mode come from vold, never from the card. A malformed reply ends
  the session, and the volume then answers EIO until it is mounted again.
- **The VM keeps no state:** a fresh instance disk in memory each start.
