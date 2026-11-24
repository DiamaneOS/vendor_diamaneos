# fsvm: SD cards and USB drives mounted in a protected VM

Android's kernel parses neither the partition table nor the filesystem of an SD card or USB drive, nor an app's OBB
image. A small protected VM with its own Linux kernel reads them, and `fsvmd` serves the files to Android through FUSE
after checking everything the VM sends.

```
card -> fsvmd --probe: the VM reads the partition table, fsvmd checks it (proto/src/layout.rs), vold makes volumes
card -> vold (opens the whole disk, runs fsck in fsck_untrusted on a partition added for the check, mounts FUSE)
     -> fsvmd (system user, no capabilities, SELinux domain fsvmd)
     -> protected VM: our guest kernel parses FAT or exFAT, fsvm_guest_init serves files over vsock
     -> fsvmd checks every reply (fsvm_proto) -> FUSE at /mnt/media_rw/<uuid> -> MediaProvider's FUSE as before
```

## Layout

- `proto/`: the protocol and the checking client (`libfsvm_proto`), with unit tests and tests against a hostile
  server (`cargo test` on any machine, `fsvm_proto_test` and `fsvm_proto_hostile_test` in the tree).
- `fsvmd/`: the daemon that serves the public partitions of a card or USB drive, all from one VM per drive (each
  partition a disk of that VM and a range of its own), and OBB images. vold asks init's fsvmd service (`fsvmd_launcher`,
  `fsvmd.rc`, `launcher.rs`, a domain of its own) to start one, as the system user without capabilities. Before
  every orderly stop fsvmd has the VM write the volume back and unmount it, so an eject loses nothing.
- `guest/`: the VM's `/init` (`fsvm_guest_init`, static), its partition table reader (`table.c`, host-tested by
  `fsvm_guest_table_test` on hostile tables) and its initramfs (`fsvm_guest_initrd`). `fsvm_guest_initrd_selftest`
  is the same with a self test for the host harness (`scripts/p2-harness.py`), in no image.
- `kernel/`: the phase 2 kernel change (`CONFIG_BLK_NO_EXTERNAL_PART_SCAN`, kernel_common-6.18 and kernel_qcom-6.18).
- `patches/`: the changes to system/vold, packages/modules/Virtualization, external/crosvm and vendor/diamaneos, and
  in `patches/p2/` phase 2 on top of them, plus frameworks/base (the failure notice).
- `scripts/`: branch, build and phone scripts (`p2-*` for phase 2).
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
- **No partition table in Android's kernel:** SD cards and USB disks get `GENHD_FL_USER_PART`. Only vold may add a
  partition (SELinux `allowxperm` BLKPG), one at a time (the kernel), and only the adoptable storage partition or a
  public one for the time of an fsck or format, at the range the VM read and fsvmd checked.
- **A card the VM cannot open is not "corrupted":** vold reports it as `VOLUME_STATE_UNOPENABLE` and SystemUI shows a
  plain notice without a format offer.
