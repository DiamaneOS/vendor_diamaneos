#!/usr/bin/env python3
# Copyright (C) 2026 DiamaneOS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""mkinitrd.py OUT INIT [NAME=BINARY ...]: the filesystem VM's initramfs, a newc cpio archive with /init, the empty
directories it mounts on (dev, proc, sys, mnt) and the checkers in /bin (fsck_msdos=..., fsck.exfat=...). Fixed
owners, modes and times, so the same binaries always give the same bytes and the same signature."""

import sys


def entry(name, mode, data=b"", ino=1):
    name_b = name.encode() + b"\0"
    fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_b), 0]
    head = b"070701" + b"".join(b"%08X" % f for f in fields)
    out = head + name_b
    out += b"\0" * (-len(out) % 4)
    out += data
    out += b"\0" * (-len(out) % 4)
    return out


def main():
    out, init = sys.argv[1], sys.argv[2]
    with open(init, "rb") as f:
        init_data = f.read()
    entries = [
        entry("bin", 0o040755, ino=1),
        entry("dev", 0o040755, ino=2),
        entry("mnt", 0o040755, ino=3),
        entry("proc", 0o040555, ino=4),
        entry("sys", 0o040555, ino=5),
        entry("init", 0o100755, init_data, ino=6),
    ]
    for i, arg in enumerate(sorted(sys.argv[3:])):
        name, path = arg.split("=", 1)
        assert name and "/" not in name, name
        with open(path, "rb") as f:
            entries.append(entry("bin/" + name, 0o100755, f.read(), ino=7 + i))
    entries.append(entry("TRAILER!!!", 0, ino=0))
    archive = b"".join(entries)
    archive += b"\0" * (-len(archive) % 512)
    with open(out, "wb") as f:
        f.write(archive)


if __name__ == "__main__":
    main()
