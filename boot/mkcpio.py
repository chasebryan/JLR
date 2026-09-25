#!/usr/bin/env python3
"""Deterministic 'newc' cpio writer for initramfs images.

Entries are sorted by path; inode numbers are sequential; owner is root; all
times are SOURCE_DATE_EPOCH (default 1). The same tree therefore always yields
the same bytes, independent of the build machine's inode numbers.

usage: mkcpio.py DIR > archive.cpio
"""
import os
import stat
import sys

EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "1"))


def header(ino, mode, nlink, size, name):
    fields = [ino, mode, 0, 0, nlink, EPOCH, size, 0, 0, 0, 0, len(name) + 1, 0]
    return b"070701" + b"".join(b"%08X" % f for f in fields) + name.encode() + b"\0"


def pad(n):
    return b"\0" * (-n % 4)


def main():
    root = sys.argv[1]
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for n in dirnames + filenames:
            entries.append(os.path.join(dirpath, n))
    entries.sort(key=lambda p: os.path.relpath(p, root).encode())
    out = sys.stdout.buffer
    ino = 1
    for path in entries:
        rel = os.path.relpath(path, root)
        st = os.lstat(path)
        mode = st.st_mode
        if stat.S_ISREG(mode):
            data = open(path, "rb").read()
        elif stat.S_ISLNK(mode):
            data = os.readlink(path).encode()
        else:
            data = b""
        nlink = 2 if stat.S_ISDIR(mode) else 1
        h = header(ino, mode, nlink, len(data), rel)
        out.write(h + pad(len(h)) + data + pad(len(data)))
        ino += 1
    trailer = header(0, 0, 1, 0, "TRAILER!!!")
    out.write(trailer + pad(len(trailer)))


main()
