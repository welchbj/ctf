#!/usr/bin/env python3

"""
Run against local with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=challenges.tamuctf.com PORT=8812
"""

import functools
import hashpumpy

from pwn import *

KNOWN_SIG = (
    'a17b713167841563563ac6903a8bd44801be3c0fb81b086a4816ea457f8c829a6d5d785'
    'b49161972b7e94ff9790d37311e12b32221380041a99c16d765e8776c'
)
KNOWN_DATA = '1'
APPEND_DATA = '1653086069891774904466108141306028536722619133804'
forge_msg = functools.partial(
    hashpumpy.hashpump, KNOWN_SIG, KNOWN_DATA, APPEND_DATA,
)


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        context.log_level = 'debug'
        return process(['/usr/bin/python2', './game.py'])


def try_extension(io, secret_len):
    forged_sig, forged_data = forge_msg(secret_len)

    io.recvuntil(b'Exit\n')
    io.sendline(b'2')
    io.recvuntil(b'reached: \n')
    io.sendline(forged_data)
    io.recvuntil(b'achievement: \n')
    io.sendline(forged_sig)
    return io.recvline()


def main():
    io = init_io()

    for i in range(1, 40):
        log.info(f'Trying secret length of {i}...')
        resp = try_extension(io, i).decode()
        if 'gigem' in resp:
            print(resp)
            break


if __name__ == '__main__':
    main()
