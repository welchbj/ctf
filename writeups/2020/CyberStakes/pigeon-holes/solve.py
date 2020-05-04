#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

Run exploit against remote with:
./solve.py REMOTE HOST=challenge.acictf.com PORT=55353
"""

from __future__ import print_function

import string

from pwn import *

ALPHABET = '_' + string.ascii_letters + string.digits
BANNER = '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n'


def get_encrypted_length(io, guess):
    io.recvuntil(BANNER)
    io.sendlineafter(BANNER, '1')

    vin = 'X' * 17

    name = ('Rev:2::Vin:XXXXXXXXXXXXXXXXX::DeviceKey:' + guess) * 5
    name += ''.join(cyclic(256, alphabet=string.ascii_letters[::-1], n=2))

    io.sendlineafter('VIN: \n', vin)
    io.sendlineafter('Vehicle Name (Blank for default):\n', name)
    io.sendlineafter('Reflash Code? (y/n)\n', 'n')

    io.recvuntil('[X] Fatal Error: Final Firmware Image too large: (')
    raw_len = io.recvuntil(' bytes)', drop=True)
    io.recvline()

    return int(raw_len)


def follow_path(io, flag, expected_len):
    for c in ALPHABET:
        candidate = flag + c
        candidate_len = get_encrypted_length(io, candidate)

        if candidate_len != expected_len:
            continue

        print(candidate, '->', candidate_len)
        follow_path(io, candidate, expected_len)


def main(io):
    start_lens = {}
    for c in ALPHABET:
        length = get_encrypted_length(io, c)
        if length not in start_lens:
            start_lens[length] = []

        start_lens[length].append(c)
    print(start_lens)

    for length in sorted(start_lens):
        chars = start_lens[length]
        for c in chars:
            follow_path(io, c, length)


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))

    with open('./flag', 'w') as f:    
        f.write('th1s_1s_A_Sampl3_flAg')

    with open('./car_code.bin', 'w') as f:
        f.write('A'*64)

    pty = process.PTY
    return process('./run-wrapper.sh', stdin=pty, stdout=pty, stderr=pty)


if __name__ == '__main__':
    io = init_io()
    main(io)