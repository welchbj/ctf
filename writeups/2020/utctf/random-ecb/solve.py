#!/usr/bin/env python3

import binascii
import sys

from pwn import *

"""
Run against local with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=ecb.utctf.live PORT=9003
"""

BLOCK_LEN = 16
PT_PREFIX = b'A'*(BLOCK_LEN*2-1)
ALPHABET = [bytes([i]) for i in range(32, 128)]


def init_io():
    if args['REMOTE']:
        io = remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        io = process('./server.py', stdin=pty, stdout=pty, stderr=pty)

    return io


def encrypt(io, pt):
    io.recvuntil('to quit):\n')
    io.sendline(pt)
    io.recvuntil('day :)\n')
    encoded_ct = io.recvline().rstrip(b'\n')
    return binascii.unhexlify(encoded_ct)


def encrypt_ensure_prepended_a(io, pt):
    while True:
        ct = encrypt(io, pt)
        if is_ct_prepended_with_a(ct):
            return ct


def get_block(ct, idx):
    return ct[idx*BLOCK_LEN:(idx+1)*BLOCK_LEN]


def num_blocks(pt_or_ct):
    assert not (len(pt_or_ct) % BLOCK_LEN)
    return len(pt_or_ct) // BLOCK_LEN


def is_ct_prepended_with_a(ct):
    return get_block(ct, 0) == get_block(ct, 1)


def leak_flag_len(io):
    while True:
        ct = encrypt_ensure_prepended_a(io, PT_PREFIX)
        flag_num_blocks = num_blocks(ct) - 2
        break

    offset = 1
    while True:
        pt = PT_PREFIX + b'B'*offset
        ct = encrypt_ensure_prepended_a(io, pt)

        non_a_num_ct_blocks = num_blocks(ct) - 2
        if non_a_num_ct_blocks > flag_num_blocks:
            return (
                (flag_num_blocks-1)*BLOCK_LEN +
                (BLOCK_LEN-offset)
            )

        offset += 1


def leak_flag_contents(io, flag_len):
    char_idx = 0
    flag = b''

    while len(flag) < flag_len:
        flag_block_idx = char_idx // BLOCK_LEN
        padding_offset = (
            BLOCK_LEN - (char_idx % BLOCK_LEN) - 1
        )
        pt = PT_PREFIX + b'B'*padding_offset

        flag_ct = encrypt_ensure_prepended_a(io, pt)
        for c in ALPHABET:
            candidate_ct = encrypt_ensure_prepended_a(io, pt+flag+c)
            if (
                get_block(candidate_ct, flag_block_idx+2) ==
                get_block(flag_ct, flag_block_idx+2)
            ):
                flag += c
                yield c
                break
        else:
            log.error('No candidate characters worked!')
            sys.exit(1)

        char_idx += 1


if __name__ == '__main__':
    io = init_io()

    flag_len = leak_flag_len(io)
    log.info(f'Leaked flag length of {flag_len}')

    log.info('Leaking flag...')
    for c in leak_flag_contents(io, flag_len):
        print(c.decode(), end='')

    print()
