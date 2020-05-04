#!/usr/bin/env python3

import binascii
import requests
import string
import sys

BLOCK_LEN = 16
PT_PREFIX = b'A' * BLOCK_LEN * 2
ALPHABET = [bytes([i]) for i in range(32, 128)]

URL = 'http://challenge.acictf.com:61982'


def encrypt(pt):
    r = requests.post(f'{URL}/register', data=dict(username=pt, password='xx'))
    raw_auth_cookie = r.headers['Set-Cookie']
    encoded_ct = raw_auth_cookie[len('auth_token='):].split(';')[0]
    ct = binascii.unhexlify(encoded_ct)
    return ct


def get_block(ct, idx):
    return ct[idx * BLOCK_LEN:(idx + 1) * BLOCK_LEN]


def num_blocks(pt_or_ct):
    assert not (len(pt_or_ct) % BLOCK_LEN)
    return len(pt_or_ct) // BLOCK_LEN


def leak_secret_len():
    ct = encrypt(PT_PREFIX)
    secret_num_blocks = num_blocks(ct) - 2

    offset = 1
    while True:
        pt = PT_PREFIX + b'B' * offset
        ct = encrypt(pt)

        non_a_num_ct_blocks = num_blocks(ct) - 2
        if non_a_num_ct_blocks > secret_num_blocks:
            return (
                (secret_num_blocks - 1) * BLOCK_LEN +
                (BLOCK_LEN - offset)
            )

        offset += 1


def leak_secret_contents(secret_len):
    char_idx = 0
    secret = b''

    while len(secret) < secret_len:
        secret_block_idx = char_idx // BLOCK_LEN
        padding_offset = (
            BLOCK_LEN - (char_idx % BLOCK_LEN) - 1
        )
        pt = PT_PREFIX + b'B' * padding_offset

        secret_ct = encrypt(pt)

        for c in ALPHABET:
            candidate_ct = encrypt(pt + secret + c)

            if (
                get_block(candidate_ct, secret_block_idx + 2) ==
                get_block(secret_ct, secret_block_idx + 2)
            ):
                secret += c
                yield c
                break
        else:
            print('No candidate characters worked!')
            sys.exit(1)

        char_idx += 1


if __name__ == '__main__':
    # secret_len = leak_secret_len() + 1
    secret_len = 17
    print(f'Leaked secret length of {secret_len}')

    print('Leaking secret...')
    secret = b''
    for c in leak_secret_contents(secret_len):
        secret += c
        print(secret)

    print()