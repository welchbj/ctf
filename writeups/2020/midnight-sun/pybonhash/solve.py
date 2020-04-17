#!/usr/bin/env python3

import binascii
import itertools

from Crypto.Cipher import AES

HASH_LEN = 32
DATA_LEN = 204
KEY_LEN = 42

FIB_OFFSET = 4919


def fib_seq(n):
    out = [0, 1]
    for i in range(2, n):
        out.append(out[(i - 1)] + out[(i - 2)])
    return out


def gen_keys():
    keys = []
    for a, b in itertools.product(range(256), range(256)):
        keys.append(bytes([a, b]) * 16)
    return keys


def valid_hash(h):
    return all(chr(x).isalnum() for x in h)


def is_printable(c):
    return c >= 32 and c <= 127


def print_key(key):
    for i in key:
        s = '?' if i == -1 else chr(i)
        print(s, end='')
    print()


def main():
    FIB = fib_seq(KEY_LEN + DATA_LEN + FIB_OFFSET)
    KEY = [-1 for _ in range(KEY_LEN)]

    with open('hash.txt', 'rb') as f:
        hash_blob = f.read().rstrip(b'\n')

    possible_keys = gen_keys()
    block_num = 0
    i = 0
    while i < DATA_LEN:
        hash_block = hash_blob[block_num * 64:(block_num + 1) * 64]
        enc_data_block = binascii.unhexlify(hash_block)
        block_num += 1

        key1_pos = (i + FIB[FIB_OFFSET + i]) % KEY_LEN
        i += 1

        key2_pos = (i + FIB[FIB_OFFSET + i]) % KEY_LEN
        i += 1

        for possible_key in possible_keys:
            pt = AES.new(possible_key, AES.MODE_ECB).decrypt(enc_data_block)
            if valid_hash(pt):
                KEY[key1_pos] = possible_key[0]
                KEY[key2_pos] = possible_key[1]
                print_key(KEY)
                break


if __name__ == '__main__':
    main()
