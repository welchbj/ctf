#!/usr/bin/env python2

from __future__ import print_function

import string

from pwn import *

NUM_PROBLEMS = 50
ALPHABET = string.ascii_uppercase


def get_fib_numbers():
    with open('fib.lst', 'r') as f:
        return [
            int(line.strip()) for line in f.readlines()
            if line.strip()
        ]


def caesar(pt, n):
    return ''.join(
        ALPHABET[(ALPHABET.index(c) + n) % len(ALPHABET)]
        for c in pt
    )


def main():
    fib_nums = get_fib_numbers()
    io = remote('misc.2020.chall.actf.co', 20300)

    for i in range(NUM_PROBLEMS):
        log.info('On problem %d' % i)

        io.recvuntil('Shift ')
        shift_input = io.recvuntil(' by ', drop=True)

        io.recvuntil('n=')
        fib_index = int(io.recvuntil('\n', drop=True))
        fib_num = fib_nums[fib_index]

        io.recvuntil(': ')
        io.sendline(caesar(shift_input, fib_num))

    print(io.recvall())


if __name__ == '__main__':
    main()
