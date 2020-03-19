#!/usr/bin/env python3

import string
import time

from base64 import b64decode

from pwn import *

ALPHABET = string.ascii_letters


def gen_sample():
    p = ''.join([
        ALPHABET[random.randint(0, len(ALPHABET) - 1)]
        for _ in range(random.randint(1, 30))
    ])
    k = ''.join([
        ALPHABET[random.randint(0, len(ALPHABET) - 1)]
        for _ in range(len(p))
    ])
    x = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(p, k))

    return x, p, k


def try_sample(given_x, given_k):
    x, p, k = gen_sample()
    return x == given_x and k == given_k


def get_flag(io, seed):
    random.seed(seed)

    gen_sample()
    x, p, k = gen_sample()

    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'Your answer: ')
    io.sendline(p.encode())

    return io.recvline().decode()


def main():
    io = remote('misc.2020.chall.actf.co', 20301)

    start_time = int(time.time())
    random.seed(start_time)

    io.recvuntil(b'> ')
    io.sendline(b'1')

    resp = io.recvline().decode().strip()
    raw_given_x, raw_given_k = resp.split(' with key ')
    given_x = b64decode(raw_given_x).decode()
    given_k = b64decode(raw_given_k).decode()

    for maybe_seed in range(start_time - 100, start_time + 100):
        random.seed(maybe_seed)
        if try_sample(given_x, given_k):
            log.info(f'Found seed {maybe_seed}')
            print(get_flag(io, maybe_seed))


if __name__ == '__main__':
    main()
