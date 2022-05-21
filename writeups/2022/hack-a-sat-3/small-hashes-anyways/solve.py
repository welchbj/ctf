#!/usr/bin/env python3

import os
import string
from contextlib import contextmanager

from pwn import *

alphabet = string.printable

def try_input(candidate, offset):
    io = process(["sudo", "chroot", ".", "./qemu-microblaze-static", "./small_hashes_anyways"])

    io.sendlineafter(b"small hashes anyways: \n", candidate.encode())
    io.recvuntil(b"mismatch ")
    mismatch_offset = int(io.recvuntil(b" wanted", drop=True).decode())

    io.kill()
    return mismatch_offset-1

def main():
    flag = "flag{juliet45984bravo3:"
    while len(flag) < 111:
        for candidate in alphabet:
            candidate_flag = flag + candidate
            candidate_flag += "A"*(111-len(candidate_flag))

            num_correct_chars = try_input(candidate_flag, offset=len(flag)+1)
            if num_correct_chars > len(flag):
                flag = candidate_flag[:num_correct_chars]
                print(flag)
                break
        else:
            log.error("Exhausted search!")

@contextmanager
def cwd(path):
    oldpwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(oldpwd)

if __name__ == "__main__":
    with cwd("microblaze-linux/"):
        main()
