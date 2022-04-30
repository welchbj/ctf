#!/usr/bin/env python3

import itertools

from pwn import disasm

for a, b in itertools.product(range(0xff+1), repeat=2):
    a_lsb = a & 1
    b_lsb = b & 1

    if a_lsb == b_lsb:
        continue

    disassembled = disasm(bytes([a, b]))
    if ".byte" in disassembled:
        continue

    print(disassembled)
