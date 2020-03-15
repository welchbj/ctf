#!/usr/bin/env python3

import binascii
import itertools

CT = binascii.unhexlify(
    '1921754512366910363569105a73727c592c5e5701715e571b76304d3625317c1b72744d'
    '0d1d354d0d1d73131c2c655e'
)


def xor(one: bytes, two: bytes) -> bytes:
    """XOR, re-cycling two if len(one) > len(two)."""
    assert len(one) >= len(two)
    return bytes([
        a ^ b for a, b in zip(one, itertools.cycle(two))
    ])


def main():
    known_pt = b'pctf'
    candidate_keys = [
        xor(CT[i:i+len(known_pt)], known_pt)
        for i in range(len(known_pt))
    ]

    for ck in candidate_keys:
        print(xor(CT, ck))


if __name__ == '__main__':
    main()
