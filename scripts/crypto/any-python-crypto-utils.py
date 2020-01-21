#!/usr/bin/env python


def xor_bytes(a, b):
    """Repeats b if a is longer."""
    xored = bytearray()
    for i in range(len(a)):
        next_byte = a[i] ^ b[i % len(b)]
        xored.append(next_byte)
    return b''.join(bytes(x) for x in xored)
