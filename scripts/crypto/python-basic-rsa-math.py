#!/usr/bin/env python3

# implementation of pure RSA in python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime

def rsa_encrypt(m: int, e: int, n: int):
    c = pow(m, e, n)
    return c

def rsa_decrypt(c: int, e: int, n: int, p: int):
    q = n // p

    try:
        assert p * q == n
    except AssertionError:
        raise AssertionError("Error: specified factor of n not valid")

    totient_n = (p - 1) * (q - 1)
    d = pow(e, -1, totient_n)
    m = pow(c, d, n)
    return m
    
def rsa_example():
    # encrypting
    p = getPrime(128)
    q = getPrime(128)
    n = p * q
    e = 65537

    m = b"rsa is cool"
    m = bytes_to_long(m)
    c = rsa_encrypt(m, e, n)
    
    # decrypting
    decrypted_m = rsa_decrypt(c, e, n, p)
    decrypted_m = long_to_bytes(decrypted_m)
    print(decrypted_m)

rsa_example()