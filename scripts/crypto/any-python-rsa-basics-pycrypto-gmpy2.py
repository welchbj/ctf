#!/usr/bin/env python3

from __future__ import division

import gmpy2
from Crypto.PublicKey import RSA

with open('key.pub', 'r') as f:
    pub_key = RSA.importKey(f.read())

n = pub_key.n  # = p * q
e = pub_key.e  # = gmpy2.divm(1, d, r)

# factor n to get p and q
p = ...  # = n // q
q = ...  # = n // p

r = (q-1) * (p-1)
d = gmpy2.divm(1, e, r)
# m = gmpy2.powmod(ct, d, n)

private_key = RSA.construct((n, e, d))

ct = b'some cool ciphertext'  # = gmpy2.powmod(pt, e, N) = pub_key.encrypt(pt, '')
pt = private_key.decrypt(ct)  # = gmpy2.powmod(ct, d, N)
