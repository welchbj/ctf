#!/usr/bin/env python3

import binascii
import gmpy2

n = 126390312099294739294606157407778835887
e = 65537
c = 13612260682947644362892911986815626931

# From factordb.
p = 9336949138571181619
q = 13536574980062068373

r = (q - 1) * (p - 1)
d = gmpy2.divm(1, e, r)

p = gmpy2.powmod(c, d, n)
print(binascii.unhexlify(hex(p)[2:]).decode())
