#!/usr/bin/env python3

import binascii

from Crypto.Cipher import Blowfish

with open('encrypted', 'rb') as f:
    ct = f.read()

key = binascii.unhexlify(b'09651a1fe89e49fe9ed03f37dae7c2ff')
iv = binascii.unhexlify(b'd970175280c3df30')

cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
msg = cipher.decrypt(ct)
print(msg)