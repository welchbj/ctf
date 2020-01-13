#!/usr/bin/env python3

import binascii
import hashlib
import itertools
import os

curr_max = 0

while True:
    rand = os.urandom(24)
    sha1_obj = hashlib.sha1()
    sha1_obj.update(rand)
    sha1_hash = sha1_obj.hexdigest()

    a_count = len(list(itertools.takewhile(lambda x: x == 'a', sha1_hash)))
    if a_count > curr_max:
        curr_max = a_count
        print('sha1:', sha1_hash)
        print('data:', binascii.hexlify(rand).decode())
        print('count: ', a_count)
        print()
