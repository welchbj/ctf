#!/usr/bin/env python3

import base64
import itertools

secret = base64.b64decode('PjzvDg1ox1iPtP5QQnD7BFIs5U54SPpLT3HYEcu3+2I=')
secret = [i for i in reversed(secret)]

# unxor
for i in range(len(secret)):
    secret[i] = secret[i] ^ ((32 + i + 1) % 256)


def encrypt(pt):
    ct = [x for x in pt]
    for i in range(len(ct)):
        switch = i % 4
        if switch == 0:
            ct[i] = (ct[i] - 104 + 256) % 256
        elif switch == 1:
            ct[i], ct[i-1] = ct[i-1], ct[i]
        elif switch == 2:
            ct[i] = ((ct[i] * 16) % 256) + (ct[i] // 16)
        elif switch == 3:
            ct[i] = ct[i] ^ ct[i-1]

    return ct


ans = []
while len(ans) < len(secret):
    for i, j in itertools.product(range(256), range(256)):
        ct = encrypt(ans + [i, j])
        if ct == secret[:len(ct)]:
            ans.append(i)
            ans.append(j)
            print(''.join(chr(c) for c in ans))
            break
    else:
        print('FAILED')