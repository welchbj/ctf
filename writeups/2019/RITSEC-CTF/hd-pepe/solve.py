#!/usr/bin/env python3

"""
Encoder does the following to hide a message:
    * convert plaintext to base64 bytes
    * change all alpha values of original image to 255-original_ord
"""

import base64
import sys

from PIL import Image

ct_img = './pepe.png'

im = Image.open(ct_img)
pixels = im.load()
x_size, y_size = im.size

pt = ''
for x in range(x_size):
    for y in range(y_size):
        try:
            r, g, b, a = pixels[x, y]
        except ValueError as e:
            print(e)
            print('NO ALPHA VALUE!')
            sys.exit(1)

        if a == 255:
            continue

        pt += chr(255-a)
        print(pt)

print(pt)
