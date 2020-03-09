#!/usr/bin/env python3

import struct

from PIL import Image

PNG2_FILE = 'pic.png2'


def hex2rgb(hex_str):
    """Convert hex colors to RGB tuples."""
    hex_str = hex_str.lstrip('#')
    assert len(hex_str) == 6
    return (
        int(hex_str[0:2], 16),
        int(hex_str[2:4], 16),
        int(hex_str[4:6], 16),
    )


def get_image_dimensions(img_bytes):
    width = struct.unpack('>h', img_bytes[10:12])[0]
    height = struct.unpack('>h', img_bytes[19:21])[0]
    return width, height


def iter_pixel_colors(img_bytes):
    img_bytes = img_bytes[21:]
    assert not (len(img_bytes) % 3)

    for i in range(0, len(img_bytes), 3):
        yield hex2rgb(img_bytes[i:i + 3].hex())


def main():
    with open(PNG2_FILE, 'rb') as f:
        png2_bytes = f.read()
    assert png2_bytes[:4] == b'PNG2'

    width, height = get_image_dimensions(png2_bytes)
    img = Image.new('RGB', (width, height))
    pixels = img.load()

    for i, rgb in enumerate(iter_pixel_colors(png2_bytes)):
        x = i % width
        y = i // width
        pixels[x, y] = rgb

    img.show()


if __name__ == '__main__':
    main()
