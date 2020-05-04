#!/usr/bin/env python2

import ast

from pwn import *

SEP = '-'*78


def int2raw(x):
    return binascii.unhexlify(hex(x)[2:].rstrip('L'))


def raw2int(x):
    hex_str = '0x' + binascii.hexlify(x)
    return ast.literal_eval(hex_str)


def main():
    io = remote('challenge.acictf.com', 3882)
    context.log_level = 'debug'

    # raw as intermediate format
    _from_dict = {
        'raw': lambda x: ''.join(c for c in x if c.strip()),
        'b64': lambda x: base64.b64decode(x),
        'hex': lambda x: binascii.unhexlify(x),
        'dec': lambda x: int2raw(int(x)),
        'oct': lambda x: int2raw(int(x, 8)),
        'bin': lambda x: int2raw(int(x, 2)),
    }
    _to_dict = {
        'raw': lambda x: ''.join(c for c in x if c.strip()),
        'b64': lambda x: base64.b64encode(x),
        'hex': lambda x: binascii.hexlify(x).rstrip('L'),
        'dec': lambda x: str(raw2int(x)),
        'oct': lambda x: oct(raw2int(x)).lstrip('0').rstrip('L'),
        'bin': lambda x: bin(raw2int(x)).lstrip('b0'),
    }

    while True:
        io.recvuntil(SEP)
        io.recvline()

        _from, _to = io.recvline().strip().split(' -> ')
        data = io.recvline().strip()

        answer = _to_dict[_to](_from_dict[_from](data))
        io.sendlineafter('answer: ', answer)


if __name__ == '__main__':
    main()