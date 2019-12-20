#!/usr/bin/env python3

"""
Gradually decrypt the payload since bh.exe is an oracle for the plaintext.

Before running, make sure you create a virtual interface with the C2 IP:
ifconfig eth0:0 192.168.206.161

Tear it down later with:
ifconfig eth0:0 down
"""

import os
import socket

DESIRED_CT = (b'\x00\x0c\x11\x25\x30\x31\x08\x61\x1d\x03\x3f\x39\x2d\x27\x1a'
              b'\x76\x1a\x32\x41\x26\x47\x2f')
LISTEN_ADDR = ('192.168.206.161', 33333)


def set_keylog(data):
    with open('./keylog.txt', 'wb') as f:
        f.write(data)


def sniff_ct(pt, delay=0.1):
    set_keylog(pt)
    os.system(f'sleep {delay} && wine bh.exe &>/dev/null')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(LISTEN_ADDR)
    sock.listen(1)

    conn, _ = sock.accept()
    data = conn.recv(1024)

    conn.close()
    sock.close()
    return data


def main():
    pt = b'RITSEC{'

    while True:
        for candidate_pt_int in range(32, 127):
            candidate_pt_byte = bytes([candidate_pt_int])
            if candidate_pt_byte == b'\n':
                continue

            sniffed_ct = sniff_ct(pt + candidate_pt_byte)
            if DESIRED_CT.startswith(sniffed_ct):
                pt += candidate_pt_byte
                print('CURRENT PLAINTEXT:', pt)
                break
        else:
            print('No candidate ints worked!')
            return


if __name__ == '__main__':
    main()
