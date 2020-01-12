#!/usr/bin/env python

from __future__ import print_function

import sys

from argparse import ArgumentParser

from pwn import *


ROOTER_HOST, ROOTER_PORT = '10.90.100.5', 23
PASSWORD = 'Yoko_Ono_killed_the_beatles'
OPTION_PROMPT = 'Choose an option: '
COMMAND_END_BANNER = """\
=============================================
MENU ** authenticated **
============================================="""


def get_parsed_args():
    parser = ArgumentParser(
        usage='rooter-exec.py OPTIONS',
    )
    parser.add_argument(
        '-c', '--command',
        metavar='COMMAND',
        help='the command to run'
    )
    parser.add_argument(
        '-f', '--file',
        metavar='FILE',
        help='file to load a command from'
    )

    return parser.parse_args()


def login():
    io = remote(ROOTER_HOST, ROOTER_PORT)
    io.recvuntil(OPTION_PROMPT)
    io.sendline('1')
    io.recvuntil('Password: ')
    io.sendline(PASSWORD)
    return io


def run_command(io, command):
    io.recvuntil(OPTION_PROMPT)
    io.sendline('2')
    io.recvuntil('COMMAND: ')
    io.sendline(command)

    command_output = io.recvuntil(COMMAND_END_BANNER)
    command_output = command_output.replace(COMMAND_END_BANNER, '')
    return command_output


def quit(io):
    io.recvuntil(OPTION_PROMPT)
    io.sendline('5')
    sys.exit()


def main():
    opts = get_parsed_args()

    if opts.file:
        with open(opts.file, 'r') as f:
            command = f.read().strip()
    elif opts.command:
        command = opts.command
    else:
        print('No command specified; use -c or -f')
        sys.exit()

    io = login()
    print(run_command(io, command))
    quit(io)


if __name__ == '__main__':
    main()
