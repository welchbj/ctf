#!/usr/bin/env python3

import ast
import string
import os

os.environ["PWNLIB_SILENT"] = "1"
from pwn import process

charset = string.ascii_letters + string.digits + "_{}."
target = b'\x8e\x86\x8d\x95\xbb\xaa\xb9\xb2\xc8\xb3\xba\xc5\xaf\xc3\xc8\xc7\xc5\xb9\xcf\xe3\xe3\xe6\xd3\xd3\xd1\xe4\xe1\xcd\xe3\xf2\xed\xfa\xe0\xe9\xea\xddC0EH\xe7\xf3\x0f\xed\x06\x17\x02\xf5_Z^\x13`\x16\x15fhj)'
flag_len = 59
flag = "FLAG{"

while not flag.endswith("}"):
    for c in charset:
        guess = flag + c
        guess += "A"*(flag_len - len(flag) - 2) + "}"

        io = process(["./bin/python", "hook_guess.py", guess])
        io.recvuntil(b"check result:\n")
        guess_result = ast.literal_eval(io.recvuntil(b"\n", drop=True).decode())
        io.kill()

        check_len = len(flag)+1
        if guess_result[:check_len] == target[:check_len]:
            flag = flag + c
            print(flag)
            break
    else:
        raise ValueError("Exhausted guess space!")
