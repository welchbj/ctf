#!/usr/bin/env python3

import re
import string
import subprocess

FAIL_MARKER = 'CHECK FAIL'
PASS_MARKER = 'CHECK PASS'

TRACE_FILE = '.gdb.trace.tmp'
ALPHABET = '_' + string.printable.rstrip('_|&;\'"\t\n\r\x0b\x0c')


def run_gdb_trace(guess):
    with open(TRACE_FILE, 'w') as f:
        f.write(f"""\
set pagination off
gef config context.enable 0

# We hit this if a character is wrong.
pie break *0x1680

# We hit this if a character is right.
pie break *0x163f

# We are only breaking on reads so that we have
# a chance to register commands on our two PIE
# breakpoints, which GEF doesn't transform into
# actual GDB breakpoints until we start running.
catch syscall read
commands
    silent
    commands 2
        silent
        printf "{FAIL_MARKER}\\n"
        continue
    end
    commands 3
        silent
        printf "{PASS_MARKER}\\n"
        continue
    end
    # Don't keep catching reads.
    del 1
    continue
end

pie run < <(echo '{guess}')
quit""")

    # The patched version of the binary just skips the initial prompt.
    output = subprocess.check_output(
        f'gdb -x {TRACE_FILE} ./engine.patched', shell=True
    ).decode()
    num_fail = len(list(re.finditer(FAIL_MARKER, output)))
    num_pass = len(list(re.finditer(PASS_MARKER, output)))
    return num_fail, num_pass


def main():
    print('Solving...')

    flag = 'pctf{'
    while not flag.endswith('}'):
        for c in ALPHABET:
            print(c)
            num_fail, num_pass = run_gdb_trace(flag + c)
            if num_pass > len(flag):
                flag += c
                print(flag)
                break
        else:
            print('FAILED')


if __name__ == '__main__':
    main()
