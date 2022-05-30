import sys

guess = sys.argv[1]

def hook_input(prompt):
    return guess
__builtins__.input = hook_input

def hook_check_flag(x):
    print("check result:")
    print(x)

import chall
chall.check_flag = hook_check_flag
chall.main()
