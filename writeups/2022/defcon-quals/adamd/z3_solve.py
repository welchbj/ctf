#!/usr/bin/env python3

import binascii

from z3 import *

def all_smt(s, initial_terms):
    def block_term(s, m, t):
        s.add(t != m.eval(t, model_completion=True))
    def fix_term(s, m, t):
        s.add(t == m.eval(t, model_completion=True))
    def all_smt_rec(terms):
        if sat == s.check():
           m = s.model()
           yield m
           for i in range(len(terms)):
               s.push()
               block_term(s, m, terms[i])
               for j in range(i):
                   fix_term(s, m, terms[j])
               yield from all_smt_rec(terms[i:])
               s.pop()   
    yield from all_smt_rec(list(initial_terms))

s = Solver()
flag_len = 59

chars = [
    BitVec(f"char{i}", 8) for i in range(flag_len)
]

with open("hook_results.txt", "r") as f:
    while True:
        try:
            idx = int(f.readline().strip().split("Access of index: ")[1])
            and_op = int(f.readline().strip().split("Bitwise and with: ")[1])
            result = int(f.readline().strip().split("Equality comparison with: ")[1])
        except IndexError:
            break

        s.add((chars[idx] & and_op) == result)

count = 0
for model in all_smt(s, chars):
    sol_bytes = bytes([model[bv].as_long() for bv in chars])
    print(sol_bytes)
    count += 1
print(f"{count} solutions")
