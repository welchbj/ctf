#!/usr/bin/env python3

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

chars = [
    BitVec(f"char{i}", 32) for i in range(6)
]

# alphanumeric constraints
for char in chars:
    s.add(char >= 0x30)
    s.add(char <= 0x7a)

s.add((chars[0] + chars[1] + chars[2] + chars[3] + chars[4] + chars[5]) == 0x223)
s.add((chars[0] + chars[5]) == 0xdf)
s.add((chars[1] + chars[4]) == 0xdd)
s.add((chars[2] + chars[3]) == 0x67)

# char5 + 3*(char4 + 3*(char3 + 3*(char2 + 3*(char1 + 3*char0)))) == 0x8dd3
s.add(
    (chars[5] + 3*(chars[4] + 3*(chars[3] + 3*(chars[2] + 3*(chars[1] + 3*chars[0]))))) == 0x8dd3
)

s.add(chars[2] <= chars[3])
s.add(chars[3] <= chars[0])
s.add(chars[0] <= chars[4])
s.add(chars[4] <= chars[1])
s.add(chars[1] <= chars[5])

count = 0
for model in all_smt(s, chars):
    sol_bytes = bytes([model[bv].as_long() for bv in chars])
    print(sol_bytes)
    count += 1
print(f"{count} solutions")
