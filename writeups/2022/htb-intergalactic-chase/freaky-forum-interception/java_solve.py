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
    BitVec(f"char{i}", 32) for i in range(9)
]

arrayOfInt = [219, 227, 209, 154, 104, 97, 158, 163]

# alphanumeric constraints
for char in chars:
    s.add(char >= 0x30)
    s.add(char <= 0x7a)

for i in range(len(arrayOfInt)):
    s.add((chars[i] + chars[i+1]) == arrayOfInt[i])

count = 0
for model in all_smt(s, chars):
    sol_bytes = bytes([model[bv].as_long() for bv in chars])
    print(sol_bytes)
    count += 1
print(f"{count} solutions")
