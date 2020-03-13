#!/usr/bin/env python3

from z3 import *

SOLUTION_LEN = 82


def load_operands():
    with open('trace.out', 'r') as f:
        for line in f:
            if not line.startswith('0x'):
                continue

            xor_operand, sub_operand = line.strip().split(',')
            yield int(xor_operand, 16), int(sub_operand, 16)


def model_to_ascii(model, solution_vars):
    return ''.join(
        chr(model[sv].as_long()) for sv in solution_vars
    )


def main():
    solver = Solver()

    solution_vars = [BitVec(f'c{i}', 8) for i in range(SOLUTION_LEN)]
    zip_iter = zip(solution_vars, load_operands())
    for solution_var, (xor_operand, sub_operand) in zip_iter:
        solver.add((solution_var ^ xor_operand) == sub_operand)

    assert solver.check() == sat
    print(model_to_ascii(solver.model(), solution_vars))


if __name__ == '__main__':
    main()
