#!/usr/bin/env python3

import angr
import claripy

BINARY = './chugga'
FLAG_LEN = 0x17


def main():
    project = angr.Project(BINARY)

    start_addr = 0x49305d
    initial_state = project.factory.blank_state(addr=start_addr)

    flag = claripy.BVS('flag', FLAG_LEN*8)

    # We just need somewhere to store the flag buffer. Since
    # the region of the binary we are working doesn't use the
    # stack at all, putting it there doesn't matter.
    initial_state.memory.store(initial_state.regs.rsp, flag)
    initial_state.regs.rdx = initial_state.regs.rsp
    initial_state.regs.rcx = FLAG_LEN

    find_addr = 0x49327e
    avoid_addr = 0x493066

    simulation = project.factory.simgr(initial_state)

    print('Solving...')
    simulation.explore(find=find_addr, avoid=avoid_addr)

    if len(simulation.found) > 0:
        for sol_state in simulation.found:
            print(sol_state.solver.eval(flag, cast_to=bytes))
    else:
        print('FAILED')


if __name__ == '__main__':
    main()
