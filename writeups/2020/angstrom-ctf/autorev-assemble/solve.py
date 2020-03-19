#!/usr/bin/env python3

import angr
import claripy

BINARY = 'autorev_assemble'
FLAG_LEN = 0x100


def main():
    project = angr.Project(BINARY)

    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_chars)

    st = project.factory.full_init_state(
        add_options=angr.options.unicorn,
        stdin=flag,
    )

    # Main flag contents won't contain a newline or null byte.
    for c in flag_chars[:-1]:
        st.solver.add(c != 0x00)
        st.solver.add(c != 0x0a)
    # Assume flag ends with newline.
    st.solver.add(flag_chars[-1] == 0x0a)

    find_addr = 0x40894c
    avoid_addr = 0x40895a

    sm = project.factory.simgr(st)

    print('Solving...')
    sm.explore(find=find_addr, avoid=avoid_addr)

    if len(sm.found) > 0:
        for sol_state in sm.found:
            print(sol_state.solver.eval(flag, cast_to=bytes))
    else:
        print('FAILED')


if __name__ == '__main__':
    main()
