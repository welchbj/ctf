#!/usr/bin/env python3

import angr
import claripy

BINARY = 'metaverse'


def unpie(addr):
    return addr + 0x400000


def main(flag_len):
    project = angr.Project(BINARY)

    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars)

    st = project.factory.full_init_state(
        add_options=angr.options.unicorn,
        stdin=flag,
    )

    # Flag constraints.
    for i, c in enumerate('ACI{'):
        st.solver.add(flag_chars[i] == ord(c))
    for c in flag_chars[4:-2]:
        st.solver.add(c >= 0x20)
        st.solver.add(c < 0x7f)
    st.solver.add(flag_chars[-2] == ord('}'))
    st.solver.add(flag_chars[-1] == ord('\n'))

    find_addr = unpie(0xf60)
    avoid_addr = unpie(0xf6e)

    sm = project.factory.simgr(st)

    print(f'Solving for flag length {flag_len}...')
    sm.explore(find=find_addr, avoid=avoid_addr)

    if len(sm.found) > 0:
        for sol_state in sm.found:
            print(sol_state.solver.eval(flag, cast_to=bytes))
    else:
        print('FAILED')


if __name__ == '__main__':
    for i in range(0x20-1, 0x40):
        main(i)