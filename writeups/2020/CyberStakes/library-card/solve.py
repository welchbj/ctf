#!/usr/bin/env python3

import angr
import claripy

BINARY = 'liblibrary_card.so'


def unpie(addr):
    return 0x400000 + addr


def main():
    project = angr.Project(BINARY, load_options={'auto_load_libs':False})

    st = project.factory.call_state(unpie(0x22fa), 0x824, 0x82c, 0x82b)

    find_addr = unpie(0x25ae)
    sm = project.factory.simgr(st)

    print('Solving...')
    sm.explore(find=find_addr)

    if len(sm.found) > 0:
        for sol_state in sm.found:
            print(sol_state.posix.dumps(1))
    else:
        print('FAILED')


if __name__ == '__main__':
    main()

