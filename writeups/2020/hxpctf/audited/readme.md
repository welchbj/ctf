# audited

Cool Python challenge I didn't solve until after the ctf ended, thanks to some comments from some nice folks in the competition's IRC channel.

## Solutions

There are a couple of ways to solve this (and possibly more). The first involves importing the `gc` module via an importer or loader left around in memory. The other involves walking back up to the main frame of execution via an exception traceback. Both solutions involve nopping out `__exit` with `print` so that the audit hook no longer quits execution.

## Resources

* [Another recent Python audit hook bypass challenge](https://flagbot.ch/posts/pyaucalc/): Really nice writeup that presents a good way to think about audit hook bypassing.
* [Corresponding CPython patch for the above audit hook bypass](https://bugs.python.org/issue41162)
* [`pylifecycle.c`](https://github.com/python/cpython/blob/b8fa135908d294b350cdad04e2f512327a538dee/Python/pylifecycle.c): Good reference for understanding when things are supposed to happen during Python code execution.
* [Audit event documentation](https://docs.python.org/3/library/audit_events.html)
