# Crack the Heart

I didn't solve this one during the competition, but wanted to try it out afterwards to practice some GDB tracing.

## Bypassing `ptrace` Anti-Debugging

We can still `strace` the binary if we patch `ptrace` return values, but don't get anything useful:

```sh
strace -e inject=ptrace:retval=0 ./cracktheheart
```

We can even make GDB overwrite the return code of the `ptrace` syscall:

```gdb
catch syscall ptrace
commands
    silent
    set $rax = 0
    continue
end
```

## Tracing for Answers

To generate output to be consumed by a SAT solver script, we use the following:

```sh
gdb --nx -q -x trace.gdb ./cracktheheart > trace.out
```

## Solving the Trace

By tracing a couple of the operations that work on the bytes of the .bss segment (which contains our input), we can leak a set of operations which provide enough information to setup a SAT model. The GDB tracing script that powered this can be found [here](./trace.gdb) and the Z3 solve script can be found [here](./solve.py).
