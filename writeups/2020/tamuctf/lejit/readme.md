# LeJIT

From the challenge description, it appears that we are going to have to exploit some kind of JIT runtime for [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck).

Trying to figure out more about the implementation, I typed in some garbage and got a somwhat helpful error message:

```
bf$ ;e[;w[;wd]wp[f,p[]resmf,
thread 'main' panicked at 'brainf*ck compilation failed: [ without matching ]', src/main.rs:272:17
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

So, this error message at least tells us that this is written in Rust. Using the awesome GitHub code search tool [grep.app](https://grep.app), I found the project that this implementation seemed to be based on: [dynasm-rs](https://github.com/CensoredUsername/dynasm-rs). Click [here](https://grep.app/search?q=%5B%20without%20matching%20%5D) for the actual query I ran to find the project.

Knowing this, we basically have a full source code reference for the basic implementation of the program. Since this is a pwn challenge, I assumed that I should focus on Brainfuck's operations for moving the data pointer and reading/writing memory. Messing around some more yielded something interesting:

```sh
$ bf <<<<<>>>.
(
```

The above line is moving the data pointer to a negative index of the tape (i.e., Brainfuck's linear memory) and printing out actual data. We can automate this a little bit to extract out a lot more data:

```python
data = ''
for i in range(126):
    resp = send_cmd(io, '<' * i + '.')
    data += resp
    print(i)

with open('data.reversed.raw', 'wb') as f:
    f.write(''.join(reversed(data)))
```

Of note is that byes in the buffer are in reverse order of their semantic meaning. We can then disassemble the extracted bytes with:

```sh
$ objdump -D -b binary -Mintel -mi386:x86-64 data.reversed.raw
... snip ...
   0:   83 ec 28                sub    esp,0x28
   3:   48 89 4c 24 30          mov    QWORD PTR [rsp+0x30],rcx
   8:   4c 89 44 24 40          mov    QWORD PTR [rsp+0x40],r8
   d:   4c 89 4c 24 48          mov    QWORD PTR [rsp+0x48],r9
  12:   48 81 ee 68 00 00 00    sub    rsi,0x68
  19:   48 3b f2                cmp    rsi,rdx
... snip ...
```

This looks like real assembly, so we are probably leaking from the RWX JIT buffer that is stored adjacent to the Brainfuck tape. It assembles for both 32-bit and 64-bit x86 variants. However, the dumped beginning of the assembly also looks exactly like the [dynasm prologue](https://github.com/CensoredUsername/dynasm-rs/blob/a68f9df2210820dfaa543e2087f2f62b221ba01f/doc/examples/bf-jit/src/x64.rs#L30).

Since this JIT buffer is RWX, we can write our own assembly payload to it, which will then be executed. Just like we read the assembly from the buffer in reverse, we have to write it in reverse, too. I wasn't sure what an acceptable offset into the RWX buffer was, so I just bruteforced it. Full solution script is available [here](./solve.py).
