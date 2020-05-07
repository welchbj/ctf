# UNO Reverse Card

This was a fun shellcoding problem that involved writing size- and character-constrained shellcode.

After some basic reverse engineering, I observed the following about the target `uno` binary:

* It starts by reading 64 bytes of shellcode from `stdin`, which must not contain any of the characters in `\x00flag\xc2\xc3\xca\xcb`.
* It allocates two RWX pages via `mmap`. One of these pages will hold our written shellcode in the order it was submitted; the other will hold our written shellcode in the reverse order.
* The process forks, with the child process then spinning off two threads. Each thread executes one of the two `mmap`ed pages (with some basic `seccomp` filters applied; the filters aren't that important, just know that they still permit the `open`, `read`, and `exit` syscalls). The return value for each of the threads is checked upong their return, and must be non-zero to avoid an early exit from the program.
* If both threads return okay, then the contents of each `mmap`ed region is dumped to a temporary file created via `mkstemp`.
* The parent process then dumps the content of the temporary file to `stdout`.

The following observations about the shellcode "runtime" (which are the result of a decent amount of debugging) make crafting a working solution a lot easier, too:

* At the start of shellcode execution, the thread return value that is checked at the end of the shellcode's execution is held at `[rdi+8]`.
* At the start of shellcode execution, `rax` holds the address of the `mmap`ed page currently being executed.
* The `exit` syscall only kills the current thread, not the entire process. This means we can use it to safely exit from our current thread.

The easiest way I found to debug was prepending the shellcode with an `int3` instruction (which generates a `SIGTRAP` signal, telling GDB to break), and telling GDB to follow child processes and threads with:

```gdb
set follow-fork-mode child
```

Knowing all of this, we can devise the following solution:

* To avoid thinking too much, we'll create a minimal "reverse" shellcode that exits as soon as possible. This allows us to focus mainly on writing the "forward" shellcode, which is what we'll actually use to get the flag.
* Since we just need the thread return value to be non-zero, our "reverse" shellcode only needs to consist of instructions that set the value in `[rdi+8]` to be non-zero and then call an `exit` syscall.
* Since we know the flag is in the file `flag` (thanks to one of the problem hints), and that the beginning of the `mmap`ed pages eventually get dumped to `stdout` as long as the threads return okay, our "forward" shellcode only needs to consist of an `open`/`read` shellcode, which writes the contents of the `flag` file to the beginning of the `mmap`ed page that we are currently executing out of.
* The "forward" shellcode can make use of the same clean exit shellcode that we crafted for the "reverse" shellcode.

My [solve script](./solve.py) makes heavy use of the [`pwntools` shellcraft API](https://docs.pwntools.com/en/stable/shellcraft.html). I highly recommend becoming comfortable with it if you are not already.
