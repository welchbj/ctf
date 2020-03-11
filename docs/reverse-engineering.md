# Reverse Engineering

This document discusses different analysis tools, techniques, and general knowledge for reverse engineering problems.

## Linux Preliminary Analysis

There is a lot of information that can be gathered about a binary before diassembling, using tools from `radare2`, GNU binutils, and other tool suites. Here are some potentially useful snippets:

```sh
# search for strings in a binary
strings -a ./program

# search for strings of different formats:
#    -e s -> single-7-bit-byte characters (default)
#    -e S -> single-8-bit-byte characters
#    -e b -> 16-bit bigendian
#    -e l -> 16-bit littleendian
#    -e B -> 32-bit bigendian
#    -e L -> 32-bit littleendian
strings -e b ./program

# check sections of an ELF; writable/executable sections are of interest
readelf --sections ./program

# display program headers, including section to segment mapping
readelf -l ./program

# dump ELF information
readelf -a ./program

# methods of printing all symbols
nm -an ./program
rabin2 -s ./program

# print relocation bytes
objdump -R ./program
```

## `radare2` Snippets

### Preliminary Analysis

`radare2` is a powerful command-line suite of tools for reverse engineering. To get started, print out some diagnostic information about a binary:

```sh
rabin2 -I ./program
```

### Static Analysis

Then load the binary for further analysis with:
```sh
radare2 ./program
```

This opens an interactive command-line interface, where we will do the bulk of the analysis and disassembly. Below are some useful snippets for reverse engineering tasks within the `radare2` shell.

```sh
# run a detailed analysis of the loaded binary
aaa

# print program entry points
ie

# print flag spaces; these are interesting offsets in the file
fs

# choose the `imports` flag space and print the flags that it contains
fs imports; f

# print strings within the data sections; use izz for global search
iz

# search for cross-references to all string flags; @@ acts like a `for-each` iterator
fs strings; axt @@ str.*

# list functions analyzed by radare (analyze function list)
afl

# seek to a symbol or address
s main
s 0xdeadbeef

# seek to previous location
s -

# show disassembly from the current position (print diasessmble function)
pdf

# show disassembly from specific position (@ means temporary seek)
pdf @ sym.main

# switch to visual mode; navigate with the followings keys:
#     p/P           -> move forward/backward between views
#     u/U           -> move forward/backward between seeks
#     x/X           -> list references to/from a function
#     m<key>/'<key> -> mark a location and go to it from anywhere
#    :<command>     -> execute a radare2 command
#    ;<comment>     -> add a comment
#    ;-             -> remove a comment
#    <digit>        -> follow the corresponding call/jump
#    q              -> return to the radare2 shell
#    r              -> refresh graph
V

# switch to graph mode; most keybindings from V will still work, also see:
#    g<key> -> jump to a function
VV

# convert a value to a variety of formats
? 0xdead

# mark several addresses as strings
ahi s @@=0xdeadb33f 0xdeadb34f 0xdeadb35f
```

### Dynamic Analysis

`radare2` can also be used for dynamic analysis (i.e., debugging). To open a program in debug mode, use:

```sh
radare2 -d ./program arg1 arg2 arg3
```

Alternatively, from an existing `radare2` shell, use:

```sh
ood arg1 arg2 arg3
```

Once in a debugging shell, the following commands may be useful:
```sh
# continue execution until a specified symbol is reached
dcu main

# step 5 times
ds 5

# step into / step over current instruction
s
S

# set / remove a breakpoint
db 0xdeadbeef
db -0xdeadbeef

# continue execution
dc

# continue until syscall
dcs

# show process maps
dm

# set register value
dr eax=44

# dump value at register
x @ eax
```

### `rahash2` Snippets

`rahash2` is another command-line utility for hashing and encoding data in different formats. Below are some useful snippets.

The following snippets are useful for encoding data:

```sh
# rot13 encode / decode
rahash2 -E rot -S s:13 -s 'a nice string'
rahash2 -D rot -S s:13 -s 'n avpr fgevat'
```

## Linux Tracing Utilities

### "Tracing" via GDB Scripts

TODO: https://stackoverflow.com/questions/58851/can-i-set-a-breakpoint-on-memory-access-in-gdb

TODO: https://spotless.tech/utctf-ctf-2020-Crack_the_heart.html

TODO: https://stackoverflow.com/questions/10748501/what-are-the-best-ways-to-automate-a-gdb-debugging-session

### Linux - eBPFs and `bpftrace`

It turns out that Linux Kernel performance-tracing tools are also great for tracing CTF problem binaries. Some awesome introductory articles to Linux tracing through the lense of performance engineering include:

* TODO: https://netflixtechblog.com/linux-performance-analysis-in-60-000-milliseconds-accc10403c55
* TODO: http://www.brendangregg.com/blog/2015-07-08/choosing-a-linux-tracer.html

TODO: https://github.com/iovisor/bcc

TODO: https://github.com/iovisor/bpftrace

### `strace`

#### `strace` Pitfalls

TODO

#### `strace` Snippets

System calls can be traced and manipulated with the command-line program `strace`. Below are some useful snippets for reverse engineering challenges:

```sh
# print instruction pointer at the time of the syscall
strace -i ./program

# manipulate the maximum size of strings printed as call arguments; default is 32
strace -s 256 ./program

# print non-ascii strings in hex format; use -xx to do this for ascii strings, too
strace -x ./program

# full hex/ascii dump of data read from / written to specific file descriptors
strace -e read=3,4 -e write=3,4 ./program

# print paths associated with file descriptor arguments and ip:port pairs for socket file descriptors
strace -y -yy ./program

# attach to an already-running process by PID
strace -p <PID>

# properly run a setuid binary as root
strace -u root ./program

# follow child processes spawned via fork, vfork, and clone
strace -f ./program

# trace a multi-threaded program without following its children
strace -b execve -f ./program

# trace a specific class of calls; options include:
#     %process -> process management syscalls
#     %network -> network-related syscalls
#     %signal  -> signal-related syscalls
#     %ipc     -> inter-process communication syscalls
#     %desc    -> file descriptor syscalls
#     %memory  -> memory mapping syscalls
#     %pure    -> syscalls that always succeed and have no arguments (getuid, getpid, etc.)
strace -e trace=%process,%network

# trace a specified signal
strace -e signal=SIGIO ./program

# filter out a specific system call (open in this case); omit \! to only include that syscall
strace -e trace=\!open

# pass an environment variable to process (omit =val part to unset the variable)
strace -E var=val ./program

# trace only the system calls that access the specified path
strace -P /a/file/path -P /another/file/path ./program

# print only syscalls that returned without an error code; use -Z for calls that returned WITH an error code
strace -z ./program

# injecting syscalls to bypass anti-debugging (in this case, ptrace)
strace -e inject=ptrace:retval=0 ./program
```

### `ltrace`

Library calls can be traced with the command-line program `ltrace`. Below are some useful snippets:

```sh
# TODO
TODO
```
