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

## Linux Tracing Utilities

### "Tracing" via GDB Scripts

GDB scripts can be a useful tool for dynamic tracing, . Some useful resources in this vein:

* [StackOverflow: Breakpoints on memory accesses in GDB](https://stackoverflow.com/questions/58851/can-i-set-a-breakpoint-on-memory-access-in-gdb)
* [StackOverflow: GDB scripting examples to automate debugging](https://stackoverflow.com/questions/10748501/what-are-the-best-ways-to-automate-a-gdb-debugging-session)
* [Crack the Heart writeup from UTCTF 2020](https://spotless.tech/utctf-ctf-2020-Crack_the_heart.html)

### Linux - eBPFs and `bpftrace`

It turns out that Linux Kernel performance-tracing tools are also great for tracing CTF problem binaries. Some awesome introductory articles to Linux tracing through the lense of performance engineering include:

* [Netflix: Linux Performance Analysis in 60,000 Milliseconds](https://netflixtechblog.com/linux-performance-analysis-in-60-000-milliseconds-accc10403c55)
* [Choosing a Linux Tracer (2015)](http://www.brendangregg.com/blog/2015-07-08/choosing-a-linux-tracer.html)

And useful tools:

* [`bcc`](https://github.com/iovisor/bcc)
* [`bpftrace`](https://github.com/iovisor/bpftrace)

### `strace`

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

### Statement-level Tracing

Sometimes you have to go deeper. This may involve tracing a binary's execution at the processor statement-level. A CTF writeup that surveys possible techniques can be found [here](https://fevral.github.io/2017/08/13/flareon2015-2.html).

#### Frida

[Frida](https://frida.re/) is a powerful dynamic instrumentation framework. [Here](https://sectt.github.io/writeups/Volga20/f-hash/README) is an example of a CTF writeup that uses Frida to memoize the result of an expensive recursive function.

## File Systems

### FAT32

The loose nature of references in [FAT file systems](https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system) allows for the encoding of data that probably doesn't belong in a file system. For some FAT32-parsing Python utilities (borrowed from a separate gist I found online), see [my strcmp go brrrr writeup](https://github.com/welchbj/ctf/tree/master/writeups/2020/PlaidCTF/file-system-based-strcmp-go-brrrr). See [here](https://www.pjrc.com/tech/8051/ide/fat32.html) for a nice general FAT32 reference.

A useful utility for these challenges is [fatcat](https://github.com/Gregwar/fatcat). Its use (among other techniques) is documented in [this writeup](https://ctftime.org/writeup/20091).

## Weird File Formats

### Adobe Director

An example of reversing files created with Adobe Director comes from Plaid CTF 2020's [YOU wa SHOCKWAVE](https://ctftime.org/task/11307) challenge. A comprehensive writeup can be found [here](https://github.com/jacopotediosi/Writeups/tree/master/CTF/2020/PlaidCTF-2020/Rev-You_wa_shockwave-250), which introduces the following tools and resources:

* [A Tour of the Adobe Directory File Format](https://medium.com/@nosamu/a-tour-of-the-adobe-director-file-format-e375d1e063c0): A nice overview of the data you may encounter.
* [DCR2DIR](https://github.com/Brian151/OpenShockwave/tree/master/tools/imports): Convert a DCR file to DIR format.
* [Lingo script extractor](https://alex-dev.org/lscrtoscript/): Finds embedded scripts from DCR files.

## Working with Other Architectures and Operating Systems

Sometimes you encounter binaries requiring setups that you don't have immediate access to. Here are some projects that might get you what you need:

* [Darling](https://www.darlinghq.org/): A translation layer that lets you run macOS software on Linux. Find an article demonstrating its use [here](https://0xdf.gitlab.io/2019/07/01/darling-running-macos-binaries-on-linux.html).
* [OSX-KVM](https://github.com/kholia/OSX-KVM): Run macOS on QEMU/KVM.
* [arm_now](https://github.com/nongiach/arm_now): Quickly setup VMs via QEMU for working with ARM, MIPS, PowerPC, and other architectures.
