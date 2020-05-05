# Assembly Voyageur

This was a nice challenge that required emulating short assembly programs for a bunch of different architectures.

I initially wanted to try to emulate all of this in `angr` (as its VEX IR should support all of the problem's architectures), but eventually decided it would just be easier to get the needed register values from each assembly snippet by debugging with GDB and QEMU. The QEMU emulation worked quite well (with some basic register renaming required for MIPS and PowerPC), with the exception of MIPS. QEMU wouldn't let me attach to the MIPS program with GDB, so I ended up editing the MIPS assembly template to force a segfault at the end of execution so I could extract the register values from the coredump.

The segfault can be triggered with an instruction like:

```asm
move $s0, 0($zero)
```

And to make sure you get core dumps, use:

```sh
ulimit -c unlimited
echo core > /proc/sys/kernel/core_pattern
```
