#!/usr/bin/env bash

# deps:
# sudo apt install nasm gcc gcc-aarch64-linux-gnu gcc-mips-linux-gnu gcc-powerpc-linux-gnu gdb-multiarch qemu-user-static

nasm -f elf32 i386.asm
gcc -m32 i386.o -o i386

nasm -f elf64 x86_64.asm
gcc x86_64.o -o x86_64

/usr/bin/aarch64-linux-gnu-as aarch64.asm -oaarch64.o
/usr/bin/aarch64-linux-gnu-ld aarch64.o -oaarch64

/usr/bin/mips-linux-gnu-as mips.asm -omips.o
/usr/bin/mips-linux-gnu-ld mips.o -omips

/usr/bin/powerpc-linux-gnu-as powerpc.asm -opowerpc.o
/usr/bin/powerpc-linux-gnu-ld powerpc.o -opowerpc