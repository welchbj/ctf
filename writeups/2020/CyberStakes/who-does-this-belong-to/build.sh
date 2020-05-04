#!/usr/bin/env bash

gcc -c -fPIC read-flag.c -o read-flag.o
gcc -o libb.so -shared read-flag.o

gcc -o drop-privs -static drop-privs.c