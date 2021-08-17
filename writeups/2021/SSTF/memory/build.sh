#!/usr/bin/env bash

gcc -c -fPIC util-benign.c -o util-benign.o
gcc -o libutil-benign.so -shared util-benign.o

gcc -c -fPIC util-payload.c -o util-payload.o
gcc -o libutil-payload.so -shared util-payload.o

mkdir -p ./lib/
mv libutil-benign.so ./lib/libutil.so
