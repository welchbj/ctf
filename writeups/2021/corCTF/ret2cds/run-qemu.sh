#!/usr/bin/env bash

qemu-system-x86_64 -serial mon:stdio -hda ret2cds-qemu.qcow2 -nographic -smp 1 -m 1G -net user,hostfwd=tcp::1337-:1337 -net nic
