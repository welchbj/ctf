# b64decoder

From basic inspection in Binary Ninja, it became clear that there is a format string vulnerability.

Also, looking at the address that gets printed in gdb (via `x/i 0xdeadbeef`), it becomes obvious that this value is always the address of `a64l` within LIBC. So, we don't need an information leak since we can always use this address to determine the LIBC base address.

Since we are also provided with the remote target's LIBC, we can determine the address of useful functions like `system` with confidence.

Messing around with format string, we see our input ends up pretty far down the stack. We can find it with the input `AAAA.%71$p`. Using this knowledge and our knowledge of code-execution-gaining function address in LIBC, we can follow the standard format string GOT entry overwrite approach to partially overwrite `a64l`'s GOT entry with that of `system`.

The GOT overwrite approach works for the following reasons:

* `a64l`'s address has already been resolved by the time our format string injection occurs, which allows to perform a partial overwrite of the last 2 bytes of the address.
* The binary is compiled without PIE, so we know the GOT address without needing an information leak.
* `a64l` is called after our format string injection occurs. This makes it a great candidate to be swapped out with `system` since both of these functions accept a single string as a parameter.

I wasted a lot of time thinking that I was trying to write null bytes as a part of my format string (which would fail to be properly output via `printf`), but was mistaken. There was just a discrepancy between output being returned from my local process and from the remote.

Find my solution script [here](./solve.py).
