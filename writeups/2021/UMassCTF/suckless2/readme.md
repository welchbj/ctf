# suckless2

Interesting challenge exploiting a program written in the [Myrddin](https://myrlang.org/) programming language. Gist of the solution is corrupting a slab allocator.

## Rererences
* [Myrddin high-level allocation interface](https://github.com/oridb/mc/blob/master/lib/std/alloc.myr)
* [Relevant portion of low-level allocation routines](https://github.com/oridb/mc/blob/master/lib/std/bytealloc.myr#L320-L344)
