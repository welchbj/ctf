# cache_v2

This was another great C++ heap challenge, but exploitation became a bit more complicated than in [cache_v1](../cache_v1).

The vulnerability in this case is the use of the `uint8_t` data type for a `cache`'s `refCount` field, which is used to implement a crude version of reference counting to know when a `cache` can be freed. This extra layer of logic is needed due to this binary supporting the ability to "duplicate" an existing `cache`.

The use of `uint8_t` compared with `>` comparison to the `UINT_MAX` constant meant to detect too many duplicates being created, means that by creating 256 duplicates of a `cache` we can force its `refCount` to roll back over to `1`. The next time `release()` is called, the `cache` will be deleted, but there will still be 256 duplicate references to the freed `cache`.

Once we do this, we can use one of the duplicates to read from and write to freed memory in the heap (somewhat similar to what we could do in `cache_v1`). Messing around with this landed me at a relative read/write from a heap address very close to the beginning of the heap. One of the few things immediately beyond our initial heap address are the tcache list heads. I followed these first few steps for exploitation:

* Overwrite one of the tcache list heads to point to an area at the front of the heap, where we can still read from and write to with our initial relative read/write (these are reads/writes to `BB` in the solve script).
* Allocate a new `cache`, some of whose data will be allocated from the tcache list that we modified. This results in a `cache`'s `std::unique_ptr<char []>` internal `char *` and the `cache`'s `size` field to be stored at heap addresses within range of where we can write via the initial UAF. This controllable `cache` is referred to as `fake` in the solve script.

With the ability to modify `base` and `size`, we can implement an arbitrary read and write in similar fashion to `cache_v1`. However, the modification of the tcache list head corrupted it to the point where we cannot allocate further entries from this specific list. Attempts to repair the list after our allocation also failed, since we would have to end up with a misaligned pointer somewhere. A consequence of corrupting this specific list means we cannot enter very large numbers to the `readUint64` function, as this causes a conflicting heap allocation to be made. So, we implement the arbitrary read and write in the following way:

* Write to `BB` to modify the `base` pointer of `fake` to whatever address we are targeting.
* Keep the `BB` size field as `0xffffffffffffffff` so we can use any offset, even though we will only use small ones.
* Use offset `0` to perform our reads/writes at the address we wrote to `base`.

I wasn't able to leak a stack pointer in the same way as in `cache_v1` (i.e., overwriting `__free_hook` with `printf`), due to the inability to make heap allocations out of the smallest tcache list. Instead, I used the arbitrary read to get the address of the `environ` symbol from libc. This points to a stack address, but the offset from other stack data may change slightly depending on the target environment (due to things like environment variables on the stack). However, my local setup ended up only having an 8 byte difference in the desired target address of `handleWrite`'s stack frame. So, we can use the same technique to execute the same ROP chain and final ORW payload as in `cache_v1`.

This is all implemented in [my solve script](./solve.py).
