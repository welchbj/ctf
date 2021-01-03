# cache_v1

The vulnerability in this program is the use of the result computed by `std::hash<std::string>` as the key into the `caches` global `std::unordered_map<size_t, cache>`. This is problematic because it means we can edit the `size` of an existing `cache` by finding a collision for the hashing function. The ability to edit sizes manifests itself in the following line from `handleCreate`, which blindly updates the size for the corresponding entry to the user-specified size (the `[]` operator will implicitly create an entry if it does not already exist):

```cpp
caches[std::hash<std::string>{}(name)].size = size;
```

I was able to find a collision in the glibc implementation of `std::hash` for `std::string` (which turns out to be a variation of [MurmurHash](https://en.wikipedia.org/wiki/MurmurHash)) by re-implementing [the main logic](https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/hash_bytes.cc) in z3.

Due to the relatively short lengths of the colliding strings, this would probably have been easier to brute force. There's also [a nice article](http://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-dos-reloaded/) that talks about actually applying thought to computing MurmurHash collisions. Anyways, after running the z3 portion of the solve script for ~10 minutes, it produces a collision:

```
[*] Searching for collision...
[*] Checking model for lengths 1 and 1...
[*] Collision search failed
[*] Checking model for lengths 1 and 2...
[*] Collision search failed
[*] Checking model for lengths 1 and 3...
[*] Collision search failed
[*] Checking model for lengths 1 and 4...
[*] Collision search failed
[*] Checking model for lengths 1 and 5...
[*] Collision search failed
[*] Checking model for lengths 1 and 6...
[*] Collision search failed
[*] Checking model for lengths 1 and 7...
[*] Collision search failed
[*] Checking model for lengths 1 and 8...
[+] Got collision!
b'\x17'
b'#vJ\xe7\x01Q}\xbd'
```

More information about where to find the portions of source for glibc's convoluted hash implementation is explained in [this great StackOverflow Q/A](https://stackoverflow.com/questions/19411742/what-is-the-default-hash-function-used-in-c-stdunordered-map).

Once we can edit the size of a `cache` to something larger than what was actually allocated, we can perform relative reads and writes from wherever our edited `cache`'s `char * base` points to on the heap (via the `handleRead` and `handleWrite` functions). This means we can leak pointers and update the `base` and `size` values of another `cache` that sits on the heap beyond our edited `cache` instance. To see how this can be upgraded into an arbitrary read/write, a quick look at the layout of a `cache` instance is helpful:

```cpp
struct cache {
    char *base;
    size_t size;
    cache() : base(nullptr), size(0) {}
    virtual ~cache() {
        if (base != nullptr) {
            delete[] base;
            base = nullptr;
        }
    }
};
```

We can read or write data to any data at an offset from the `base` pointer, as long as that offset is less than `size`. So if we change `base` to a really low number (but not `nullptr`, since the program has a sanity check for this) and change `size` to the max unsigned long value (`0xffffffffffffffff`), then we can read from or write to any address in the process's address space.

Once this arbitrary read and write is implemented, I used pointers leaked from the heap to determine the heap base and target binary's base. We can then get a libc leak by reading from the binary's GOT.

I had trouble figuring out how to pivot the stack into the heap for a ROP chain, so instead I:

* Overwrote `__free_hook` with `printf`.
* Freed a string with lots of `%p` format specifiers, which resulted in leaking a stack address.

This allowed me to use the arbitrary write to write a ROP chain to the stack frame of `handleWrite`, which would trigger as soon as the current call to `handleWrite` (which was performing the arbitrary write) finished.

The ROP chain was fairly straightforward, and just `mmap`ed a RWX segment to `read` in a final ORW shellcode to print the flag. This is all implemented in [my solve script](./solve.py).
