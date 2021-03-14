# safe_vector

This was a cool challenge, with the only vulnerability being a subtle feature of the C++ modulus operator that leads to the ability of specifying negative indexes. This gives us relative reads and writes on the heap, enough to read heap and libc pointers and edit chunk metadata.

As a learning experience, I implemented my solution to be capable of executing arbitrary shellcode payloads (rather than simply overwriting `__free_hook` with a one-gadget or `system`).

## Other Solutions

Looking at [the implementation of `pop_back`](https://gcc.gnu.org/onlinedocs/gcc-4.6.3/libstdc++/api/a01115_source.html), it seems like the only check there may be to prevent popping too many times is `__glibcxx_check_nonempty`:

```cpp
00388       void
00389       pop_back()
00390       {
00391     __glibcxx_check_nonempty();
00392     this->_M_invalidate_if(_Equal(--_Base::end()));
00393     _Base::pop_back();
00394       }
```

However, that is a macro hidden behind debug defines, so you can `pop_back` infinitely without triggering an exception. An easier form of exploitation would be to just `pop_back` enough times to overwrite one of the tcache bin heads towards the beginning of the heap.

## References

* [ptr-yudai's solution](https://hackmd.io/@ptr-yudai/BJ1Zs2lXO)
* [Glibc 2.31 Heap + Seccomp Exploitation Technique using ROP](https://blog.efiens.com/post/midas/heap-seccomp-rop/)
* [Steps for debugging parts of glibc](https://stackoverflow.com/questions/29955609/include-source-code-of-malloc-c-in-gdb).
