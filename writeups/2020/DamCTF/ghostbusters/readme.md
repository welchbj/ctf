# Ghostbusters

Cool challenge that involved influencing the userspace stack by calling `vsyscall` syscalls (which reside at static addresses in every process).

Helpful resources:

* [Writeup from GoogleCTF](http://gmiru.com/writeups/gctf-wiki/) that uses `vsyscall` addresses as a sled into more useful functions
* [LWN article on the security implications of `vsyscall`/vDSO](https://lwn.net/Articles/446528/)
