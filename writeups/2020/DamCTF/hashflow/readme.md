# Hashflow

Fun challenge that involved:

* Forging signatures by breaking naive hashing algorithm with z3.
* Leaking the stack cookie and a binary address via a stack-based overflow that was guarded by the signature check we can break.
* Using the stack-based overflow (and leaked data) to do a short ROP to leak a libc address.
* Using the stack-based overflow one more time (with gadgets from the leaked libc) to do a `read`/`write` ROP to print the flag.

Helpful resources:

* [Blog post about breaking naive hashing algorithms](https://www.tiraniddo.dev/2014/09/generating-hash-collisions.html)
* [Example z3 Python code for finding hash collisions](https://github.com/0vercl0k/z3-playground/blob/master/hash_collisions_z3.py)
* [Seccomp refresher](https://eigenstate.org/notes/seccomp.html)
