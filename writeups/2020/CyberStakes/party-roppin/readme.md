# Party Ropping

This was a binary exploitation challenge that involved building a ROP payload.

The trick with this challenge was that each time you connected to the remote service, it would send you a slightly different binary to exploit. The only differences that I was able to observe in these binaries were the different book records that they contained and slightly different addresses for the required ROP gadgets.

The core vulnerability in the binary is the ability to specify negative indexes when checking out a book, which lets you write over the stack's stored return address (and a little bit beyond). However, this does not give us a ton of space to work with for building a ROP chain capable of executing arbitrary code. Fortunately, the program has a very large `choice` global buffer, that we can populate by searching for books by title. Since this isn't a PIE, we know the address of this buffer with certainty and can pivot the stack to it (which we can do with a `pop rsp; ...; ret;` gadget present in the binary).

Once the stack is pivoted, we can use a code-executing ROP chain without worrying about being especially space-efficient. I set up a ROP chain that does the following:

* [`mmap`](http://man7.org/linux/man-pages/man2/mmap.2.html) a RWX region of memory. To make referencing this address easier in the next step of the ROP chain, I used `mmap`'s `MAP_FIXED` flag, which tells `mmap` you want the allocated memory to be at *precisely* the specified address (just make sure it's page-aligned).
* `read` from `stdin` into this `mmap`ed region. This is when we'll send a basic `system("/bin/sh")` shellcode.
* Redirect the execution flow to the `mmap`ed region, executing our `system("/bin/sh")` shellcode.

Even though the gadget addresses change on each connection to the remote target, the same gadgets are always available. I ended up writing a simple [`ropper`](https://github.com/sashs/Ropper) output parser to compute the gadget addresses for each invocation of the program. This results in a nearly-always reliable exploit.
