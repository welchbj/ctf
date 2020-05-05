# Do You C What I C

This was a Windows pwnable challenge. Most CTFs tend to be exclusively Linux, so I struggled through this one a bit.

The vulnerable application is a basic number-managing application that lets you read or write numbers, stored in a large array on the stack. The writes appear to be properly bounded, but the reads are unbounded. However, the code that reads in the hex-formatted data that you want to write to a specified index is not properly bounded, and allows for overwriting several important pieces of stored data (like the stack cookie, stored frame pointer, stored SEH address, and stored return address). Since the function never returns, overwriting the return address does nothing for us. We must instead focus on the SEH record (made easier by the fact that the binary does not have [SafeSEH](https://docs.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers)).

I won't go into a ton of detail here, but the basic exploitation flow was:

* Write our main payload shellcode to the number array, packed as 32-bit dwords.
* Use the unbounded read to leak the stack cookie value.
* Use the unbounded read to leak a stack address that sits at a known offset from the number array (which is also stored on the stack).
* Overwrite the SEH address stored on the stack with the address of the stack number array (where we put our shellcode). We also have to make sure we overwrite the stored cookie with the correct value.

This exploitation flow relies on DEP being disabled on the target, which was not immediately obvious from the problem description or hints. I was eventually able to observe that DEP was disabled on target by calling out to myself with a `WinExec` payload of `ftp.exe -A 159.65.160.185`. Testing this was annoying on my Windows 10 host, where DEP is enabled. Because I wasn't willing to globally disable DEP, each time I debugged the program I had to manually mark the stack as RWX in Immunity Debugger's memory view.

With the ability to execute code, I was expecting to easily pop a shell with an `msfvenom` reverse shell payload. I'm still not sure why, but I could never get one of those payloads to execute properly. Instead, I consulted [this excellent resource](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/) to gain code execution via `WinExec`. I ended up going with their `rundll32.exe` example, which downloads and executes a payload from a DLL hosted on an SMB share.
