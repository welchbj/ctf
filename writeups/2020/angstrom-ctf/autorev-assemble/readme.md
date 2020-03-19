# Autorev, Assemble!

Taking a look at this binary, it looks like a standard crackme that performs a bunch of checks on the input. Due to the straightforward nature of the checks being made, this is a great candidate for symbolic execution with [angr](https://angr.io/).

Looking at the initial `fgets` call, I assumed the desired input length was `0x100`, but it appears to actually be much shorter than that. My angr-powered [solution script](./solve.py) could figure it out anyways.
