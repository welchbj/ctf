# Into the Metaverse

This was a high point challenge that implemented a custom VM for executing a check on the user's input (which would be the flag when the check passed). Not wanting to reverse the whole VM, I first tried to see if [`angr`](https://angr.io/)(a symbolic execution and binary analysis framework) could solve for the flag.

It turns out that it can! I was able to use my pretty standard `angr` crackme template, which sets up the flag's symbolic variables (with some basic constraints to follow the flag format) on stdin. `angr` is even able to get through each iteration of the solution so quickly that I could bruteforce the flag length, too.
