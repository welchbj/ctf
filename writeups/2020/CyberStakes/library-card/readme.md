# Library Card

This was a basic reverse engineering problem that involved calling a single function from a shared library.

I was able to solve this problem with `angr`'s binary emulation. We can user `angr`'s [`call_state`](https://github.com/angr/angr-doc/blob/1ad7173c6503175b736f4296e6e2ff1d3d0aceb7/docs/states.md#state-presets) to begin execution at the desired library function. `angr`'s `call_state` also allows us to specify the correct arguments for the function (which could be identified from static analysis). Then, we can just grab the flag from the emulated state's `stdout`.
