# Say What

This challenge involved reversing a Microsoft Word macro.

The file extension `.docm` is a big tipoff that this will involve a Word macro of some kind, so my first step was to extract it via the [`olevba`](https://github.com/decalage2/oletools/wiki/olevba) tool from the `oletools` suite. Inspection of the macro source reveals that this is some kind of crackme, with the

Some light reversing resulted in the semi-unobfuscated script found in the [script.vbs](./script.vbs) file. This gave me enough of an understanding of the password transformation to implement a solution, which reverses the transformation to recover the password from the text that it gets compared to in the macro. The key part of my solution requires the observation that the password transformation works on characters two-by-two, so we can bruteforce the flag in chunks of two characters by permutating over all 65536 combinations for each two-byte sequence.
