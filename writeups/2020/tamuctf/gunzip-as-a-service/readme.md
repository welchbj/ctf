#  Gunzip as a Service

Pulling up this binary in Ghidra, it looks like `gets` is called on our `gunzip`-ed input. Because of NX being enabled on this binary, it looks like we have to send a `gzip`-ed ROP chain to the binary.

Experimenting with that theory:

```sh
pwn cyclic -n 4 1200 > cyclic.txt
<cyclic.txt >cyclic.gz gzip
<cyclic.gz ./gunzipasaservice
```

This segfaults, and if we look at the `dmesg` logs we get:

```
[39567.067921] gunzipasaservic[22302]: segfault at 6b61616d ip 000000006b61616d sp 00000000ff9fb3a0 error 14 in libc-2.29.so[f7da9000+1d000]
```

Plugging this EIP overwrite back into `pwn cyclic` gets us our offset (note that `0x6b61616d` can be encoded as the string `"maak"`):

```sh
$ pwn cyclic -n 4 -l maak
1048
```

A great ROP gadget available to us is the address of the `execl` function. Fortunately, there are also references to the strings `"/bin/sh"` and `"-c"` in the binary. These are the basic ingredients for our exploitation flow:

* Send 1048 dummy bytes, bringing us right next to where the stored EIP address is in the stack frame.
* Overwrite EIP with the address of `execl`.
* Make fake stack arguments to achieve a call of `execl("/bin/sh", "/bin/sh", "-c")
* `gzip` our whole payload and send it to the target.

Find these steps in my solution script [here](./solve.py).
