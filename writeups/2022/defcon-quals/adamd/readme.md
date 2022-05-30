# adamd

Flag checker problem with a custom Python interpreter. I took an approach of solving this from the Python side rather than reversing/diffing the actual changes to the Python interpreter.

## Finding a Starting Point

We are given what appears to be a modified Python interpreter (the `python` binary is in [`bin/`](bin/) and a compiled Python bytecode file called [`chall.pyc`](chall.pyc).

Simply running the `python` binary reports that this is Python 3.12:

```
$ ./bin/python
Python 3.12.0a0 (heads/main:8d1f948adb, May 21 2022, 07:53:34) [GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Additionally, legitimate CPython interpreter binaries choke on this bytecode format. This confirms our suspicion that we are dealing with a modified CPython build.

Using the provided Python binary to run `chall.pyc` presents us with a check flag prompt:

```
$ ./bin/python chall.pyc
Give me a flag:
```

So the end goal is to deduce what input to the program (the flag) passes a gauntlet of constraints/checks within the `chall.pyc` bytecode and potentially within the `python` binary itself.

Let's start by looking at `chall.pyc` at the macro level. Because it is a Python module, we can import it into a Python REPL and inspect what's defined within it:

```sh
$ ./bin/python
>>> import chall
>>> chall.__dict__.keys()
dict_keys(['__name__', '__doc__', '__package__', '__loader__', '__spec__', '__file__', '__cached__', '__builtins__', 'check_flag', 'main'])
```

`main` and `check_flag` look interesting. If we can assume `main` is just the boilerplate for reading our input from `stdin`, the meat of the constraints should be in `check_flag`.

## Solving `check_flag`

Because we can load the `chall` module and call `check_flag` ourselves, this means we can pass an arbitrary argument to the `check_flag` function. While it presumably expects a `str` or `bytes` object, we can instead make a custom class that quacks like `str` or `bytes` and use this to better understand what the `check_flag` function wants to actually check about our input.

As an example:

TODO

## Backtracking to `main`

So, we know what input we want to pass to `check_flag` that passes the constraints and gives us a win message. If we also choose to assume that the input to the program as a whole is simply the flag string itself (without any encoding applied), then the only thing that can be happening is some transformation of our flag input between when we provide it to `main` and when it gets passed as an argument to `check_flag`.

TODO
