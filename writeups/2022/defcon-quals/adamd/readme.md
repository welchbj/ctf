# adamd

Flag checker problem with a custom Python interpreter. I took an approach of solving this from the Python side rather than reversing/diffing the actual changes to the Python interpreter.

## Finding a Starting Point

We are given what appears to be a modified Python interpreter (the `python` binary is in [`bin/`](bin/)) and a compiled Python bytecode file called [`chall.pyc`](chall.pyc).

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

### Finding the Flag Length

Because we can load the `chall` module and call `check_flag` ourselves, this means we can pass an arbitrary argument to the `check_flag` function. While it presumably expects a `str` or `bytes` object, we can instead make a custom class that quacks like `str` or `bytes` and use this to better understand what the `check_flag` function wants to actually check about our input.

As an example, let's assume that `check_flag` will start accessing elements on our input, provided it's the right length. We can make a class that looks like the following:

```python
class Hook:
    def __init__(self, len_):
        self.len_ = len_

    def __getitem__(self, idx):
        1/0

    def __len__(self):
        return self.len_
```

Now, by fuzzing `check_flag` with `Hook` instances of varying lengths until we trigger a `ZeroDivisionError`, we can determine the flag length. This is demonstrated with the [`hook_check_flag_find_len.py`](hook_check_flag_find_len.py) script:

```sh
$ ./bin/python hook_check_flag_find_len.py
Flag len: 59
```

### (Almost) Finding the Flag

We can take the premise of our length-finding approach to hook other Python [dunder methods](https://www.pythonmorsels.com/what-are-dunder-methods/) to figure out what conditions `check_flag` attempts to verify on our input. After some experimentation with overriding various dunder methods like `__and__` with `1/0` expressions to trigger raises of `ZeroDivisionError`, I was able to determine that `check_flag`'s workflow did the following:

* Access a byte at specific index
* Bitwise AND that byte (via Python's `__and__`) with an integer
* Compare the result of that operation (via `__eq__`) with another integer

By hooking `__getitem__` (for index accesses), `__and__` (for the bitwise ANDs), and `__eq__` (to record the target result), we can record `check_flag`'s full set of constraints and then solve for them via [`z3`](https://ericpony.github.io/z3py-tutorial/guide-examples.htm).

The capturing of constraints is implemented in [`hook_check_flag_find_constraints.py`](hook_check_flag_find_constraints.py):

```sh
$ ./bin/python hook_check_flag_find_constraints.py
Access of index: 27                               
Bitwise and with: 8                               
Equality comparison with: 8
Access of index: 32                               
Bitwise and with: 64                              
Equality comparison with: 64
... and so on ...
```

Once this series of constraints has been encoded, we can make a simple Z3 model to solve for what we hope is the flag. This is implemented in [`z3_solve.py`](z3_solve.py):

```sh
$ ./bin/python hook_check_flag_find_constraints.py > hook_results.txt
$ python3 z3_solve.py
b'\x8e\x86\x8d\x95\xbb\xaa\xb9\xb2\xc8\xb3\xba\xc5\xaf\xc3\xc8\xc7\xc5\xb9\xcf\xe3\xe3\xe6\xd3\xd3\xd1\xe4\xe1\xcd\xe3\xf2\xed\xfa\xe0\xe9\xea\xddC0EH\xe7\xf3\x0f\xed\x06\x17\x02\xf5_Z^\x13`\x16\x15fhj)'
1 solutions
```

Unfortunately, the only sequence of bytes that satisfies `check_flag` isn't the flag itself. But it will still prove useful.

## Backtracking to `main`

So, we know what input we want to pass to `check_flag` that passes the constraints and gives us a win message. If we also choose to assume that the input to the program as a whole is simply the flag string itself (without any encoding applied), then the only thing that can be happening is some transformation of our flag input between when we provide it to `main` and when it gets passed as an argument to `check_flag`.

To better understand this, let's hook `check_flag` itself to see what `main` ends up passing it. We also hook `__builtins__.input` so we can programmatically pass our input to `main` rather than having it read from `stdin`.

```sh
$ ./bin/python
>>> __builtins__.input = lambda x: "FLAG{" + "A"*53 + "}"
>>> import chall
>>> chall.check_flag = lambda x: print("check_flag called with:", x) 
>>> chall.main()
check_flag called with: b'\x8e\x86\x8d\x95\xbb\x93\x95\x97\x99\x9b\x9d\x9f\xa1\xa3\xa5\xa7\xa9\xab\xad\xaf\xb1\xb3\xb5\xb7\xb9\xbb\xbd\xbf\xc1\xc3\xc5\xc7\xc9\xcb\xcd\xcf\xd1\xd3\xd5\xd7\xd9\xdb\xdd\xdf\xe1\xe3\xe5\xe7\xe9\xeb\xed\xef\xf1\xf3\xf5\xf7\xf9\xfb)'
Wrong flag :(
I'm going to mine some nautilus flag tokens on your GPU!
```

This confirms our suspicion that `main` *is* transforming our input in some way. But also observe how the transformed version of our input begins with the same byte sequence as the correct `check_flag` argument we solved for earlier. This implies that `main`'s transformation occurs byte-by-byte (i.e., the bytes after the position-being-transformed don't affect the transformation). Does this mean we can just bruteforce the flag byte-by-byte until `check_flag` is called with an argument that matches the byte sequence we solved for with Z3? Yes, yes it does.

Due to the fact that we want to automate this bruteforce using a normal CPython interpreter (to use things like `process` from `pwntools`), we create a simple guesser program ([`hook_guess.py`](hook_guess.py)) meant to be invoked with the modified CPython binary by the driver bruteforcer ([`brute.py`](brute.py)). This produces the flag relatively quickly:

```sh
$ python3 brute.py
FLAG{h                                            
FLAG{he                                           
FLAG{hel                                          
FLAG{help                                         
FLAG{helpi                                        
FLAG{helpin                                       
FLAG{helping                                      
FLAG{helping_                                     
FLAG{helping_a                                    
FLAG{helping_ad                                   
FLAG{helping_ada                                  
FLAG{helping_adam
... and so on ...
```
