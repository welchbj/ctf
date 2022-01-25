# QLaaS

This a challenge for finding an exploiting an unknown vulnerability in the [Qiling emulation framework](https://github.com/qilingframework/qiling), version `1.4.1`. Qiling is an emulation framework intended for malware analysis and vulnerability research. It works as a binary format loader and OS abstraction layer on top of the [Unicorn CPU emulation project](https://www.unicorn-engine.org/), with syscall implementations for the main operating systems (POSIX/Linux, Windows, MacOS, etc.).

## Getting Started

This challenge only provided one file: [`main.py`](./main.py). This file is quite simple, doing the following:

* Reading in a base64-encoded binary.
* Creating a temporary directory and writing the user-provided binary to that directory.
* Starting an instance of the Qiling emulator to run the user-provided binary, with the temporary directory as the emulator's root file system.

### Defining Our Goal

Of note from the original challenge description was that the `/readflag` binary on the host must be executed to get the flag. This implies that the flag file is either not in a known location or is not readable by our user. This leads to an important distinction: we must get arbitrary code execution on the host OS (the one running the Qiling emulator), not just arbitrary code execution within the Qiling emulator outside of its root file system.

Knowing this, I can only think of a few ways this can be achieved:

* Abuse of an unsafe function like `eval` or `exec` in the Qiling source.
* Ability to seek/read/write files outside of the emulation's root file system. This would allow us to write shellcode into `/proc/self/mem`.
* Memory corruption in the Python interpreter (seems unlikely, but can't be ruled out).

### Setting Up

Since we're looking at Qiling version 1.4.1, the first step is to download and checkout that version of the repo:

```sh
git clone https://github.com/qilingframework/qiling.git
cd qiling
git checkout 1.4.1
```

## Looking for an Easy Win

[Bandit](https://github.com/PyCQA/bandit) is a tool for finding common vulnerability patterns in Python code, which it does by inspecting the program/library's AST for known patterns.

```sh
# Install the bandit tool.
pip install bandit

# Change into the qiling root directory.
cd qiling

# Run it across the qiling repo, ignoring a few things:
#   B101: Use of assert detected.
#   B108: Probable insecure usage of temp file/directory.
#   B110: Try, Except, Pass detected.
bandit --skip B101,B108,B110 --recursive qiling
```

Through some noise, we do actually see one interesting flagged code segment:

```
>> Issue: [B307:blacklist] Use of possibly insecure function - consider using safer ast.literal_eval.
   Severity: Medium   Confidence: High
   Location: qiling/qiling/os/qnx/syscall.py:204:23
   More Info: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b307-eval
203             if msg_name in dir(_msg_handler):
204                 msg_hook = eval(msg_name)
205                 msg_name = msg_hook.__name__
```

This looks like the use of the dangerous `eval` function in a syscall implementation for QNX. While it looks like we could actually control the argument passed to `eval`, this syscall helper is not actually referenced elswhere in Qiling. Perhaps this will be tied together in a future release?

## Digging Deeper with CodeQL

### Setting Up CodeQL

[CodeQL](https://codeql.github.com/) is a query language designed to scan code for queryable vulnerability patterns. With some custom querying, we may be able to find locations where paths are not properly sanitized by Qiling.

Let's start by setting up CodeQL:

```sh
TODO
```

### Writing a Query

TODO

## Manual Inspection and Exploitation

TODO
