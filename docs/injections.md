# Injections

This page covers tips and tricks for making the most of injections into vulnerable applications, whether that be TODO or bypassing character blacklists.

## Structed Query Language (SQL)

### `sqlmap`

I am always amazed by the power of [`sqlmap`](https://github.com/sqlmapproject/sqlmap) when I use it. This section includes some general tips for this tool's use and some resources for customizing its behavior.

#### Overview

`sqlmap` is usually good enough to start working on its own. I like to give it a recorded HTTP request to get going:

```sh
sqlmap -r recorded-request.req --batch
```

#### Tamper Scripts

`sqlmap`'s [tamper scripts](https://github.com/sqlmapproject/sqlmap/tree/master/tamper) provide a mechanism for altering the input that. The library ships with many tamper scripts, but you can write your own, too. They follow the format:

```python
#!/usr/bin/env python

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL


def tamper(payload, **kwargs):
    # Mutate the payload somehow.
    return payload
```

And can then be invoked with:

```sh
sqlmap -r recorded-request.req --batch --tamper path/to/my/tamper/script.py
```

## Python

### Overview

Most Python template injection challenges will involve trying to walk your way up to process-spawning reference somewhere in memory. A lot of guides will tell you to get a reference to `subprocess.Popen` via `__mro__ -> object -> __subclasses__()`, but I think a much better generic solution is walking up to `builtins['__import__']` via the `__globals__` attribute of any defined method of any object instance floating around in memory (these are almost always available).

If seeing command output inline is a must, then aiming for a payload that achieves `__import__('subprocess').check_output('/bin/bash -c "cat fl* /fl* /home/*/fl*"', shell=True)` is a good target.

### Sandbox Escape Techniques

You can go a lot of ways with Python sandbox escaping. Here are some good writeups that explore this topic:

* [Python Sandbox Escape Some Ways](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/): General overview of some basic Python sandbox escape techniques.
* [Escaping a Python sandbox (NdH 2013 quals writeup)](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/): A very involved solution that creates a custom type with custom Code Objects.
* [Escaping a Python sandbox with a memory corruption bug](https://hackernoon.com/python-sandbox-escape-via-a-memory-corruption-bug-19dde4d5fea5): Real-life exploitation that uses a memory corruption bug in a Python library.

### Bypassing Character Filters

For Flask/Jinja SSTI problems, if `_` is blacklisted then a pretty generic gadget for it is `g.get|string|slice(4)|first|last`. A great overall reference for Flask/Jinja SSTI can be found [here](https://web.archive.org/web/20200217202837/https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti).

## JavaScript

Note that many of these techniques are applicable to both client-side and server-side JavaScript runtimes.

### Sandbox Escape Techniques

See [Sandboxing NodeJS is hard, here is why](https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html) for a discussion of sandbox escapes for the NodeJS [`vm`](https://nodejs.org/api/vm.html) and [`vm2`](https://github.com/patriksimek/vm2) modules.

For other ideas, looking at the `vm2` [issues](https://github.com/patriksimek/vm2/issues/187) can help, as well.

### JSON Confusion

Sometimes, the goal of your injection is to corrupt or manipulate a JSON object that can lead to new paths of execution in the targeted application. A potential way of doing this is through the injection of JSON Unicode escape sequences. For an indepth introduction to this idea, take a look at [Bypassing WAFs with JSON Unicode Escape Sequences](https://trustfoundry.net/bypassing-wafs-with-json-unicode-escape-sequences/) from TrustFoundry.

Some specific CTF challenge writeups using JSON Unicode escape sequences include:

* [Balsn's CONFidence CTF 2020 cat web writeup](https://balsn.tw/ctf_writeup/20200314-confidencectf2020teaser/#cat-web): Uses `\u0022` (encoded `"`) for XSS.

### Bypassing Character Filters

In the event that the injection point restricts the permitted set of input characters, you may have to get fancy. Fortunately, this is a trodden path.

#### Overview

The gist of most JavaScript injections involve walking up to the [`Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) constructor, defining a generic payload from a string, and executing the new `Function` definition. This usually equates to something along the lines of:

```javascript
[]['fill']['constructor']('alert(1);')()
```

#### Generic Payloads

Client-side execution without parentheses (see [PortSwigger's JavaScript without parentheses using DOMMatrix](https://portswigger.net/research/javascript-without-parentheses-using-dommatrix)):

```javascript
x=new DOMMatrix;
matrix=alert;
x.a=1337;
location='javascript'+':'+x
```

Client-side execution with `a-zA-Z0-9=+{}` charset (see [@terjanq's tweet](https://twitter.com/terjanq/status/1223403166118694912) and [related slackers thread](https://www.reddit.com/r/Slackers/comments/ex5mmt/cool_ways_to_generate_strings_in_javascript/)).

Server-side execution with `^[a-zA-Z0-9 ${}\`]+$` [see Balsn's writeup](https://balsn.tw/ctf_writeup/20200314-confidencectf2020teaser/#temple-js-(unsolved)):

```javascript
Function`a${`return constructor`}{constructor}` `${constructor}` `return flag` ``
```

#### `jsfuck`

The [jsfuck](https://github.com/aemkei/jsfuck) project has compiled gadgets for a primitive set of characters that can be used to generate any JavaScript payload.

Good `jsfuck`-inspired gadget lists can be found [in its source](https://github.com/aemkei/jsfuck/blob/76fe36a5c0e3365c0e7fae8086e92233b907d2a5/jsfuck.js#L9-L115) and [in its Wikipedia page](https://en.wikipedia.org/wiki/JSFuck).
