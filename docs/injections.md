# Injections

This page covers tips and tricks for making the most of injections into vulnerable applications, whether that be TODO or bypassing character blacklists.

## DNS / IP

Sometimes you can control a hostname or IP address to which some kind of request is sent. Perhaps need to bypass some filter, with limited characters or blocklisted strings.

A great explanation of some of the wonky IP address parsing behavior that exists can be found [in this article](https://blog.dave.tf/post/ip-addr-parsing/). Some general tips:

* Octets can be encoded in hex and (sometimes) octal.
* IPv4 addresses can be interpreted as unsigned integers.
* `::` and implicit zero digits in IPv6 lead to lots of really weird behavior.

As a quick reference, the following addresses are sometimes treated equivalently to `0.0.0.0` or `127.0.0.1`:

* `0x7f.0.0.1` == `0x7f.0.0.0x1` == `127.0.0.1`
* `2130706433` == `0x7f000001` == `127.0.0.1`
* `0` == `0x0` == `0.0.0.0`

To generate the packed decimal and hex forms of an IPv4 address, the following Python snippet may come in handy:

```python
>>> ip = "127.0.0.1"
>>> o = [int(x) for x in ip.split(".")]; (o[0]<<24)+(o[1]<<16)+(o[2]<<8)+(o[3]<<0)
2130706433
>>> hex(_)
'0x7f000001'
```

If a DNS name is needed instead of an IP address, then the following are good options:

* [xip.io](http://xip.io/): Create domains that resolve to desired IP addresses (e.g., `1.2.3.4.xip.io` == `1.2.3.4`)
* `localtest.me`: Hostname that resolves to `127.0.0.1`.

## Structured Query Language (SQL)

### General Resources

Some good general-purpose SQL injection resources:

* [websec.ca](https://websec.ca/kb/sql_injection): MySQL-focused, includes topics ranging from default MySQL tables to DNS out of band channeling techniques.
* [pentestmonkey](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet): Any of these cheat sheets is a great resource. Each one covers a different DBMS.

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

### Out of Band Exfiltration

With some blind injections, the only method of exfiltrating data is out of band. Out of band means via a channel not in the synchronous communication that generated the SQL query, so think external network communications like DNS. A great resource for Postgres techniques is covered in [this writeup of the fbctf 2019 challenge hr_admin_module](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md).

## Bash

Bash is an interesting target for injection challenges because there are so many little-known and arcane features scattered throughout it. This section aims to document some potentially useful techniques.

### Bypassing Extreme Character Blacklists

Some useful primitives to get you started:

* Bash's brace expansion means `{a,b,c} == a b c`.
* Characters can be encoded using octal escape sequences like `$'\'`.
* `$#` is the number of parameters.
* `$$` is the process ID.
* [Indirect parameter expansion](https://www.tldp.org/LDP/abs/html/ivr.html) can be applied to Bash's special variables, which means `${!#} == ${0} == /bin/bash` if there are zero parameters passed to Bash.
* `<<<` is Bash's [here string](https://www.tldp.org/LDP/abs/html/x17837.html) operator, which allows for writing a string to a process's stdin.

Additional good resources include [GNU's page on Bash special characters](https://www.gnu.org/software/bash/manual/html_node/Special-Parameters.html) and [The Linux Documentation Project's Bash Internal Variables page](http://tldp.org/LDP/abs/html/internalvariables.html).

For a challenge that uses some of these techniques, check out [this superb writeup of the 34C3 CTF challenge minbashmaxfun](https://hack.more.systems/writeup/2017/12/30/34c3ctf-minbashmaxfun/), which involves crafting a payload comprised of only the characters `$ ( ) # ! { } < \ ' ,`. LiveOverflow explores similar techniques in his [Bash injection without letters or numbers - 33c3ctf hohoho](https://www.youtube.com/watch?v=6D1LnMj0Yt0) video.

### Arithmetic Injections

If you can inject into a Bash arithmetic expression (think `$(( var_name + 1))`), that is actually enough to achieve code execution. This is due to the fact that Bash allows for arbitrary evaluation of array indexing operands, which means injecting a subprocess via ```id``` or `$(id)` is fair game. Here is an example:

```sh
$ x='__[$(id)]'
$ y=$(( 1+x ))
-bash: uid=1001(user) gid=1001(user)...
```

p4 provides a nice [writeup and explanation](https://github.com/p4-team/ctf/tree/master/2019-10-19-seccon/multiplicater) that uses this technique to a solve a challenge from SECCON 2019. Likewise, PlaidCTF 2020's challenge [JSON Bourne](https://ctftime.org/task/11317) could be solved with this kinda of injection, as was done [here](https://ctftime.org/writeup/20090).

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

Server-side execution with ``^[a-zA-Z0-9 ${}`]+$`` [see Balsn's writeup](https://balsn.tw/ctf_writeup/20200314-confidencectf2020teaser/#temple-js-(unsolved)):

```javascript
Function`a${`return constructor`}{constructor}` `${constructor}` `return flag` ``
```

#### `jsfuck`

The [jsfuck](https://github.com/aemkei/jsfuck) project has compiled gadgets for a primitive set of characters that can be used to generate any JavaScript payload.

Good `jsfuck`-inspired gadget lists can be found [in its source](https://github.com/aemkei/jsfuck/blob/76fe36a5c0e3365c0e7fae8086e92233b907d2a5/jsfuck.js#L9-L115) and [in its Wikipedia page](https://en.wikipedia.org/wiki/JSFuck).
