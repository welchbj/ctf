# Mercenary Hat Factory

This was a Python web application challenge that involved some basic JWT and less-basic Jinja template injection.

The basic solution flow is:

* Use `alg = none` JWT trick to bypass signature check
* See that nested list structure for storing user information is flawed and can be overwritten at will
* Bypass SSTI blacklists to reach code execution

The hardest part about the Jinja SSTI payload was avoiding underscores and spaces. I found that the expression `g.get|string|slice(4)|first|last` would evaluate to `'_'` (abusing coercion of `g`'s class name to a string). We can do something similar to get a space character primitive. We can use these in conjunction with Jinja's string concatenation operator `~` to build otherwise-restricted strings. Pairing these with our good friends `|attr`, `__builtins__`, and `os.system`, we can achieve some command execution. This can all be seen in my [solve script](./solve.py).

Looking at other writeups, I see that you can just use hex-escaped strings to bypass the `_` blacklist. Oh well.
