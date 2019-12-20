# Super Calc

This was a pretty awesome challenge which required some Python/Flask/Jinja knowledge. The solution flow is:

* Observe that there does not appear to be a way to achieve code execution through expression evaluation due to the restrictive ast whitelist/blacklist
* Observe that we can put anything in comments, which won't get parsed by the ast
* Verify that Jinja template injection works in comments when we trigger a legitimate error (something like `1/0 --> ZeroDivisionError` or `1@1 --> TypeError`), as the error message rendering does not sanitize the expression contents
* Eventually build a Jinja template code execution payload, working around the semi-restrictive character blacklist

It turns out the intended solution was just to leak the secret token via a `{{ config.items() }}` injection, and then use this to a sign a cookie with a malicious expression. This would work since expressions are only sanitized / verified on submission, not after they are included in a cookie.

My solve script is available [here](./solve.py).
