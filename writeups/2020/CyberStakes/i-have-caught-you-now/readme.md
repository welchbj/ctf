# I Have Caught You Now

This was a fairly straightforward web XSS challenge. The goal was to submit a link to an admin, which would then read a private article and exfil the flag (which was somewhere in the private article).

The main observation you needed to make is that the WAF present will reflect back part of your search query in its error page, and not properly escape the reflected text. This is the main vector for XSS. Spaces didn't appear to be allowed in a final payload, but [this StackExchange answer](https://security.stackexchange.com/a/47846) provides a nice `<svg>`-based payload with no spaces required. All that remained at this point was encoding our flag-exiltrating JavaScript in base64 and putting it in an `eval(atob())` wrapper.
