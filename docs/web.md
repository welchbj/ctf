# Web

Web challenges can range a lot. This page aims to cover many common topics for both client and server challenges.

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

TODO: https://shhnjk.blogspot.com/2019/07/intro-to-chromes-gold-features.html?m=1

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

TODO

TODO: fetch and XHR

### Browser JS Runtime Quirks

TODO: hoisting -- https://developer.mozilla.org/en-US/docs/Glossary/Hoisting

### Content Security Policy (CSP)

#### JSONP Bypasses

TODO

#### Script `src` Directory Bypasses

TODO

## Server-side

TODO

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
exiftool -Comment $'<?php system("cat fl* /fl* /home/*/fl*"); ?>' empty.jpg
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

In terms of legitimate interaction with different AWS products, the [`awscli` package](https://github.com/aws/aws-cli) is king.

[Rhino Security Labs](https://rhinosecuritylabs.com/) publishes the best content and writes the best tools for AWS security assessments. Their tool [`pacu`](https://github.com/RhinoSecurityLabs/pacu) automates a lot of attacks.

The following articles are useful references, too:

* [Rhino Security Labs - Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)
* [An SSRF, privileged AWS keys and the Capital One breach](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)

### Google Cloud Platform

The best guide to [GCP](https://cloud.google.com/) security and red teaming I've found was [published by GitLab](https://web.archive.org/web/20200212192707/https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/).
