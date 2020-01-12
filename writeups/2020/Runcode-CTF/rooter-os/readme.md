# Rooter OS

This isn't really a writeup for the challenge, just a method of documenting the [`rooter-exec.py`](./rooter-exec.py) script I wrote for tunneling through the router to the rest of the network.

The solution flow was roughly:

* Discover [lighttpd path traversal](https://www.rapid7.com/db/vulnerabilities/http-lighttpd-cve-2018-19052) vulnerability allows you to enumerate the file system
* Download the `rooter` binary via a URL like `http://host/tmp../usr/bin/rooter
* Pull out the hardcoded password from the binary and use it to access the router's proprietary service for running system commands
