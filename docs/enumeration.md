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

If you choose not to see the light, these Nmap snippets will prove useful:
```sh
export HOST=scanme.nmap.org

# quick TCP port scan on common ports
nmap -vv -n -Pn -sV -sC --top-ports 1000 -oN $'nmap.tcp.quick.'$(date -Iseconds) $HOST

# thorough and complete TCP port scan on all ports
nmap -vv -n -Pn -sV -sC -p- -oN $'nmap.tcp.thorough.'$(date -Iseconds) $HOST

# UDP scan
nmap -vv -n -Pn -sV -sC -sU -oN $'nmap.udp.'$(date -Iseconds) $HOST
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

Your friend for HTTP fuzzing wordlists will be the [SecLists project](https://github.com/danielmiessler/SecLists). The best open source HTTP fuzzing engine that I know of is the [wfuzz project](https://github.com/xmendez/wfuzz). Here are some useful snippets combining these two awesome projects:

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

Projects like [LinEnum](https://github.com/rebootuser/LinEnum) are great for automating tedious privilege escalation checks. Here are some snippets related to serving a script over the public internet:
```sh
TODO
```

### Process Watching

A lot of information can be gleaned by watching changes to [procfs](https://en.wikipedia.org/wiki/Procfs). An amazing tool for automating this is [`pspy`](https://github.com/DominicBreuker/pspy). Here are some snippets for transferring it to target and executing:
```sh
TODO
```

## Pivoting

### Scanning the Subnet

If you don't care about being too loud, this `ping` snippet is a quick-and-dirty way of detecting adjacent hosts on your subnet:
```sh
export SUBNET=192.168.33
for i in {1..254}; do (ping $SUBNET.$i -c 1 -w 5  >/dev/null && echo "$SUBNET.$i" &); done
```

TODO: automated port scans on the subnet

### Spraying Creds

#### SMB

TODO: cme

#### SSH

TODO: hydra? medusa?
