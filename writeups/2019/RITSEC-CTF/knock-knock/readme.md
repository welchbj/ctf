# Knock Knock

This was an interesting challenge with some infra frustrations due to the shared environment. The gist of this challenge was:

* SSH into a shared server where there is a lot of incoming / outgoing traffic
* Observe a re-occuring port knock sequence that opens access to 443
* Replay the port knock and request the HTTPS server, which returns the flag

The hard part of this challenge was sending the observed port knock fast enough, since people were constantly port scanning the server and interrupting any sent port knocks. Eventually, I was able to successfully use the following:
```sh
for port in 2710 5293 6608; do (nc -nz -w 1 192.168.0.14 $port &); done; curl -k https://192.168.0.14:443
```
