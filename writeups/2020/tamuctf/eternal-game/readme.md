# Eternal Game

It quickly becomes obvious that this challenge will require a [hash length extension attack](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks).

A hash length extension attack is feasible for this problem for the following reasons:

* SHA512 is an algorithm vulnerable to hash length attacks.
* The server implements weak input-parsing logic that starts at the end of our message. Furthermore, the server does not reject the entire message once it encounters bad input; it just returns with the score it has already calculated.

So, now to build our attack. At the start of a new game, the data should always be `1`. When we request the proof of this score, we get the signature:

```
a17b713167841563563ac6903a8bd44801be3c0fb81b086a4816ea457f8c829a6d5d785b49161972b7e94ff9790d37311e12b32221380041a99c16d765e8776c
```

So, we have a plaintext and it's corresponding signature. This (along with knowledge of the server secret's length) is enough to forge a new message with arbitrary data appended and a corresponding valid proof hash.

To perform the hash length calculation, I used the awesome [Python bindings](https://pypi.org/project/hashpumpy/) for the equally awesome [HashPump tool](https://github.com/bwall/HashPump).

The only remaining unknown is the length of the server's secret prefix. This can be bruteforced, as is done in my [solution script](./solve.py).
