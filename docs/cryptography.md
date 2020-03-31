# Cryptography

## General References

Here are some general

* [Cryptopals](https://cryptopals.com/) - A collection of challenges to teach you about different cryptographic vulnerabilities.

## Substitution Ciphers

### Tools for Manual Tweaking

[CyberChef](https://gchq.github.io/CyberChef/) is king for playing with data in weird formats in your browser. Here are some of its most useful modules:

* Fork: Lets you divide input data into separate streams that will then be processed separately by the specified modules.
* XOR brute force: I've really only found this useful for single-byte XOR keys, but this module can still deliver some quick wins.
* Magic: This is an awesome module that tries to apply permutations of other modules, looking for data with interesting entropy levels. One thing I've noticed is that this module *will not* apply ASCII85 decoding, so try that one manually.

### Other Random Encoding Formats

Sometimes data is encoded in formats that aren't immediately clear. Ones I've run into trouble with in the past:

* [NetBIOS encoding](https://en.wikipedia.org/wiki/NetBIOS): If you see a string of uppercase alphabet letters, this might be NetBIOS-encoded data. This is also an option for encoding data with [dnscat](https://wiki.skullsecurity.org/Dnscat), so be on the lookout for this data in PCAPs, too.

### Automated Solvers

There are a few handy websites for automating the solution of some cryptogram problems:

* [quipqiup](https://quipqiup.com/): Fast and accurate cryptogram solver.
* [guballa.de](https://www.guballa.de/substitution-solver): An alternative to quipqiup that also provides good results.
* [dcode.fr](https://www.dcode.fr/en): Solves a variety of basic ciphers and offers some brute forcing functionality.

### Hill Ciphers

The [Hill Cipher](https://en.wikipedia.org/wiki/Hill_cipher) is a variation of the classic subsitution cipher based on linear algebra. [This solution script](https://github.com/LionelOvaert/write-ups/blob/master/b01lers_ctf_2020/crypto_crossword/solve.py) gives an example of using the Python library [sympy](https://www.sympy.org/en/index.html) to solve a Hill Cipher.

## One-time Pad (OTP)

[OTP](https://en.wikipedia.org/wiki/One-time_pad) is an encryption scheme that is secure as long as the following conditions are met:

* Key length greater than or equal to the length of the message.
* Keys are never re-used.

[This StackOverflow question](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse) explains in detail how to exploit erroneous applications/implementations of OTP.

## RSA Cryptography

### Basics

[The RSA Wikipedia page](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) is pretty good about explaining the basic RSA parameters.

For a more CTF-oriented look at the basics, try [this link](https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/).

### Applications of Number Theory

For a nice challenge and writeup applying number theory to solving an RSA problem, look [here](https://advenamtacet.github.io/Writeups/rsa/math/justctf/2020/01/25/RSA-exponent-task.html).

## Block Ciphers

Block ciphers are symmetric-key-powered deterministic transformations on fixed-length groups of bits (i.e., blocks). The below sections comprise a non-exhaustive list of potential misuses and weaknesses of the various block cipher modes of operation.

### Electronic Codebook (ECB)

[ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) mode of operation's inherent weakness comes from the fact that any plaintext block will always produce the same ciphertext block, no matter where it occurs in the overall message. I find this to be well-explained by the [ECB penguin](https://crypto.stackexchange.com/questions/14487/can-someone-explain-the-ecb-penguin) classic example.

Some potential attacks include:

* Chosen plaintext attack: Find great explanations in the answers to [this StackOverflow question](https://crypto.stackexchange.com/questions/42891/chosen-plaintext-attack-on-aes-in-ecb-mode).
* ECB cut-and-paste: Since the same plaintext will always produce the same ciphertext, you can re-order encrypted blocks to forge messages. This is well-explained within solutions to the [Cryptopals problem of the same name](https://cryptopals.com/sets/2/challenges/13).

### Cipher Block Chaining (CBC)

TODO

### Galois/Counter Mode (GCM)

[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) mode of operation provides authentication (i.e., integrity) in addition to encryption (i.e., confidentiality).

Some potential pitfalls and opportunities for attack include:

* The Forbidden Attack: Nonce reuse is always bad, but it also allows for authenticity tag forgery for some problem setups. This is explored in [this ctf writeup](https://web.archive.org/web/20190117114407/http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/) and [accompanying solve script](https://web.archive.org/web/20200308130642/https://gist.github.com/rugo/c158f595653a469c6461e26a60b787bb).
* Applications to TLS: [This paper](https://eprint.iacr.org/2016/475.pdf) and [this ctf writeup](https://web.archive.org/web/20190117114407/http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/) explore the weaknesses and implications of nonce-reuse within TLS implementations.

## Hash Length Extension Attacks

Under specific conditions, and the right vulnerable hashing algorithms, it is possible to forge messages with valid tags using [hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks).

Tools for performing these types of attacks include:

* [HashPump](https://github.com/bwall/HashPump): This is my preferred tool, especially because it hash its own [Python bindings](https://pypi.org/project/hashpumpy/).
* [hash_extender](https://github.com/iagox86/hash_extender): Another fine option, but no Python bindings.

For a more involved writeup that doesn't just involve using the vanilla version of one of the above tools, see [this writeup](https://blog.mheistermann.de/2014/04/14/plaidctf-2014-parlor-crypto-250-writeup/) of a challenge from PlaidCTF 2014.

## Hash Collision Attacks

It's important to note that **all** hashing algorithms are vulnerable collisions (due to the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem)). Conditions which cause collisions can just be more precisely controlled in some algorithms versus others.

It is now feasible (and within scope of a CTF challenge) to collide hashes for some weaker/older hashing algorithms (think MD5 and SHA1). The [collisions](https://github.com/corkami/collisions) repository has great explanations of and example code for different collision-based attacks. The [hashclash tool](https://github.com/cr-marcstevens/hashclash) provides utilities for performing some collision attacks.

Some challenges may become simpler with knowledge of "special" hashes, such as those with many leading zeroes. Some interesting plaintexts and their corresponding hashes can be found at [this link](https://web.archive.org/web/20180419023213/http://0xf.kr/md5/).
