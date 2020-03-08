# Cryptography

## General References

Here are some general

* [Cryptopals](https://cryptopals.com/) - A collection of challenges to teach you about different cryptographic vulnerabilities.

## Substitution Ciphers

### Automated Solvers

There are a few handy websites for automating the solution of some cryptogram problems:

* [quipqiup](https://quipqiup.com/): Fast and accurate cryptogram solver.
* [dcode.fr](https://www.dcode.fr/en): Solves a variety of basic ciphers and offers some brute forcing functionality.

## One-time Pad (OTP)

[OTP](https://en.wikipedia.org/wiki/One-time_pad) is an encryption scheme that is secure as long as the following conditions are met:

* Key length greater than or equal to the length of the message.
* Keys are never re-used.

[This StackOverflow question](https://crypto.stackexchange.com/questions/59/taking-advantage-of-one-time-pad-key-reuse) explains in detail how to exploit erroneous applications/implementations of OTP.

## Block Ciphers

Block ciphers are symmetric-key-powered deterministic transformations on fixed-length groups of bits (i.e., blocks). The below sections comprise a non-exhaustive list of potential misuses and weaknesses of the various block cipher modes of operation.

### Electronic Codebook (ECB)

[ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) mode of operation's inherent weakness comes from the fact that any plaintext block will always produce the same ciphertext block, no matter where it occurs in the overall message. I find this to be well-explained by the [ECB penguin](https://crypto.stackexchange.com/questions/14487/can-someone-explain-the-ecb-penguin) classic example.

Some potential attacks include:

* Chosen plaintext attack. Find great explanations in the answers to [this StackOverflow question](https://crypto.stackexchange.com/questions/42891/chosen-plaintext-attack-on-aes-in-ecb-mode).
* ECB cut-and-paste. Since the same plaintext will always produce the same ciphertext, you can re-order encrypted blocks to forge messages. This is well-explained within solutions to the [Cryptopals problem of the same name](https://cryptopals.com/sets/2/challenges/13).

### Cipher Block Chaining (CBC)

TODO

### Galois/Counter Mode (GCM)

[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) mode of operation provides authentication (i.e., integrity) in addition to encryption (i.e., confidentiality).

Some potential pitfalls and opportunities for attack include:

* The Forbidden Attack: Nonce reuse is always bad, but it also allows for authenticity tag forgery for some problem setups. This is explored in [this ctf writeup](https://web.archive.org/web/20190117114407/http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/) and [accompanying solve script](https://web.archive.org/web/20200308130642/https://gist.github.com/rugo/c158f595653a469c6461e26a60b787bb).
* Applications to TLS: [This paper](https://eprint.iacr.org/2016/475.pdf) and [this ctf writeup](https://web.archive.org/web/20190117114407/http://blog.redrocket.club/2018/03/27/VolgaCTF-Forbidden/) explore the weaknesses and implications of nonce-reuse within TLS implementations.
