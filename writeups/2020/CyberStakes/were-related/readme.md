# We're Related

This is a cryptography problem that involves attacking textbook RSA.

## Understanding the Server

The [challenge server](./messenger.py) is a messenger application that allows for sending encrypted messages between different users. The messages are encrypted with textbook RSA, which means that they're just using the raw [RSA formulas](https://www.di-mgt.com.au/rsa_alg.html) without adding padding or anything special. We can decrypt any ciphertext we want, as long as hasn't been "seen" by the server before. For the purposes of this challenge, this means that we cannot simply decrypt the flag's ciphertext.

## Exploitation

Knowing how the server functions, it looks like we are going to have to perform a chosen ciphertext attack. However, we can only choose a ciphertext that is not precisely the flag ciphertext. Fortunately, [this StackExchange answer](https://crypto.stackexchange.com/a/2331) explains precisely the kind of attack that we need to perform. My [solve script](./solve.py) is a simple implementation of it.
