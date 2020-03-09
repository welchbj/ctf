# Random ECB

From inspection of the [server source](./server.py), it becomes pretty obvious that this involves a chosen plaintext attack on ECB mode of operation. An explanation of how this kind of attack works is well-explained in the answers to [this StackOverflow answer](https://crypto.stackexchange.com/questions/42891/chosen-plaintext-attack-on-aes-in-ecb-mode).

An implementation of my solution can be found [here](./solve.py).
