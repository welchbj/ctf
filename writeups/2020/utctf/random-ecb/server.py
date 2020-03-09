#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits

# flag stubbed out for local testing.
flag = b'utflag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
KEY = get_random_bytes(16)


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encryption_oracle(plaintext):
    b = getrandbits(1)
    plaintext = pad((b'A' * b) + plaintext + flag, 16)
    return aes_ecb_encrypt(plaintext, KEY).hex()


if __name__ == '__main__':
    while True:
        print("Input a string to encrypt (input 'q' to quit):")
        user_input = input()
        if user_input == 'q':
            break
        output = encryption_oracle(user_input.encode())
        print("Here is your encrypted string, have a nice day :)")
        print(output)
