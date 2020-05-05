#!/usr/bin/env python3
from Crypto.PublicKey import RSA
import hashlib
import binascii
import sys


class user(object):
    def __init__(self, username, server):
        self.username = username

        self.inbox = []
        self.outbox = []

        self.server = server

class server(object):
    def __init__(self):
        keyfile = open("./serverkey.pem", "rb")
        self.keypair = RSA.import_key(keyfile.read())
        keyfile.close()

        flag = open("./flag", "r").read()
        flag = binascii.hexlify(flag.encode('utf-8'))
        flag = int(b"0x%s" % flag, 16)

        flag_ciphertext = self.keypair._encrypt(flag)
        m = hashlib.sha256()
        m.update(str(flag_ciphertext).encode('utf-8'))

        self.seen_hashes = [m.hexdigest()]

        print("Flag Ciphertext: %s" % flag_ciphertext)
        self.users = {}

    def send_message(self, msg, user):
        if user not in self.users.keys():
            return False

        msg = binascii.hexlify(msg.encode('utf-8'))
        msg = int(b"0x%s" % msg, 16)

        try:
            ctx = self.keypair._encrypt(msg)
        except:
            print("Invalid Plaintext")
            return False

        self.users[user].inbox.append(ctx)

        print(ctx)
        sys.stdout.flush()

        return True

    def recv_message(self, msg):
        msg = str(int(msg))

        m = hashlib.sha256()
        m.update(msg.encode('utf-8'))
        hmsg = m.hexdigest()

        if hmsg in self.seen_hashes:
            return False

        self.seen_hashes.append(hmsg)

        try:
            ptxt = self.keypair._decrypt(int(msg))
        except:
            print("Invalid Ciphertext")
            return False

        print(ptxt)
        sys.stdout.flush()

        return True

    def handle_send_message(self, msg):
        msg = msg.split(':')
        smsg = msg[1]
        user = msg[2]

        if not self.send_message(smsg, user):
            print("[Server] Sending Message Failed")
            sys.stdout.flush()
            return

    def handle_recv_message(self, msg):
        msg = msg.split(':')
        rmsg = msg[1]

        if not self.recv_message(rmsg):
            print("[Server] Message Retrieval Failed")
            sys.stdout.flush()
            return

    def handle_key_message(self):
        n = self.keypair._n
        e = self.keypair._e

        print("N:%s\nE:%s\n" % (n, e))
        sys.stdout.flush()

    def serve(self):
        while 1:
            msg = input()

            if msg.startswith("SEND:"):
                self.handle_send_message(msg)
            elif msg.startswith("RECV:"):
                self.handle_recv_message(msg)
            elif msg.startswith("KEY:"):
                self.handle_key_message()
            else:
                print("[Server] Unrecognized API")
                continue


if __name__ == "__main__":
    s = server()

    Alice = user("Alice", s)
    Bob = user("Bob", s)

    s.users["Bob"] = Bob
    s.users["Alice"] = Alice

    s.serve()
