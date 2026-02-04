#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""DH kex server."""

import os
from socketserver import BaseRequestHandler, ThreadingTCPServer
import binascii
import pyaes
import hashlib
from pyaes import AES


SECRET_MSG = b"I love you!"


def generate_random(N, bits=1536):
    """Generate a random number with bits=1536, then mod N."""
    byte = bits // 8
    rnd_num = os.urandom(byte)
    # ensure the number of bits is as high as 'bits'
    while rnd_num[0] < 128:
        rnd_num = os.urandom(byte)

    # convert from ascii to hex to a decimal integer
    rnd_num = int(''.join(format(i, 'x') for i in rnd_num), 16)
    return rnd_num % N

def encrypt(plaintext: bytes, key: bytes):
    aes = AES(key)
    buf = bytearray(plaintext)
    if len(buf) % 16 != 0:
        residual = len(buf) & 16
        buf.extend(bytearray(residual))

    plaintext_blocks = [buf[i:i+16] for i in range(0, len(buf), 16)]
    ciphertext_blocks = [bytes(aes.encrypt(bytes(block))) for block in plaintext_blocks]
    return b"".join(ciphertext_blocks)

def decrypt(ciphertext: bytes, key: bytes):
    aes = AES(key)
    buf = bytearray(ciphertext)
    if len(buf) % 16 != 0:
        residual = len(buf) & 16
        buf.extend(bytearray(residual))
    ciphertext_blocks = [buf[i:i+16] for i in range(0, len(buf), 16)]
    plaintext_blocks = [bytes(aes.decrypt(bytes(block))) for block in ciphertext_blocks]
    return b"".join(plaintext_blocks)

class DH_Alice(BaseRequestHandler):
    """Alice the DH server."""

    def send_data(self, data):
        """Send integer, 'num' is decimal number."""
        self.request.sendall(data)

    def recv_int(self):
        """Receive and convert it to integer."""
        num_str = self.request.recv(8192).decode('utf8')
        return int(num_str, 16)

    def handle(self):
        """DH Alice handler."""
        print("Connection from:", self.client_address)
        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
        g = 2 # the generator of the group (Z/pZ)*

        # generate random exponent x1
        x1 = generate_random(p)
        # calc g^x1 & send (A -> B)
        g_x1 = format(pow(g, x1, p), "x").encode()
        self.send_data(g_x1)
        
        # receive g^x2
        g_x2 = self.recv_int()
        
        # Calc Alice's key NOTE: do not share!!!!
        key_ = pow(g_x2, x1, p)
        key = hashlib.sha256(bytes.fromhex(hex(key_))).digest()
        # Encrypt the message

        msg = SECRET_MSG

        enc = encrypt(bytes(msg), key)
        self.send_data(enc)


if __name__ == '__main__':
    try:
        dh = ThreadingTCPServer(("0.0.0.0", 6004), DH_Alice)
        print("Serving on 0.0.0.0 port 6004 ...")
        dh.serve_forever()
    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting.")
        dh.socket.close()