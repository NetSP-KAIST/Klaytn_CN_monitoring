import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sha3
import snappy
from rlp import (
    encode,
    decode
)
import data_processing_header as h
from scapy.all import *
import matplotlib.pyplot as plt
import os
from os.path import getsize

def hexlify(binary):
    return binascii.hexlify(binary)

class AES_CTR(object):
    def __init__ (self, key, iv):
        ctr = Counter.new(128, initial_value = iv)
        self.aes = AES.new(key, AES.MODE_CTR, counter = ctr)
    
    def encrypt(self, plain_data):
        return self.aes.encrypt(plain_data)
    
    def decrypt(self, encrypted_data):
        return self.aes.decrypt(encrypted_data)

def readInt24(b):
    return int(b[2]) | int(b[1])<<8 | int(b[0])<<16

#TODO: Modify here#
def export_cn(cn_msg):
    msg = cn_msg.hex()
    if msg == '8b2ee32fb341666a5dfa04c1295c3230d877886a':
        return "cn1"
    elif msg == 'f9f854ee359f24440417107e075423b4904365a0':
        return "cn2"
    elif msg == '8a1ab5d3f9b253c55278913152671b8cc58e1d25':
        return "cn3"
    elif msg == '9e5dee93587d2c166a4c8e763362ca7d3becb845':
        return "cn4"
    elif msg == 'b427c66d3c1c37bab9bba928203ae3813233cc4b':
        return "cn5"
    elif msg == 'a76e416b59cbc5a4babe3bec331f55f093b7996a':
        return "cn6"
    elif msg == '2f1e0e6a1de3db0e67d3fc409efc911748e47e43':
        return "cn7"

def export_msg_type(cn_msg):
    if cn_msg == '':
        return "preprepare"
    elif cn_msg == '01':
        return "prepare"
    elif cn_msg == '02':
        return "commit"
    elif cn_msg == '03':
        return "roundchange"
    elif cn_msg == '04':
        return "msgall"

def node_to_ip(node):
    if node == "cn1":
        return "10.0.0.1"
    elif node == "cn2":
        return "10.0.0.2"
    elif node == "cn3":
        return "10.0.0.3"
    elif node == "cn4":
        return "10.0.0.4"
    elif node == "cn5":
        return "10.0.0.5"
    elif node == "cn6":
        return "10.0.0.6"
    elif node == "cn7":
        return "10.0.0.7"

def ip_to_node(ip):
    if ip == "10.0.0.1":
        return "cn1"
    elif ip == "10.0.0.2":
        return "cn2"
    elif ip == "10.0.0.3":
        return "cn3"
    elif ip == "10.0.0.4":
        return "cn4"
    elif ip == "10.0.0.5":
        return "cn5"
    elif ip == "10.0.0.6":
        return "cn6"
    elif ip == "10.0.0.7":
        return "cn7"

def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value