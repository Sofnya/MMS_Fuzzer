import pyshark
import socket
import binascii
import random
import time
import math
from bitarray import bitarray
from logging import log

def packToBytes(pack):
    return binascii.unhexlify(pack.replace(":", ""))

def flipBit(a, ind):
    b = bitarray(endian="big")
    b.frombytes(a)
    b[ind] ^= 1
    return b.tobytes()

def mutate(el, amount):
    res = el
    targets=[]
    for _ in range(amount):
        cur = random.randint(0, len(el)*8 - 1)
        while cur in targets:
            cur = random.randint(0, len(el)*8 - 1)
        targets.append(cur)

    for ind in targets:
        res = flipBit(res, ind)
    
    return res

filter = "((mms) && (ip.src == 127.0.0.1)) && (tcp.dstport == 102)"
pcap = "testpackets.pcapng"
cap = pyshark.FileCapture(pcap, display_filter="cotp")
handshake1 = packToBytes(cap[0].tcp.payload)
handshake2 = packToBytes(cap[2].tcp.payload)
cap.close()

cap = pyshark.FileCapture(pcap, display_filter=filter)
test = packToBytes(cap[5].tcp.payload)
while True:
    for i in range(1,10000):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", 102))
            s.send(handshake1)
            s.recv(102)
            s.send(handshake2)
            data, addr = s.recvfrom(102)
            s.recv(102)

            pack = mutate(test, random.randint(1,math.floor(math.log(i))))

            s.send(pack)
            s.close()
        except:
            try:
                s.close()
            except:
                pass
            pass