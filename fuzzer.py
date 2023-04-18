#!/usr/bin/env python3

from boofuzz import *
from enum import Enum
import pyshark
import binascii
import subprocess
import time
import argparse

class FieldType(Enum):
    TAG = 0
    LENGTH = 1
    VALUE = 2
    TLV = 3

def getBit(byte, ind):
    return (byte >> ind) & 1

def getBits(byte, start, end):
    return (byte >> start) & ((1 << (end-start+1)) - 1)

def parseTLV(block):
    res = []
    cur = 0
    l = len(block)
    
    while cur < l:
        tagLen = 1
        tag = block[cur].to_bytes(1, "big")
        if getBits(tag[-1], 0,4) == 31:
            tagLen += 1
            tag = block[cur:cur + tagLen]
            print(f"Long tag: Len {tagLen} Tag: {tag}")
            while getBit(tag[-1], 7) == 1:
                tagLen += 1
                tag = block[cur:cur + tagLen]
                print(f"Long tag: Len {tagLen} Tag: {tag}")
                
        res.append((FieldType.TAG, tag))
        length = block[cur + tagLen]
        res.append((FieldType.LENGTH, length.to_bytes(1, "big")))
        value = block[cur +tagLen + 1:cur + tagLen + 1+ length]
        cur += length + tagLen + 1
        if getBit(tag[0], 5) == 1: #Is constructed
            res.append((FieldType.TLV, parseTLV(value)))
        else:
            res.append((FieldType.VALUE, value))
        
    return res

def recomposeTLV(TLV):
    res = b""
    for el in TLV:
        if el[0] == FieldType.TAG:
            res += el[1]
        elif el[0] == FieldType.LENGTH:
            res += el[1]
        elif el[0] == FieldType.VALUE:
            res += el[1]
        elif el[0] == FieldType.TLV:
            res += recomposeTLV(el[1])
    return res

nameCount = 0
def setupFuzzTLV(TLV):
    global nameCount
    curCount = nameCount
    children = []
    for t, el in TLV:
        if t == FieldType.TAG:
            children += [Bytes(name="Tag"+str(nameCount), size=len(el), default_value=el, fuzzable=True)]
        elif t == FieldType.LENGTH:
            children += [Size(name="Length"+str(nameCount), block_name="Value"+str(nameCount), length=1, fuzzable=False)]
        elif t == FieldType.VALUE:
            children += [RandomData(name="Value"+str(nameCount), max_length=0xff, min_length = 0, default_value=el)]
            nameCount +=1
        elif t == FieldType.TLV:
            nameCount += 1
            children[-1].block_name = "TLV"+str(nameCount)
            children += [setupFuzzTLV(el)]
    
    res = Block(name="TLV"+str(curCount), children=children)
    return res


def packetToBytes(packet):
    return binascii.unhexlify(packet.replace(":", ""))

def splitMMS(packet):
    dat = packet.tcp.payload_raw[0]
    mms = packet.mms_raw.value
    header = dat[:-len(mms)]
    return (header, mms)

"""
Gets a human readable name for the packet
"""
def getName(packet):
    a = packet.mms.field_names[0].split("_raw")[0]
    if "initiate_Request" in a:
        return "initiate"
    elif "confirmed_Request" in a:
        b = packet.mms.get_field(a)
        return b.confirmedServiceRequest_tree.field_names[0].split("_")[0]
    elif "conclude_Request" in a:
        return "conclude"
    else:
        return "unknown"


handshake1Pack = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\r\xc2\x02\x00\x01\xc1\x02\x00\x01"
handshake2Pack = b'\x03\x00\x00\xbb\x02\xf0\x80\r\xb2\x05\x06\x13\x01\x00\x16\x01\x02\x14\x02\x00\x023\x02\x00\x014\x02\x00\x01\xc1\x9c1\x81\x99\xa0\x03\x80\x01\x01\xa2\x81\x91\x81\x04\x00\x00\x00\x01\x82\x04\x00\x00\x00\x01\xa4#0\x0f\x02\x01\x01\x06\x04R\x01\x00\x010\x04\x06\x02Q\x010\x10\x02\x01\x03\x06\x05(\xca"\x02\x010\x04\x06\x02Q\x01a^0\\\x02\x01\x01\xa0W`U\xa1\x07\x06\x05(\xca"\x02\x03\xa2\x07\x06\x05)\x01\x87g\x01\xa3\x03\x02\x01\x0c\xa6\x06\x06\x04)\x01\x87g\xa7\x03\x02\x01\x0c\xbe/(-\x02\x01\x03\xa0(\xa8&\x80\x03\x00\xfd\xe8\x81\x01\x05\x82\x01\x05\x83\x01\n\xa4\x16\x80\x01\x01\x81\x03\x05\xf1\x00\x82\x0c\x03\xee\x1c\x00\x00\x04\x08\x00\x00y\xef\x18'
pingPack = b"\x03\x00\x00\x1b\x02\xf0\x80\x01\x00\x01\x00\x61\x0e\x30\x0c\x02\x01\x03\xa0\x07\xa0\x05\x02\x01\x1a\x82\x00"

def ping(target, fuzz_data_logger, session, test_case_context=None, *args, **kwargs):
    target.open()
    fuzz_data_logger.log_info("Sending handshake")
    target.send(handshake1Pack)
    target.send(handshake2Pack)
    target.recv()
    fuzz_data_logger.log_info("Pinging")
    target.send(pingPack)
    res = target.recv()
    target.close()
    if(len(res) > 0):
        fuzz_data_logger.log_pass("Ping successful")
    else:
        fuzz_data_logger.log_fail("Ping failed")

"""
Starts the testClient as a subprocess, and intercepts the traffic in a pcap file.
"""
def genTraffic(target, pcapName, interface):
    subprocess.run(f"sudo rm {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run(f"touch {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run(f"sudo chmod o=rw {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Starting Capture")
    capture = subprocess.Popen(["sudo", "tshark", "-i", interface, "-w", pcapName, "-f", f"tcp port {target[1]}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    print("Starting Client")
    subprocess.run(f"./testClient/testClient.out -h {target[0]} -p {target[1]}",stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Stopping Capture")
    time.sleep(0.5)
    subprocess.check_call(f"sudo kill -SIGTERM {capture.pid}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    time.sleep(0.5)
    print("Generated traffic!")

    

def main():
    parser = argparse.ArgumentParser(
        description="A fuzzer for IEC 61850 MMS"
    )
    parser.add_argument("-p", "--pcap", help="The pcap file to use as input, if not specified, a new one will be generated")
    parser.add_argument("-i", "--interface", help="The interface on which to capture traffic", default="lo")
    parser.add_argument("-t", "--target", help="The target to fuzz", default="localhost:102")
    parser.add_argument("--testRun", help="Set to do a test run of the fuzzer without the actual fuzzing step", action="store_false", default=True)
    

    args = parser.parse_args()
    target=args.target.split(":")
    target = (target[0], int(target[1]))
    if args.pcap:
        pcap = args.pcap
        generate = False
    else:
        pcap = "mms.pcapng"
        generate = True
    interface = args.interface
    testRun = not args.testRun

    session = Session(
        target=Target(
        connection=TCPSocketConnection(target[0], target[1])
        ),
        post_test_case_callbacks=[ping]
    )


    if generate:
        genTraffic(target, pcap, interface)


    cap = pyshark.FileCapture(pcap, display_filter="cotp")
    handshake1 = packetToBytes(cap[0].tcp.payload)
    handshake2 = packetToBytes(cap[2].tcp.payload)
    handshake1 = Request("handshake1", children=[Static(name="handshake1", default_value=handshake1)])
    handshake2 = Request("handshake2", children=[Static(name="handshake2", default_value=handshake2)])
    cap.close()

    session.connect(handshake1)
    session.connect(handshake1, handshake2)

    filter = f"(mms) && (tcp.dstport == {target[1]})"
    cap = pyshark.FileCapture(pcap, display_filter=filter, include_raw=True, use_json=True)
    for i, pack in enumerate(cap):
        print(f"Parsing {i}")
        header, mms = splitMMS(pack)
        mms = packetToBytes(mms)
        header = packetToBytes(header)
        funk = setupFuzzTLV(parseTLV(mms))
        head = Static(name="header"+str(i), default_value=header)
        name = getName(pack)
        print(f"Name: {name}[{i}]")
        curReq = Request(f"{name}[{i}]", children=(head, funk))
        session.connect(handshake2, curReq)
        print(f"Success {i}")
    cap.close()
    subprocess.call(f"sudo rm {pcap}", shell=True)

    if not testRun:
        session.fuzz()


if __name__ == "__main__":
    main()