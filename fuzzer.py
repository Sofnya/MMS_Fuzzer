#!/usr/bin/env python3

from boofuzz import *
from enum import Enum
import pyshark
import binascii
import subprocess
import time
import argparse
import random

fuzzLogger = None
class FieldType(Enum):
    TAG = 0
    CONSTRUCTED_TAG=1
    LENGTH = 2
    VALUE = 3
    TLV = 4

def getBit(byte, ind):
    return (byte >> ind) & 1

def getBits(byte, start, end):
    return (byte >> start) & ((1 << (end-start+1)) - 1)

def setBit(byte, ind):
    return byte | (1 << ind)

def setBits(byte, start, end):
    mask = ((1 << (end-start+1)) - 1) << start
    return (byte | mask)

def clearBit(byte, ind):
    return byte & ~(1 << ind)

class MMSType(Bytes):
    def __init__(
        self,
        name: str = None,
        default_value: bytes = b"",
        size: int = None,
        padding: bytes = b"\x00",
        max_len: int = None,
        isConstructed: bool = False,
        *args,
        **kwargs
    ):
        # We need to know if the type is constructed, so we can set the correct bit in the tag.
        self.isConstructed = isConstructed
        super().__init__(name=name, default_value=default_value, size=size, padding=padding, max_len=max_len, *args, **kwargs)
    
    def encode(self,value,mutation_context):
        value = super().encode(value, mutation_context)
        if value is None:
            value = b""
            return value
        res = [el for el in value]
        # We set the constructed bit in the tag if the type is constructed, as this may have been changed by the fuzzer breaking our message structure.
        if self.isConstructed:
            res[0] = setBit(res[0],5)
        else:
            res[0] = clearBit(res[0],5)
        # If our tag is longer than one we need to mark the first byte as a long tag.
        l = len(value)
        if l > 1:
            res[0] = setBits(res[0], 0,4)
            # And set the highest bit in the remaining bytes(apart from the last) to 1.
            for i in range(1,l-1):
                res[i] = setBit(res[i], 7)
        return bytes(res)

# Short length encoding is the default encoding, where the length is encoded in a single byte.
def shortLengthEncoding(value):
    return value

# Long length encoding uses multiple bytes to encode the length, with the first byte having the highest bit set.
def longLengthEncoding(value, max_length):
    res = [el for el in value]
    # We choose a random amount of bytes in which to encode our length.
    l = random.randint(1, max_length)
    # In the first byte, we set the highest bit to 1, and encode the number of bytes chosen in the remaining 7 bits.
    res[0] = l
    res[0] = setBit(res[0], 7)

    # Afterwards we fit the actual length into the remaining bytes.
    tmp = value[0].to_bytes(l, "big")
    for el in tmp:
        res.append(el)
    fuzzLogger.log_info("Long length: " + str(l) + " Value: " + str(value) + " Encoded: " + str(bytes(res)))
    return bytes(res)

# This class is used to encode the length of a field in the MMS protocol.
class MMSLength(Size):
    def __init__(self, name=None, block_name=None, request=None, offset=0, length=4, endian="<", output_format="binary", inclusive=False, signed=False, math=None, max_length=0, *args, **kwargs):
        if(max_length == 0):
            self.max_length = length
        else:
            self.max_length = max_length
        super().__init__(name, block_name, request, offset, length, endian, output_format, inclusive, signed, math, *args, **kwargs)

    # We override the encode function to use our custom length encoding.    
    def encode(self, value, mutation_context):
        # Randomly choose between short and long length encoding.
        value = super().encode(value, mutation_context)
        if random.random() > 0.001:
            value = shortLengthEncoding(value)
        else:
            value = longLengthEncoding(value, self.max_length)
        return value



def parseTLV(block):
    res = []
    cur = 0
    l = len(block)
    
    while cur < l:
        tagLen = 1
        tag = block[cur].to_bytes(1, "big")
        # We need to handle long tags, marked by setting the last 5 bits of the packet.
        if getBits(tag[-1], 0,4) == 31:
            tagLen += 1
            tag = block[cur:cur + tagLen]
            print(f"Long tag: Len {tagLen} Tag: {tag}")
            while getBit(tag[-1], 7) == 1:
                tagLen += 1
                tag = block[cur:cur + tagLen]
                print(f"Long tag: Len {tagLen} Tag: {tag}")
        
        # This bit marks a constructed type, which we identify separately.
        if getBit(tag[0], 5) == 1:
            res.append((FieldType.CONSTRUCTED_TAG, tag))
        else:       
            res.append((FieldType.TAG, tag))
        

        length = block[cur + tagLen]
        res.append((FieldType.LENGTH, length.to_bytes(1, "big")))
        value = block[cur +tagLen + 1:cur + tagLen + 1+ length]
        cur += length + tagLen + 1

        # If the tag is constructed, we need to recursively parse the value as a TLV.
        if getBit(tag[0], 5) == 1:
            res.append((FieldType.TLV, parseTLV(value)))
        else:
            res.append((FieldType.VALUE, value))
        
    return res

def recomposeTLV(TLV):
    res = b""
    for el in TLV:
        if el[0] == FieldType.TAG:
            res += el[1]
        elif el[0] == FieldType.CONSTRUCTED_TAG:
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
    # Values in our tree are always triples of (type, value, name)
    for t, el in TLV:
        # Tags are fuzzed by our custom MMSType class, here we need to set the isConstructed flag appropriately.
        if t == FieldType.TAG:
            children += [MMSType(name="Tag"+str(nameCount), max_len=3, size=len(el), default_value=el, fuzzable=True)]
        elif t == FieldType.CONSTRUCTED_TAG:
            children += [MMSType(name="Tag"+str(nameCount), max_len=3, size=len(el), default_value=el, fuzzable=True, isConstructed=True)]

        # Length fields are fuzzed by our custom MMSLength class which extends the boofuzz Size class.
        elif t == FieldType.LENGTH:
            children += [MMSLength(name="Length"+str(nameCount), block_name="Value"+str(nameCount), length=1, max_length=126, fuzzable=False)]
        
        # Base Value fields are fuzzed as bytestrings.
        elif t == FieldType.VALUE:
            children += [Bytes(name="Value"+str(nameCount), max_len=0xff, default_value=el, fuzzable=True)]
            nameCount +=1
        # Constructed Value fields are recursively fuzzed as TLVs.
        elif t == FieldType.TLV:
            nameCount += 1
            # We need to update the block name of the last Length field to match our inner TLV block.
            children[-1].block_name = "TLV"+str(nameCount)
            # And then recursively generate our inner blocks.
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
sleepTime = 0.07
def ping(target:Target, fuzz_data_logger, session, test_case_context=None, *args, **kwargs):
    target.close()
    time.sleep(sleepTime)
    target.open()
    fuzz_data_logger.log_info("Sending handshake")
    # The sent packets are hardcoded, as they are not fuzzed.
    target.send(handshake1Pack)
    target.send(handshake2Pack)    
    target.recv()
    fuzz_data_logger.log_info("Pinging")
    # This is actually an MMS identify request.
    target.send(pingPack)
    res = target.recv()
    target.close()
    if(len(res) > 0):
        fuzz_data_logger.log_pass("Ping successful")
    else:
        # A log_fail call will cause the test case to be marked as failing
        fuzz_data_logger.log_fail("Ping failed")

"""
Starts the testClient as a subprocess, and intercepts the traffic in a pcap file.
"""
def genTraffic(target, pcapName, interface, coverage):
    # Clean up the old pcap file, and create a new one.
    subprocess.run(f"rm {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run(f"touch {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run(f"chmod o=rw {pcapName}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Starting Capture")

    # Start the capture in a subprocess.
    capture = subprocess.Popen(["sudo", "tcpdump", "-i", interface, "-w", pcapName, f"tcp port {target[1]}"])#, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    print("Starting Client")
    subprocess.check_call(f"./trafficGen/trafficGen.out -h {target[0]} -p {target[1]} -e {coverage}", shell=True)#stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Stopping Capture")
    time.sleep(0.5)
    # Stop the capture.
    subprocess.check_call(f"sudo kill -SIGTERM {capture.pid}", shell=True)#stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    time.sleep(0.5)
    print("Generated traffic!")

    
def main():
    global sleepTime

    parser = argparse.ArgumentParser(
        description="A fuzzer for IEC 61850 MMS"
    )
    parser.add_argument("-p", "--pcap", help="The pcap file to use as input, if not specified, a new one will be generated")
    parser.add_argument("-i", "--interface", help="The interface on which to capture traffic", default="any")
    parser.add_argument("-t", "--target", help="The target to fuzz", default="localhost:102")
    parser.add_argument("-c", "--coverage", help="Which coverage preset to use (0|1|2|3|4)", default=1)
    parser.add_argument("--testRun", help="Set to do a test run of the fuzzer without the actual fuzzing step", action="store_false", default=True)
    parser.add_argument("-s", "--sleep", help="The time to sleep between packets", default=0.07)

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
    coverage = args.coverage
    sleepTime = args.sleep

    session = Session(
        target=Target(
        connection=TCPSocketConnection(target[0], target[1])
        ),
        post_test_case_callbacks=[ping],
        fuzz_loggers=[],
        restart_sleep_time=0,
        receive_data_after_fuzz = True,
        sleep_time=sleepTime
    )


    if generate:
        genTraffic(target, pcap, interface, coverage)


    cap = pyshark.FileCapture(pcap, display_filter="cotp")
    handshake1Pack = packetToBytes(cap[0].tcp.payload)
    handshake2Pack = packetToBytes(cap[2].tcp.payload)

    handshake1 = Request("handshake1", children=[Static(name="handshake1", default_value=handshake1Pack)])
    handshake2 = Request("handshake2", children=[Static(name="handshake2", default_value=handshake2Pack)])
    cap.close()
    global fuzzLogger
    fuzzLogger = session._fuzz_data_logger

    session.connect(handshake1)
    session.connect(handshake1, handshake2)

    filter = f"(mms) && (tcp.dstport == {target[1]})"
    cap = pyshark.FileCapture(pcap, display_filter=filter, include_raw=True, use_json=True)
    for i, pack in enumerate(cap):
        print(f"Parsing {i}")

        # We split the packet in a static header which we won't fuzz, and the actual MMS payload.
        header, mms = splitMMS(pack)
        mms = packetToBytes(mms)
        header = packetToBytes(header)
        head = Static(name="header"+str(i), default_value=header)

        # Here we dynamically generate a fuzzable block based on our current MMS payload.
        fuzzBlock = setupFuzzTLV(parseTLV(mms))

        # Here we generate a human readable name for the parsed packet based on the kind of request made
        name = getName(pack)
        print(f"Name: {name}[{i}]")

        # Lastly we generate the boofuzz request and connect it to the session.
        curReq = Request(f"{name}[{i}]", children=(head, fuzzBlock))
        session.connect(handshake2, curReq)
        print(f"Success {i}")
    cap.close()
    

    if not testRun:
        print("Starting Fuzzing")
        print("Interface available at http://localhost:26000")
        session.fuzz()


if __name__ == "__main__":
    main()
