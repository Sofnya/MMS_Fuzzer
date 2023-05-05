#!/bin/python3

import socket
import argparse

"""
Connect to target and send data"""
def main():
    parser=argparse.ArgumentParser(description="A simple tester for a boofuzz fuzzing session")
    parser.add_argument("-t", "--target", help="The target to fuzz", default="localhost")
    parser.add_argument("-p", "--port", help="The port to fuzz", default=102)
    parser.add_argument("-d", "--data", help="The data to send", default="A")
    args = parser.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.target, args.port))
    s.send(args.data)
    print(f"Sent: {args.data}")
    rec = s.recv(1024)
    print(f"Received: {rec}")
    s.close()
