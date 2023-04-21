#!/usr/bin/env python3

import sqlite3
import socket
import argparse



def main():
    parser = argparse.ArgumentParser(
        description="A replayer for a boofuzz fuzzing session"
    )
    parser.add_argument("-d", "--database", help="The database file to use as input", default=None)
    parser.add_argument("-i", "--index", help="The index of the test case to replay", default=None)
    parser.add_argument("-t", "--target", help="The target to fuzz", default="localhost:102")



    args = parser.parse_args()
    target=args.target.split(":")
    target = (target[0], int(target[1]))
    index = args.index
    database = args.database
    if database is None:
        print("No database specified, exiting")
        exit(1)
    if index is None:
        print("No index specified, exiting")
        exit(1)
    
    con = sqlite3.connect(database)
    cur = con.cursor()
    a = cur.execute(f"SELECT type,data FROM steps WHERE test_case_index = {index}").fetchall()
    con.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(target)
    for i in a:
        if i[0] == "send":
            s.send(i[1])
            print(f"Sent: {i[1]}")
        elif i[0] == "receive":
            rec = s.recv(1024)
            print(f"Received: {rec}")
            if rec != i[1]:
                print(f"Warning, received data does not match expected data:\nExpected: {i[1]}\nReceived: {rec}\n")
    s.close()

if __name__ == "__main__":
    main()