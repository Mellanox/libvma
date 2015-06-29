#!/usr/bin/env python

"""
A simple echo server
"""

import socket, sys

if (len(sys.argv) <3):
    print "Incorrect parameter : " + sys.argv[0] + " server-ip server-port"
    sys.exit(-1)


host = sys.argv[1]
port = int(sys.argv[2])

backlog = 5
size = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host,port))
s.listen(backlog)
while 1:
    client, address = s.accept()
    data = client.recv(size)
    if data:
        client.send(data)
    client.close()
