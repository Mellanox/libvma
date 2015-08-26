#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque


BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
s = socket(AF_INET, SOCK_STREAM) # create a TCP socket
s.bind((myHost, myPort)) 
s.listen(BACKLOG) 
d = deque()
while True:
	#time.sleep(2)
	conn, addr = s.accept()
	if len(d) == 100:
		time.sleep(0.001)
		sock=d.pop()
		print "%s: Closing an accepted socket %s..." % (time.strftime("%Y-%m-%d %H:%M:%S"), str(sock))
		sock.close()
	d.append(conn)
