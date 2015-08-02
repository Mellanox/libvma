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
	print "%s: Closing accepted %s..." % (time.strftime("%Y-%m-%d %H:%M:%S"), str(addr))
	if len(d) == 100: 
		time.sleep(0.001)
		d.pop().close()
	d.append(conn)
