#!/usr/bin/env python
# Written By: Avner BenHanoch
# Date: 2011-03-08
"""
poll server test program, identical to the select server.py test program 
that uses poll instead of select

can be used with the select client.py test program

NOTE: poll is only supported in python 2.6 and above
"""

import select
import socket
import sys
import time


HOST = ''         # IP for listening on
if len (sys.argv) > 1: HOST = sys.argv[1]
PPORT = 50007     # pyload port
CPORT = PPORT + 1 # ctrl port
SIZE = 8192      # size of recv buf
backlog = 1

def print_info (msg):
	print "INFO: ", msg
 

#server for payload channel 
pserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
pserver.bind((HOST,PPORT))
pserver.listen(backlog)

#server for ctrl channel 
cserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cserver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
cserver.bind((HOST,CPORT))
cserver.listen(backlog)


psocket = None #connected payload socket
csocket = None #connected  ctrl   socket

totalBytes = 0
timeout = 1000000

pollarr = select.poll()
pollarr.register(pserver.fileno(), select.POLLIN)
pollarr.register(cserver.fileno(), select.POLLIN)

while True:
	print_info ("waiting for traffic; sleeping %d milliseconds on poll..." % timeout) #dbg
	events = pollarr.poll(timeout)
	print_info ("--------> poll returned %d input fds" % len(events) ) #dbg
	
	for fileno, event in events:
		if cserver and fileno == cserver.fileno(): # new connection on ctrl server socket
			if csocket:  raise Exception ("payload socket is already connected")
			csocket, address = cserver.accept()
			pollarr.register(csocket.fileno(), select.POLLIN)
			print_info ("accepted ctrl socket; peer=%s" % str(address))
			
		elif pserver and fileno == pserver.fileno(): # new connection on payload server socket
			if psocket:  raise Exception ("payload socket is already connected")
			psocket, address = pserver.accept()
			pollarr.register(psocket.fileno(), select.POLLIN)
			print_info ("accepted payload socket; peer=%s" % str(address))
			
		elif csocket and fileno == csocket.fileno(): #data on ctrl socket
			buf = csocket.recv(SIZE)
			if buf:
				print_info ("got instruction on ctrl socket")
				t = float(buf)
				print_info (">>> going to sleep for %f seconds..." % t)
				t1 = time.time()
				time.sleep(t)
				t2 = time.time()
				print_info ("<<< sleep was finished after %f seconds" % (t2-t1))
			else: #EOF
				print_info ("got EOF on ctrl socket")
				pollarr.unregister(csocket.fileno())
				csocket.close()
				csocket = None
				if psocket: timeout = 1 # wait for ordinary close of payload socket
		
		elif psocket and fileno == psocket.fileno() : #data on payload socket
			buf = psocket.recv(SIZE)
			if buf:
				size = len(buf)
				print_info ("got data on payload socket; len is: %d" % size) #dbg
				totalBytes += size
			else: #EOF
				print_info (" ====> got EOF on payload socket; total bytes received: %d <<=====" % totalBytes)
				totalBytes = 0
				pollarr.unregister(psocket.fileno())
				psocket.close()
				psocket = None
				if csocket: timeout = 1 # wait for ordinary close of ctrl socket
				
	if not events: #timeout
		print_info ("poll (%d seconds) timeout" % timeout)
		if csocket:
			print_info ("closing ctrl socket")
			pollarr.unregister(csocket.fileno())
			csocket.close()
			csocket = None
		if psocket:
			print_info (" ====> closing payload socket (without EOF); total bytes received: %d <<=====" % totalBytes)
			totalBytes = 0
			pollarr.unregister(psocket.fileno())
			psocket.close()
			psocket = None
		timeout = 1000000
				

if pserver: pserver.close()
if cserver: cserver.close()
if psocket: psocket.close()
if csocket: csocket.close()
