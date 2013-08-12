#!/usr/bin/env python
# Written By: Avner BenHanoch
# Date: 2011-01-11
"""
A recv [without send] server that uses ctrl channel for getting sleep instructions
and avoid recv during sleep time.
This beavior will fastly flood TCP window, thus enabling testing behavior of
peer with TCP window.
In addition, this code tests select on 2 - 4 read fds with timeout
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
readfds = [pserver, cserver]
timeout = 1000

while True:
	print_info ("waiting for traffic; sleeping %d seconds on select..." % timeout)
	readready,writeready,exceptready = select.select(readfds,[],[], timeout)
	####print_info ("--------> select returned %d input fds" % len(readready) )

	for s in readready:
		if s == cserver: # new connection on ctrl server socket
			if csocket:  raise Exception ("payload socket is already connected")
			csocket, address = cserver.accept()
			readfds.append(csocket)
			print_info ("accepted ctrl socket; peer=%s" % str(address))
			
		elif s == pserver: # new connection on payload server socket
			if psocket:  raise Exception ("payload socket is already connected")
			psocket, address = pserver.accept()
			readfds.append(psocket)
			print_info ("accepted payload socket; peer=%s" % str(address))

		elif s == csocket: #data on ctrl socket
			buf = s.recv(SIZE)
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
				csocket.close()
				readfds.remove(csocket)
				csocket = None
				if psocket: timeout = 1 # wait for ordinary close of payload socket
		
		elif s == psocket: #data on payload socket
			buf = s.recv(SIZE)
			if buf:
				size = len(buf)
				print_info ("got data on payload socket; len is: %d" % size)
				totalBytes += size
			else: #EOF
				print_info (" ====> got EOF on payload socket; total bytes received: %d <<=====" % totalBytes)
				totalBytes = 0
				psocket.close()
				readfds.remove(psocket)
				psocket = None
				if csocket: timeout = 1 # wait for ordinary close of ctrl socket

	if not readready: #timeout
		print_info ("select (%d seconds) timeout" % timeout)
		if csocket:
			print_info ("closing ctrl socket")
			csocket.close()
			readfds.remove(csocket)
			csocket = None
		if psocket:
			print_info (" ====> closing payload socket (without EOF); total bytes received: %d <<=====" % totalBytes)
			totalBytes = 0
			psocket.close()
			readfds.remove(psocket)
			psocket = None
		timeout = 1000
				

if pserver: pserver.close()
if cserver: cserver.close()
if psocket: psocket.close()
if csocket: csocket.close()
