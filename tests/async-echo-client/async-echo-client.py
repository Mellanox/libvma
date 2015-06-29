#!/usr/bin/env python
#
#
#@copyright:
#        Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
#        This software product is a proprietary product of Mellanox Technologies Ltd.
#        (the Company) and all right, title, and interest in and to the software product,
#        including all associated intellectual property rights, are and shall
#        remain exclusively with the Company.
#
#        This software product is governed by the End User License Agreement
#        provided with the software product.
#
#@author: Avner BenHanoch

#@date: 20Jube2015
#
# This script performs non blocking connect to a given TCP server
# It can serve for checking VMA behaviour with async connect when the server
# is up or down
#
import socket, select, os, time, sys, fcntl
import datetime as dt
NUM_SOCKETS=1

if (len(sys.argv) <4):
    print "In correct parameter : " + sys.argv[0] + " server-ip server-port msg-for-echo [bind-IP]"
    sys.exit(-1)

IP   = sys.argv[1]
PORT = int(sys.argv[2])
msg  = sys.argv[3]

BIND_IP=None

if (len(sys.argv) > 4):
    BIND_IP=sys.argv[4]

sock=None
sock_fd = 0
epoll = select.epoll(NUM_SOCKETS)

counter = 0
success = False
while not success:
	sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	sock_fd = sock.fileno()
	#sock.setblocking(0)
	flags = fcntl.fcntl(sock_fd, fcntl.F_GETFL, 0)
	flags = flags|os.O_NONBLOCK
	rv = fcntl.fcntl(sock_fd, fcntl.F_SETFL, flags)
	
#	sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024)
#	sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024)
	if (BIND_IP):
		sock.bind((BIND_IP, 0)) # need local interface IP, not server IP


	print "starting async connect..."
	n1=dt.datetime.now()
	err = sock.connect_ex((IP, PORT))
	if err != 115 and err != 0:
		print "error %d"%err
		sys.exit (1)
	n2=dt.datetime.now()
	print "async connect took ", (n2-n1).microseconds, "usec"
	
#	epoll.register(sock_fd, select.EPOLLOUT | select.EPOLLET)
	epoll.register(sock_fd, select.EPOLLOUT )

	print "calling epoll - for getting for connect result (this is expected to return immediately in case the server is up)"
	n1=dt.datetime.now()
	eevents = epoll.poll(1)
	for fd, event in eevents:
		if fd != sock_fd: 
			print "ERROR: bad fd"
			sys.exit(1)
		print "event %d"%event

		# Commonly used flag setes
		READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
		READ_WRITE = READ_ONLY | select.POLLOUT
		
		# Set up the poller
		poller = select.poll()
		poller.register(sock, READ_WRITE)
		pevents = poller.poll(0)
		
		for fd, flag in pevents:
			if fd != sock_fd: 
				print "ERROR: bad fd"
				sys.exit(1)
			print "all flag are", flag
			print "flag=", flag & select.POLLIN, flag & select.POLLOUT
			print "flag=", flag & select.POLLERR, flag & select.POLLHUP
			if flag & (select.POLLERR | select.POLLHUP):
				print counter, "connection was NOT established successfully (will retry in 1 second) - Is the server up?"
				epoll.unregister(sock_fd)
				sock.close()
				time.sleep(1)
			else:
				epoll.unregister(sock_fd)
				success = True
			
		'''
		err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
		if err != 0:
			print "error %d"%err
			print counter, "connection was NOT established successfully (will retry in 1 second) - Is the server up?"
			epoll.unregister(sock_fd)
			sock.close()
			time.sleep(1)
		else:
			epoll.unregister(sock_fd)
			success = True
		'''

		counter += 1
		break
	pass
	
n2=dt.datetime.now()
delta=(n2-n1).seconds
print "connection established successfully within %d seconds (num sockets = %d)" % (delta, NUM_SOCKETS)

print "sending..."
sock.send(msg)

print "sleeping for 1 second"
time.sleep (1)

print "receiving..."
data = sock.recv(1024)
print '   *****  Received:', data

epoll.close()

print "starting disconnect..."
n1=dt.datetime.now()
sock.close()
n2=dt.datetime.now()
print "disconnect took ", (n2-n1).microseconds, "usec"
print "Done..."
