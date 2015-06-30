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

def is_connected( sock ):
	"use poll with zero timeout for checking if socket is writeable"
   
	poller = select.poll()
	poller.register(sock, select.POLLOUT)
	pevents = poller.poll(0)
	print "- poll returned: %s" % str(pevents)
	if len(pevents) == 0: return False
	fd, flag = pevents[0]
	return flag & select.POLLOUT

def main():
	if (len(sys.argv) <4):
	    print "Incorrect parameter : " + sys.argv[0] + " server-ip server-port msg-for-echo [bind-IP]"
	    sys.exit(-1)

	IP   = sys.argv[1]
	PORT = int(sys.argv[2])
	msg  = sys.argv[3]

	BIND_IP=None

	if (len(sys.argv) > 4):
	    BIND_IP=sys.argv[4]

	sock=None
	sock_fd = 0
	epoll = select.epoll(1) # we only have 1 socket

	counter = 0
	success = False
	while not success:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_fd = sock.fileno()
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

		flags = fcntl.fcntl(sock_fd, fcntl.F_GETFL, 0)
		flags = flags|os.O_NONBLOCK
		rv = fcntl.fcntl(sock_fd, fcntl.F_SETFL, flags)

		if (BIND_IP): sock.bind((BIND_IP, 0))

		print "starting async connect..."
		err = sock.connect_ex((IP, PORT))
		if err != 115 and err != 0:
			print "error %d"%err
			sys.exit (1)
		
	#	epoll.register(sock_fd, select.EPOLLOUT | select.EPOLLET)
		epoll.register(sock_fd, select.EPOLLOUT )


		print "calling epoll - for getting for connect result (this is expected to return immediately in case the server is up)"
		eevents = epoll.poll(1)
		print "- epoll returned: %s" % str(eevents)
		if len(eevents) == 0: continue
		fd, event = eevents[0]

		if is_connected( sock ):
			success = True
		else:
			print counter, "connection was NOT established successfully (will retry in 1 second) - Is the server up?"
			sock.close()
			time.sleep(1)
			counter += 1		

	print " **** connection established successfully after %d failures" % counter

	print "* sending..."
	sock.send(msg)

	print "* sleeping for 1 second"
	time.sleep (1)

	print "* receiving..."
	data = sock.recv(1024)
	print ' **** Received:', data

	print "starting disconnect..."
	epoll.close()
	sock.close()
	print "Done..."


if __name__ == "__main__":
    main()
