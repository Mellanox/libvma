#!/usr/bin/env python
#
#
#@copyright:
#        Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
#
#        This software is available to you under a choice of one of two
#        licenses.  You may choose to be licensed under the terms of the GNU
#        General Public License (GPL) Version 2, available from the file
#        COPYING in the main directory of this source tree, or the
#        BSD license below:
#
#            Redistribution and use in source and binary forms, with or
#            without modification, are permitted provided that the following
#            conditions are met:
#
#             - Redistributions of source code must retain the above
#               copyright notice, this list of conditions and the following
#               disclaimer.
#
#             - Redistributions in binary form must reproduce the above
#               copyright notice, this list of conditions and the following
#               disclaimer in the documentation and/or other materials
#               provided with the distribution.
#
#        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#        NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
#        BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
#        ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#        CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#        SOFTWARE.
#
#@author: Avner BenHanoch

#@date: 20June2015
#
# This script performs non blocking connect to a given TCP server
# It can serve for checking VMA behaviour with async connect when the server
# is up or down
#
import socket, select, os, time, sys, fcntl, errno

EPOLL_TIMEOUT=-1 # infinity

def is_writeable_timeout( sock ):
	"use poll with zero timeout for checking for timeout on writeable check (otherwise, the socket is either writeable or has errors)"

	poller = select.poll()
	poller.register(sock, select.POLLOUT)
	pevents = poller.poll(0)
	print "- poll returned: %s (is_writeable_timeout=%s)" % (str(pevents), str(len(pevents) == 0))
	return len(pevents) == 0

def 	async_echo_client(argv):
	if (len(argv) <4):
	    print "Incorrect parameter : " + argv[0] + " server-ip server-port msg-for-echo [bind-IP]"
	    sys.exit(-1)

	IP   = argv[1]
	PORT = int(argv[2])
	msg  = argv[3]
	BIND_IP=None
	if (len(argv) > 4): BIND_IP=argv[4]

	sock=None
	sock_fd = 0
	epoll = select.epoll(1) # we only have 1 socket

	counter = 0
	success = False
	while not success:
		if sock == None:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock_fd = sock.fileno()
			sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

			flags = fcntl.fcntl(sock_fd, fcntl.F_GETFL, 0)
			flags = flags|os.O_NONBLOCK
			rv = fcntl.fcntl(sock_fd, fcntl.F_SETFL, flags)

			if (BIND_IP): sock.bind((BIND_IP, 0))

			print "starting async connect..."
			err = sock.connect_ex((IP, PORT))
			if err != errno.EINPROGRESS and err != 0:
				print "error %d"%err
				sys.exit (1)

			#epoll.register(sock_fd, select.EPOLLOUT | select.EPOLLET)
			epoll.register(sock_fd, select.EPOLLOUT )

		print "calling epoll - for getting for connect result"
		eevents = epoll.poll(EPOLL_TIMEOUT)
		print "- epoll returned: %s" % str(eevents)
		if len(eevents) == 0: continue # epoll timeout
		if is_writeable_timeout (sock):
			pass # timeout - not writeable and no errors - call epoll again on same registered socket
		else:
			fd, events = eevents[0]
			if events & (select.EPOLLERR | select.EPOLLHUP): # error on socket close it and restart from begining
				print counter, "connection was NOT established successfully (will retry in 1 second) - Is the server up?"
				counter += 1
				sock.close()
				sock = None
				time.sleep(1)
			else:
				print " **** connection established successfully after %d failures" % counter
				success = True



	print "* sending..."
	sock.send(msg)

	print "* minor sleep before receiving..."
	time.sleep (1)

	print "* receiving..."
	data = sock.recv(1024)
	print ' **** Received:', data

	print "starting disconnect..."
	epoll.close()
	sock.close()
	print "Done..."

def main():
	async_echo_client(sys.argv)

if __name__ == "__main__":
    main()
