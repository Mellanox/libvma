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
#@author: Alex Rosenbaum

#@date: 20160520
#
#
import socket, select, os, time, sys, fcntl, errno

EPOLL_TIMEOUT=1 # infinity

def echo_server(argv):
	if (len(argv) <4):
	    print "Incorrect parameter : " + argv[0] + " server-ip server-port-lower num-socket packet-count-to-restart"
	    sys.exit(-1)

	# read configuration
	IP = argv[1]
	PORT = int(argv[2])
	SKT_COUNT=100
	PKT_TO_RESTART_COUNT = 100000
	if (len(argv) > 3): 
		SKT_COUNT  = int(argv[3])
		if (len(argv) > 4): 
			PKT_TO_RESTART_COUNT = int(argv[4])

	loops = 10
	while loops > 0:

		# init structures
		sock = None
		sock_fd = 0
		streams = {}
		epoll = select.epoll()

		# create socket and add to epoll()
		counter = 0
		while counter < SKT_COUNT:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			print IP, int(PORT + counter)
			sock.bind((IP, int(PORT + counter)))
			fd = sock.fileno()
			epoll.register(fd, select.EPOLLIN)
			streams[fd] = sock
			counter += 1

		# block on epoll until received expected packets
		counter = 0
		print "expected to process ", PKT_TO_RESTART_COUNT, " ingress packet before leaving loop..."
		while counter < PKT_TO_RESTART_COUNT:
			# print "calling epoll ..."
			eevents = epoll.poll(EPOLL_TIMEOUT)
			if len(eevents) == 0:
				# print "wakeup from epoll (timeout)"
				continue # epoll timeout
			else:
				# check epoll ready events
				# print "wakeup from epoll (rc=", eevents, ")"
				for fd, evt in eevents:
					if evt & select.EPOLLIN: # error on socket close it and restart from begining
						sock = streams[fd]
						data = sock.recv(1500)
						counter += 1
						# print "Rx counter=", counter
				continue
		print "done epoll Rx of ", counter, " packets"

		print "... 4s sleep before continueing..."
		time.sleep (4)
	
		# close before restart session
		print "starting disconnect..."
		for fd in streams:
			sock = streams[fd]
			sock.close()
		print "closed sockets .. 4s sleep before continueing..."
		time.sleep (4)
		epoll.close()
		print "closed epoll .. 4s sleep before continueing..."
		time.sleep (4)

		print "Done...(loop=", loops, ")"
		loops -= 1

		print "... 1s sleep before continueing..."
		time.sleep (1)

		continue

	print "... big sleep before exit..."
	time.sleep (100)

def main():
	echo_server(sys.argv)

if __name__ == "__main__":
    main()
