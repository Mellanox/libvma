#!/usr/bin/env python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
#@copyright:
#@author: Avner BenHanoch

#@date: 05July2015
#
# This script performs blocking connect to a given TCP server
# It can serve for checking VMA behaviour with a blocking connect when the server
# is up or down
#
import socket, select, os, time, sys, fcntl

def is_connected( sock ):
	"use poll with zero timeout for checking if socket is writeable and has no errors"

	poller = select.poll()
	poller.register(sock, select.POLLOUT)
	pevents = poller.poll(0)
	rv = True;
	if len(pevents) == 0: rv = False
	else:
		fd, flag = pevents[0]
		rv = (flag == select.POLLOUT) # we only asked for POLLOUT, verify that we didn't get also errors

	print "- poll returned: %s (SUCCESS=%s)" % (str(pevents), str(rv))
	return rv

def 	syncronized_echo_client(argv):
	if (len(argv) <4):
	    print "Incorrect parameter : " + argv[0] + " server-ip server-port msg-for-echo [bind-IP]"
	    sys.exit(-1)

	IP   = argv[1]
	PORT = int(argv[2])
	msg  = argv[3]

	BIND_IP=None

	if (len(argv) > 4):
	    BIND_IP=argv[4]

	sock=None
	sock_fd = 0

	counter = 0
	success = False
	while not success:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_fd = sock.fileno()
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

		flags = fcntl.fcntl(sock_fd, fcntl.F_GETFL, 0)
		flags = flags & ~os.O_NONBLOCK # set blocking
		rv = fcntl.fcntl(sock_fd, fcntl.F_SETFL, flags)

		if (BIND_IP): sock.bind((BIND_IP, 0))

		print "starting synchronized connect..."
		err = sock.connect_ex((IP, PORT))
		if err != 0:
			print "error %d"%err

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
	sock.close()
	print "Done..."

def main():
	syncronized_echo_client(sys.argv) # for functionality test purposes

if __name__ == "__main__":
    main()
