#!/usr/bin/env python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
#@copyright:
#@author: Alex Rosenbaum

#@date: 20160520
#
#
import socket, select, os, time, sys, fcntl, errno

def main():

	argv = sys.argv
	if (len(argv) < 2):
		print "Incorrect parameter : " + argv[0] + " server-ip server-port-lower"
		sys.exit(-1)

	# read configuration
	IP = argv[1]
	PORT = int(argv[2])

	loops = 4
	while loops > 0:
		print "socket create..."
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind((IP, int(PORT)))
		print ".. created ... sleep before continueing..."
		time.sleep (4)
		print "socket closing ..."
		sock.close()
		print ".. closed ... sleep before continueing..."
		time.sleep (4)
		loops -= 1

if __name__ == "__main__":
    main()
