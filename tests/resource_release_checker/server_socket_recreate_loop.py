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
