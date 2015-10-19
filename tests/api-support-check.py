#!/usr/bin/env python
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

#@date: 18Oct2015
#
# This script performs ioctl/fcntl/setsockopt tests for verifying VMA coverage and behavior
#
import socket, sys, fcntl


def main():
	if (len(sys.argv) < 2):
	    print "Incorrect Usage : " + sys.argv[0] + " Ofloaded IP"
	    sys.exit(-1)
	BIND_IP   = sys.argv[1]

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((BIND_IP, 0))
	sock_fd = sock.fileno()
	fcntl.ioctl(sock_fd, 12, 8)

if __name__ == "__main__":
    main()
