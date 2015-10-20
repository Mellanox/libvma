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

# example for usage:
# LD_PRELOAD=libvma.so VMA_EXCEPTION_HANDLING=1 ./tests/api-support-check.py
#
import socket, sys, fcntl
import struct, os

def get_ip_address(ifname, sock):
    return socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname)
    )[20:24])

def test_fcntl(sock):
	rv = fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NDELAY)

	lockdata = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
	rv = fcntl.fcntl(sock, fcntl.F_SETLKW, lockdata)
	return "fcntl returned with data of len=" + str(len(rv))

if __name__ == "__main__":
    ifname = 'eth0'

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print "test ioctl using UDP: %s=%s" % (ifname, get_ip_address(ifname, s))
    print "test fcntl using UDP: " + test_fcntl(s)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print "test ioctl using TCP: %s=%s" % (ifname, get_ip_address(ifname, s))
    print "test fcntl using TCP: " + test_fcntl(s)
