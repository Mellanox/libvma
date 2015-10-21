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

def test_ioctl(sock):
    ifname = 'eth0'
    addr = socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname)
    )[20:24])
    return "ioctl test: %s=%s" % (ifname, addr)

def test_fcntl(sock):
	rv = fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NDELAY)

	lockdata = struct.pack('hhllhh', fcntl.F_WRLCK, 0, 0, 0, 0, 0)
	rv = fcntl.fcntl(sock, fcntl.F_SETLKW, lockdata)
	return "fcntl test: returned with data of len=" + str(len(rv))

if __name__ == "__main__":
    print "testing UDP:"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print test_ioctl(s)
    print test_fcntl(s)

    print "testing TCP:"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print "setsockopt test...";
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print test_ioctl(s)
    print test_fcntl(s)
