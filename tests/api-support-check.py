#!/usr/bin/env python
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
    print "testing TCP:"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print test_ioctl(s)
    print test_fcntl(s)
    print "setsockopt test..."; s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print "getsockopt test..."; s.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print "testing UDP:"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print test_ioctl(s)
    print test_fcntl(s)
    print "setsockopt test..."; s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
    print "getsockopt test..."; s.getsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
