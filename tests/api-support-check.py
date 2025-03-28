#!/usr/bin/env python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
#@copyright:
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
