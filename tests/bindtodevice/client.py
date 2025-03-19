#!/usr/bin/env python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
#@copyright:
#@author: Alex Rosenbaum

#@date: 18May2016
#
#
#
#
import socket, time, sys

if (len(sys.argv) <3):
    print "In correct parameter : " + sys.argv[0] + " dst_ip_address dst_port src_ifname" 
    sys.exit(-1)


print "UDP target IP:port=<", sys.argv[1], ":", sys.argv[2], ">"
print "ifname:", sys.argv[3]

sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(0)
sock.setsockopt(socket.SOL_SOCKET, 25, sys.argv[3]+'\0') # SO_BINDTODEVICE
sock.sendto("HELLO WORLD", (sys.argv[1], int(sys.argv[2])))
time.sleep(1)
sock.close()
