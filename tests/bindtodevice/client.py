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
