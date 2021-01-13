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
#@author: Avner BenHanoch

#@date: 31Mar2015
#
# This script performs non blocking connect (and disconnect) to a given TCP server
# It can serve for checking [latency] effect of connect/disconnect on other client (sockperf)
# Also it can be used directly with [sockperf] server by adding debug calls to LogDuration in vma code
# (note: most effect is expected by 1st packet from a machine; hence, feel free to decrease num sockets)
#
#
#
import socket, select, os, time, sys
import datetime as dt
NUM_SOCKETS=70
DURATION=10 # seconds

if (len(sys.argv) <3):
    print "In correct parameter : " + sys.argv[0] + " IP_Address port" 
    sys.exit(-1)

sock_map = {}
for x in range(0, NUM_SOCKETS-1):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(0)
    sock_map[sock.fileno()] = sock
    
	
print "starting connect..."
n1=dt.datetime.now()
for sock in  sock_map.itervalues():
    err = sock.connect_ex((sys.argv[1], int(sys.argv[2])))
    if err != 115 and err != 0: 
        print "error %d"%err
        sys.exit (1)
n2=dt.datetime.now()
print "connect loop took ", (n2-n1).microseconds, "usec"

n1=dt.datetime.now()
epoll = select.epoll(NUM_SOCKETS)

for sock_fd in sock_map.iterkeys():
    epoll.register(sock_fd, select.EPOLLOUT | select.EPOLLET)

counter = 0	
while True:
    events = epoll.poll(1)

    for sock_fd, event in events:
        err = sock_map[sock_fd].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            print "error %d"%err
            sys.exit (1)
            
        epoll.unregister(sock_fd)
        counter += 1

    if (counter >= NUM_SOCKETS-1):
        break
n2=dt.datetime.now()
delta=(n2-n1).seconds
print "connection established successfully within %d seconds (num sockets = %d)" % (delta, counter+1)
		
epoll.close()

left = DURATION - delta
print " >> sleeping for %d more seconds..." % left
time.sleep(left)
print "after sleep"

print "starting disconnect..."
n1=dt.datetime.now() 
for sock in sock_map.itervalues():
    sock.close()
n2=dt.datetime.now()
print "disconnect loop took ", (n2-n1).microseconds, "usec"
print "Done..." 
