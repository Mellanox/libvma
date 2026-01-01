#!/usr/bin/env python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
#@copyright:
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
