#!/usr/bin/python
#
# Copyright (c) 2015-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import sys
from socket import *
import time
from collections import deque

serverHost = sys.argv[1]
serverPort = int(sys.argv[2]) 
l = []
d = deque()
i = 0
while True:
    time.sleep(0.001)
    sock = socket(AF_INET, SOCK_STREAM)
    sock.setblocking(0)
    sock.connect_ex((serverHost, serverPort)) # connect to server on the port
    #sock.send("Hello world") # send the data
    i += 1
    print "%s: Connecting #%03d..." % (time.strftime("%Y-%m-%d %H:%M:%S"), i)
    if len(d) == 10000: d.pop().close()
    d.append(sock)
