#!/usr/bin/python
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2015-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
