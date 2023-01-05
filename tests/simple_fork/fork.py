#!/usr/bin/python
#
# Copyright (c) 2015-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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


#LD_PRELOAD=libvma.so ./fork.py
#VMA_MEM_ALLOC_TYPE=2 LD_PRELOAD=libvma.so ./fork.py
#VMA_MEM_ALLOC_TYPE=2 VMA_LOG_FILE="/tmp/libvma.log.%d" VMA_TRACELEVEL=4 LD_PRELOAD=libvma.so ./fork.py

import os
import socket

def child():
	print 'A new child ',  os.getpid( )
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.close()
	os._exit(0)  

def parent():
	i = 0
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		i = i + 1
		newpid = os.fork()
		if newpid == 0:
			child()
		else:
			pids = (os.getpid(), newpid)
			print "parent: %d, child: %d" % pids
		if i == 5: break
	s.close()

parent()

