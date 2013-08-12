#!/usr/bin/python 
# Written By: Avner BenHanoch
# Date: 2011-01-11
#
"""
A client that use ctrl socket for instructing server to sleep than it send
payload on data socket during sleep time.
It compares the time the TCP window was blocked to the requested sleep time
It exit with success iff these times are close enough
In addition, this code tests select on 1 write fd using zero/fixed/infinity timeout
"""
import socket
import select
import time
import sys

HOST = 'alf6'     # The remote host
if len (sys.argv) > 1: HOST = sys.argv[1]
PPORT = 50007     # pyload port
CPORT = PPORT + 1 # ctrl port
SIZE = 1024      # size of send buf
PAYLOAD = '0' * SIZE # payload for send
SECSLEEP = 2      # seconds for requesting server to sleep without recveing data
SECGRACE = 0.2    # seconds GRACE for mismatch in sleep request vs. actual blocking time
WRITEABLE_INDICATION = 100 * 1024 # see block_till_writeable() function below

def print_info (msg):
	print "INFO: ", msg

readfds=[]

# for the sake of this test, socket is defined writeable if we could
# successfully use it for sending 'WRITEABLE_INDICATION' bytes of data
def block_till_writeable (sock):
	sent = 0
	ret = 0
	while sent < WRITEABLE_INDICATION:
		print_info(">>> before select infinity (send-ret=%d, sent=%d)" % (ret, sent))
		readready,writeready,exceptready = select.select(readfds,[sock],[])
		if sock in writeready:
			print_info("<<< after select infinity, sock is writeable (sent=%d)" % sent)
			ret = sock.send(PAYLOAD)
			sent += ret
		else:
			raise Exception("no writeable socket after select infinity")
			#sys.stdin.read(1)
	return sent

#ctrl socket
csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
csocket.connect((HOST, CPORT))

#payload socket
psocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
psocket.connect((HOST, PPORT))
psocket.setblocking(0)

#instruct peer to sleep
print_info("instructing peer to sleep %f seconds and flooding it with data" % SECSLEEP)
csocket.send(str(SECSLEEP)) #ctrl
# flood sleeping peer with data
size = 0

print_info(">>> before select (size=%d)" % size)
readready,writeready,exceptready = select.select(readfds,[psocket],[], 0)
print_info("<<< after  select (size=%d)" % size)
while psocket in writeready:
	ret = psocket.send(PAYLOAD)
	size += ret
	if size > 300*1024:
		raise Exception("socket is always writeable (size=%d)" % size)
	print_info(">>> before select (send-ret=%d, size=%d)" % (ret, size))
	readready,writeready,exceptready = select.select(readfds,[psocket],[], 0)
	print_info("<<< after  select (size=%d)" % size)

#wait till payload socket is ready for write
t1 = time.time()
print_info("---->>> TCP window was closed after sending %d bytes.  Waiting till window is open..." % size )
res = block_till_writeable(psocket)
t2 = time.time()

#check results
blocked = t2 - t1
diff = abs(SECSLEEP - blocked)
print_info ("<<<---- blocked time=%f; requested block=%f" % (blocked, SECSLEEP) )
if SECGRACE >= diff:
	print_info("SUCCESS in test: grace of %f >= diff of %f" % (SECGRACE,diff) )
	ret = 0
else:
	print_info("FAIL in test: grace of %f < diff of %f" % (SECGRACE,diff) )
	ret = 255
print_info ("[total bytes sent = %d]" % (size + res) )

psocket.close()
csocket.close()
sys.exit (ret)