#!/usr/bin/python 
# Written By: Avner BenHanoch
# Date: 2011-01-11
#
"""
An poll client that use ctrl socket for instructing server to sleep than it send
payload on data socket during sleep time.
It compares the time the TCP window was blocked to the requested sleep time
It exit with success iff these times are close enough
In addition, this code tests poll on 1 write fd using zero/fixed/infinity timeout
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

#ctrl socket
csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
csocket.connect((HOST, CPORT))

#print_info ("sleeping 3 second to allow server...") #dbg
#time.sleep(3)

#payload socket
psocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
psocket.connect((HOST, PPORT))
psocket.setblocking(0)

#print_info ("sleeping 3 second to allow server...") #dbg
#time.sleep(3)

#create poll handle
pollarr = select.poll()
pollarr.register(psocket.fileno(), select.POLLOUT)


# for the sake of this test, socket is defined writeable if we could
# successfully use it for sending 'WRITEABLE_INDICATION' bytes of data
def block_till_writeable (sock):
	sent = 0
	ret = 0
	while sent < WRITEABLE_INDICATION:
		print_info(">>> before poll infinity (send-ret=%d, sent=%d)" % (ret, sent))
		events = pollarr.poll()
		if sock and sock.fileno() in dict(events).keys() and dict(events)[sock.fileno()] & select.POLLOUT:
			print_info("<<< after poll infinity, sock is writeable (sent=%d)" % sent)
			ret = sock.send(PAYLOAD)
			sent += ret
		else:
			print events
			raise Exception("no writeable socket after poll infinity")
	return sent


#instruct peer to sleep
print_info("instructing peer to sleep %f seconds and flooding it with data" % SECSLEEP)
csocket.send(str(SECSLEEP)) #ctrl
# flood sleeping peer with data
size = 0

print_info(">>> before poll (size=%d)" % size)
events = pollarr.poll(0)
print_info("<<< after  poll (size=%d)" % size)
while psocket.fileno() in dict(events).keys():
	ret = psocket.send(PAYLOAD)
	size += ret
	if size > 300*1024:
		raise Exception("socket is always writeable (size=%d)" % size)
	print_info(">>> before poll (send-ret=%d, size=%d)" % (ret, size))
	events = pollarr.poll(0)
	print_info("<<< after  poll (size=%d)" % size)

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

pollarr.unregister(psocket.fileno())
psocket.close()
csocket.close()
sys.exit (ret)
