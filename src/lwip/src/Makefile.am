
noinst_LTLIBRARIES = liblwip.la

LWIPDIR = .
# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
COREFILES=$(LWIPDIR)/core/mem.c $(LWIPDIR)/core/memp.c $(LWIPDIR)/core/netif.c \
        $(LWIPDIR)/core/pbuf.c $(LWIPDIR)/core/stats.c $(LWIPDIR)/core/sys.c \
        $(LWIPDIR)/core/tcp.c $(LWIPDIR)/core/tcp_in.c $(LWIPDIR)/core/raw.c \
        $(LWIPDIR)/core/tcp_out.c $(LWIPDIR)/core/udp.c $(LWIPDIR)/core/init.c \
        $(LWIPDIR)/core/def.c $(LWIPDIR)/core/timers.c \
        $(LWIPDIR)/core/cc/cc.c $(LWIPDIR)/core/cc/cc_lwip.c \
        $(LWIPDIR)/core/cc/cc_cubic.c

CORE4FILES=$(LWIPDIR)/core/ipv4/icmp.c $(LWIPDIR)/core/ipv4/ip.c \
        $(LWIPDIR)/core/ipv4/inet.c $(LWIPDIR)/core/ipv4/ip_addr.c \
        $(LWIPDIR)/core/ipv4/inet_chksum.c $(LWIPDIR)/core/ipv4/ip_frag.c

# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c $(LWIPDIR)/api/api_msg.c $(LWIPDIR)/api/tcpip.c \
        $(LWIPDIR)/api/err.c $(LWIPDIR)/api/sockets.c $(LWIPDIR)/api/netbuf.c $(LWIPDIR)/api/netdb.c

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFFILES=$(LWIPDIR)/netif/etharp.c

CFLAGS=
liblwip_la_CFLAGS = \
	-Wall -g -O3 $(LDFLAGS) -DIPv4 -fPIC \
	-I$(LWIPDIR)/include -I$(LWIPDIR)/include/ipv4 \
        -I$(LWIPDIR) -I. -I$(LWIPDIR)/../arch -I.. 
	

liblwip_la_SOURCES = $(COREFILES) $(CORE4FILES) $(APIFILES) $(NETIFFILES)
