bin_PROGRAMS = udp_lat tcp_lat

INCLUDES := -I$(top_builddir)/. \
            -I$(top_builddir)/include

udp_lat_LDADD = -lrt
udp_lat_SOURCES = udp_lat.c

tcp_lat_SOURCES = tcp_lat.cpp

udp_lat_DEPENDENCIES = Makefile.am Makefile.in Makefile
tcp_lat_DEPENDENCIES = Makefile.am Makefile.in Makefile

