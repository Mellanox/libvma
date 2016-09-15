noinst_PROGRAMS = udp_lat tcp_lat

AM_CPPFLAGS := \
            -I$(top_builddir)/. -I$(top_srcdir)/. \
            -I$(top_builddir)/src -I$(top_srcdir)/src

udp_lat_SOURCES = udp_lat.c
udp_lat_LDADD = -lrt

tcp_lat_SOURCES = tcp_lat.cpp
tcp_lat_LDADD = \
	$(top_builddir)/src/utils/libutils.la

udp_lat_DEPENDENCIES = Makefile.am Makefile.in Makefile
tcp_lat_DEPENDENCIES = Makefile.am Makefile.in Makefile


