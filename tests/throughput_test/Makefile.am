bin_PROGRAMS = udp_perf

AM_CPPFLAGS := \
            -I$(top_builddir)/. -I$(top_srcdir)/. \
            -I$(top_builddir)/include -I$(top_srcdir)/include

udp_perf_LDADD = -lrt
udp_perf_SOURCES = bandwidth_test.c
udp_perf_DEPENDENCIES = Makefile.am Makefile.in Makefile


