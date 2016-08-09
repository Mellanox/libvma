AM_CFLAGS = -Wall -g -fPIC #-O3
AM_CXXFLAGS = -Wall -g -fPIC #-O3

AM_CPPFLAGS := -I$(top_srcdir)/src

noinst_LTLIBRARIES = libutils.la
libutils_la_LDFLAGS = -static
libutils_la_LIBADD = 
libutils_la_SOURCES = rdtsc.cpp

noinst_PROGRAMS = timetest
timetest_LDADD = libutils.la
timetest_SOURCES = timetest.cpp
