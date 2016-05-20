AM_CFLAGS = -Wall -g -fPIC#-O3
AM_CXXFLAGS = -Wall -g -fPIC#-O3

AM_CPPFLAGS := -I$(abs_top_srcdir)/src

noinst_LTLIBRARIES = libvlogger.la
libvlogger_la_LDFLAGS = -static
libvlogger_la_LIBADD = -lrt
libvlogger_la_SOURCES = vlogger.cpp vlogger.h

noinst_PROGRAMS = vlogger_test
vlogger_test_LDADD = libvlogger.la
vlogger_test_SOURCES = main.cpp
