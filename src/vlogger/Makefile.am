AM_CFLAGS = -Wall -g -fPIC#-O3
AM_CXXFLAGS = -Wall -g -fPIC#-O3

AM_CPPFLAGS := -I$(top_builddir)/src -I$(top_srcdir)/src

lib_LTLIBRARIES = libvlogger.la
libvlogger_la_LDFLAGS = -static -version-info 1:0:0
libvlogger_la_LIBADD = -lrt
libvlogger_la_SOURCES = vlogger.cpp vlogger.h
libvlogger_la_DEPENDENCIES = Makefile.am Makefile.in Makefile

bin_PROGRAMS = vlogger_test
vlogger_test_LDADD = libvlogger.la
vlogger_test_SOURCES = main.cpp
