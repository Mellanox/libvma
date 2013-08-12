AM_CFLAGS = -Wall -g#-O3

INCLUDES := -I$(top_builddir)/src

lib_LTLIBRARIES = libvlogger.la
libvlogger_la_LDFLAGS = -static -version-info 1:0:0
libvlogger_la_LIBADD = -lrt
libvlogger_la_SOURCES = vlogger.cpp 
libvlogger_la_DEPENDENCIES = Makefile.am Makefile.in Makefile

bin_PROGRAMS = vlogger_test
vlogger_test_LDADD = libvlogger.la
vlogger_test_SOURCES = main.cpp
