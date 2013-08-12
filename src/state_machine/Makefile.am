AM_CFLAGS = -Wall -g#-O3

lib_LTLIBRARIES = libstate_machine.la
libstate_machine_la_LDFLAGS = -static
libstate_machine_la_SOURCES = sm_fifo.cpp sm.cpp
libstate_machine_la_DEPENDENCIES = Makefile.am Makefile.in Makefile
INCLUDES := -I$(top_builddir)/src
	

bin_PROGRAMS = state_machine_test
state_machine_test_LDADD = libstate_machine.la $(top_builddir)/src/vlogger/libvlogger.la
state_machine_test_SOURCES = main.cpp
