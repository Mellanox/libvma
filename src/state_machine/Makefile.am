AM_CPPFLAGS := -I$(top_srcdir)/src

noinst_LTLIBRARIES = libstate_machine.la
libstate_machine_la_LDFLAGS = -static
libstate_machine_la_SOURCES = \
	sm_fifo.cpp \
	sm.cpp \
	sm_fifo.h \
	sm.h
	

noinst_PROGRAMS = state_machine_test
state_machine_test_LDADD = \
	libstate_machine.la \
	$(top_builddir)/src/utils/libutils.la \
	$(top_builddir)/src/vlogger/libvlogger.la

state_machine_test_SOURCES = main.cpp
	
state_machine_test_DEPENDENCIES = \
	libstate_machine.la \
	$(top_builddir)/src/utils/libutils.la \
	$(top_builddir)/src/vlogger/libvlogger.la
