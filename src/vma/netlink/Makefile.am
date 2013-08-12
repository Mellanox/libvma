AM_CFLAGS = -Wall -g #-O3

bin_PROGRAMS = nl_test

INCLUDES := -I$(top_builddir) \
	    -I$(top_builddir)/src \
	    -I$(top_builddir)/include 

noinst_HEADERS = ../infra/subject_observer.h ../util/lock_wrapper.h 

nl_test_LDADD = -lrt -ldl -lpthread -libverbs -lrdmacm -lnl \
	$(top_builddir)/src/vlogger/libvlogger.la 

nl_test_SOURCES  =  \
	neigh_info.cpp \
	route_info.cpp \
	link_info.cpp \
	netlink_wrapper.cpp \
	../infra/subject_observer.cpp \
	../event/netlink_event.cpp \
	../../vlogger/vlogger.cpp \
	test_main.cpp

nl_test_CXXFLAGS = -g

nl_test_DEPENDENCIES = Makefile.am Makefile.in Makefile

