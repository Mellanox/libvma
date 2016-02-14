AM_CFLAGS = -Wall -g #-O3

bin_PROGRAMS = nl_test

AM_CPPFLAGS := \
            -I$(top_builddir) -I$(top_srcdir) \
	    -I$(top_builddir)/src -I$(top_srcdir)/src \
	    -I$(top_builddir)/include -I$(top_srcdir)/include ${LIBNL_CFLAGS}

noinst_HEADERS = ../infra/subject_observer.h ../util/lock_wrapper.h 

nl_test_LDADD = -lrt -ldl -lpthread -libverbs -lrdmacm ${LIBNL_LIBS}  \
	$(top_builddir)/src/vlogger/libvlogger.la 

nl_test_SOURCES  =  \
	neigh_info.cpp \
	route_info.cpp \
	link_info.cpp \
	netlink_compatibility.cpp \
	netlink_wrapper.cpp \
	../infra/subject_observer.cpp \
	../event/netlink_event.cpp \
	../../vlogger/vlogger.cpp \
	test_main.cpp \
	link_info.h \
	neigh_info.h \
	netlink_compatibility.h \
	netlink_wrapper.h \
	route_info.h

nl_test_CXXFLAGS = -g

nl_test_DEPENDENCIES = Makefile.am Makefile.in Makefile

