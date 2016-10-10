AM_CFLAGS = -Wall -g #-O3

AM_CPPFLAGS := \
	-I$(top_srcdir)/src \
	${LIBNL_CFLAGS}

noinst_LTLIBRARIES = libnetlink.la
libnetlink_la_LDFLAGS = -static
libnetlink_la_SOURCES = \
	neigh_info.cpp \
	route_info.cpp \
	link_info.cpp \
	netlink_compatibility.cpp \
	netlink_wrapper.cpp \
	netlink_sock_mgr.cpp \
	netlink_cache_mgr.cpp 
	
EXTRA_DIST = \
	test_main.cpp

# This section is disabled
# (just keep one for future use)
#noinst_PROGRAMS = nl_test

#nl_test_LDADD = -lrt -ldl -lpthread -libverbs -lrdmacm \
#	${LIBNL_LIBS} \
#	libnetlink.la \
#	$(top_builddir)/src/vlogger/libvlogger.la

#nl_test_SOURCES  =  \
#	neigh_info.cpp \
#	route_info.cpp \
#	link_info.cpp \
#	netlink_compatibility.cpp \
#	netlink_wrapper.cpp \
#	../infra/subject_observer.cpp \
#	../event/netlink_event.cpp \
#	test_main.cpp \
#	link_info.h \
#	neigh_info.h \
#	netlink_compatibility.h \
#	netlink_sock_mgr.h \
#	netlink_cache_mgr.h \
#	netlink_wrapper.h \
#	route_info.h\
#	../proto/os_network_data_wrapper.h

#nl_test_CXXFLAGS = -g

#nl_test_DEPENDENCIES = \
#	libnetlink.la \
#	$(top_builddir)/src/vlogger/libvlogger.la
