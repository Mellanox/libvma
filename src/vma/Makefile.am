
noinst_LTLIBRARIES = \
	libconfig_parser.la
libconfig_parser_la_SOURCES = \
	util/config_parser.y \
	util/config_scanner.l
libconfig_parser_la_CFLAGS = \
	-Wno-sign-compare

AM_LFLAGS = -Plibvma_yy
AM_YFLAGS = -plibvma_yy -d
LEX_OUTPUT_ROOT=lex.libvma_yy
BUILT_SOURCES = config_parser.h

sysconf_DATA = util/libvma.conf
include_HEADERS = vma_extra.h

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libvma.la
	rm -f $(DESTDIR)$(libdir)/libvma.a
	rm -f $(DESTDIR)$(libdir)/libstate_machine.*
	rm -f $(DESTDIR)$(libdir)/libvlogger.*
	rm -f $(DESTDIR)$(bindir)/state_machine_test
	rm -f $(DESTDIR)$(bindir)/vlogger_test
	echo "$(libdir)" > /etc/ld.so.conf.d/libvma.conf
	/sbin/ldconfig

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libvma.so*

lib_LTLIBRARIES = libvma.la

INCLUDES := \
	-I$(top_builddir) \
	-I$(top_builddir)/src \
	-I$(top_builddir)/src/lwip/src/include \
	-I$(top_builddir)/src/lwip/src/include/ipv4 \
	-I$(top_builddir)/src/lwip/arch \
	-I$(top_builddir)/src/lwip/ \
	-I$(top_builddir)/src/netlink/

if IS_RELEASE_ZERO
libvma_la_LDFLAGS := -no-undefined -version-number @VMA_LIBRARY_MAJOR@:@VMA_LIBRARY_MINOR@:@VMA_LIBRARY_REVISION@ 
else
libvma_la_LDFLAGS := -no-undefined -version-number @VMA_LIBRARY_MAJOR@:@VMA_LIBRARY_MINOR@:@VMA_LIBRARY_REVISION@ -release @VMA_LIBRARY_RELEASE@
endif

libvma_la_LIBADD = \
	-lrt -ldl -lpthread -libverbs -lrdmacm -lnl \
	$(top_builddir)/src/vlogger/libvlogger.la \
	$(top_builddir)/src/state_machine/libstate_machine.la \
	$(top_builddir)/src/lwip/src/liblwip.la \
	libconfig_parser.la
	

libvma_la_SOURCES := \
	dev/ah_cleaner.cpp \
	dev/buffer_pool.cpp \
	dev/cq_mgr.cpp \
	dev/qp_mgr.cpp \
	dev/gro_mgr.cpp \
	dev/ring.cpp \
	dev/ring_allocation_logic.cpp \
	dev/rfs.cpp \
	dev/rfs_uc.cpp \
	dev/rfs_uc_tcp_gro.cpp \
	dev/rfs_mc.cpp \
	dev/ib_ctx_handler.cpp \
	dev/ib_ctx_handler_collection.cpp \
	dev/net_device_val.cpp \
	dev/net_device_entry.cpp \
	dev/net_device_table_mgr.cpp \
	dev/wqe_send_handler.cpp \
	dev/wqe_send_ib_handler.cpp \
	\
	event/delta_timer.cpp \
	event/event_handler_manager.cpp \
	event/vlogger_timer_handler.cpp \
	event/netlink_event.cpp \
	event/route_net_dev_event.cpp\
	\
	iomux/epfd_info.cpp \
	iomux/epoll_wait_call.cpp \
	iomux/io_mux_call.cpp \
	iomux/poll_call.cpp \
	iomux/select_call.cpp \
	\
	proto/ip_frag.cpp \
	proto/flow_tuple.cpp \
	proto/vma_lwip.cpp \
	proto/neighbour.cpp \
	proto/neighbour_table_mgr.cpp \
	proto/L2_address.cpp \
	proto/route_table_mgr.cpp \
	proto/route_entry.cpp \
	proto/route_val.cpp \
	proto/rule_table_mgr.cpp \
	proto/rule_entry.cpp \
	proto/rule_val.cpp \
	proto/dst_entry.cpp \
	proto/dst_entry_udp.cpp \
	proto/dst_entry_udp_mc.cpp \
	proto/dst_entry_tcp.cpp \
	proto/header.cpp \
	proto/arp.cpp \
	proto/igmp_mgr.cpp \
	proto/igmp_handler.cpp \
	\
	sock/sockinfo.cpp \
	sock/sockinfo_udp.cpp \
	sock/sockinfo_tcp.cpp \
	sock/fd_collection.cpp \
	sock/pipeinfo.cpp \
	sock/socket_fd_api.cpp \
	sock/sock-redirect.cpp \
	\
	infra/subject_observer.cpp \
	infra/sender.cpp \
	\
	util/wakeup.cpp \
	util/match.cpp \
	util/utils.cpp \
	util/verbs_extra.cpp \
	util/instrumentation.cpp \
	libvma.c \
	main.cpp \
	../stats/stats_publisher.cpp \
	../stats/stats_printer.cpp \
	\
	netlink/netlink_wrapper.cpp \
	netlink/neigh_info.cpp \
	netlink/link_info.cpp \
	netlink/route_info.cpp 
	
	
libvma_la_DEPENDENCIES = \
	$(top_builddir)/src/vlogger/libvlogger.la \
	$(top_builddir)/src/state_machine/libstate_machine.la \
	$(top_builddir)/src/lwip/src/liblwip.la \
	libconfig_parser.la

