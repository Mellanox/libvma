AM_CPPFLAGS := -I$(top_srcdir)/src ${LIBNL_CFLAGS}

noinst_LTLIBRARIES = libstats.la
libstats_la_LDFLAGS = -static
libstats_la_SOURCES = \
	stats_printer.cpp \
	stats_publisher.cpp \
	stats_data_reader.h

bin_PROGRAMS = vma_stats
vma_stats_LDADD= -lrt \
	libstats.la \
	$(top_builddir)/src/utils/libutils.la \
	$(top_builddir)/src/vlogger/libvlogger.la
vma_stats_SOURCES = stats_reader.cpp
vma_stats_DEPENDENCIES = \
	libstats.la \
	$(top_builddir)/src/vlogger/libvlogger.la
