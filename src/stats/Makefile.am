bin_PROGRAMS = vma_stats

AM_CPPFLAGS := -I$(top_builddir)/src -I$(top_srcdir)/src

vma_stats_LDADD= -lrt  $(top_builddir)/src/vlogger/libvlogger.la
vma_stats_SOURCES = stats_reader.cpp stats_printer.cpp stats_data_reader.h
vma_stats_DEPENDENCIES = Makefile.am Makefile.in Makefile \
			$(top_builddir)/src/vlogger/libvlogger.la
