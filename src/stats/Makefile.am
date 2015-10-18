bin_PROGRAMS = vma_stats

INCLUDES := -I$(top_builddir)/src -I$(top_srcdir)/src

vma_stats_LDADD= -lrt 
vma_stats_SOURCES = stats_reader.cpp stats_printer.cpp stats_data_reader.h
vma_stats_DEPENDENCIES = Makefile.am Makefile.in Makefile
