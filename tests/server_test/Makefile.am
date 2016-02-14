noinst_PROGRAMS = server_perf

AM_CPPFLAGS := \
            -I$(top_builddir)/. \
            -I$(top_builddir)/include

server_perf_LDADD    = -lboost_thread
server_perf_SOURCES  = server.cc client.cc main.cc options.cc vtime.cc
server_perf_CXXFLAGS = -g


