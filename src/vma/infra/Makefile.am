AM_CFLAGS = -Wall -g #-O3

bin_PROGRAMS = cache_test

AM_CPPFLAGS := \
            -I$(top_builddir)/src -I$(top_srcdir)/src \
            -I$(top_builddir)/. -I$(top_srcdir)/. \
            -I$(top_builddir)/include -I$(top_srcdir)/include

noinst_HEADERS = \
subject_observer.h \
cache_subject_observer.h \
DemoSubject.h \
DemoCollMgr.h \
DemoObserver.h 

EXTRA_DIST = \
cache_subject_observer.h

cache_test_SOURCES  =  \
subject_observer.cpp \
cache_subject_observer.h \
DemoSubject.cpp \
DemoCollMgr.cpp \
DemoObserver.cpp \
../../vlogger/vlogger.cpp \
main.cpp \
DemoCollMgr.h \
DemoObserver.h \
DemoSubject.h

cache_test_CXXFLAGS = -g

cache_test_DEPENDENCIES = Makefile.am Makefile.in Makefile

