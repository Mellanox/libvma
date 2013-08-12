AM_CFLAGS = -Wall -g #-O3

bin_PROGRAMS = cache_test

INCLUDES := -I$(top_builddir)/src \
            -I$(top_builddir)/. \
            -I$(top_builddir)/include

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
main.cpp

cache_test_CXXFLAGS = -g

cache_test_DEPENDENCIES = Makefile.am Makefile.in Makefile

