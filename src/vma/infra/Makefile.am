AM_CFLAGS = -Wall -g #-O3

AM_CPPFLAGS := \
	-I$(top_srcdir)/src

noinst_HEADERS = \
	sender.h \
	subject_observer.h \
	cache_subject_observer.h \
	DemoSubject.h \
	DemoCollMgr.h \
	DemoObserver.h

EXTRA_DIST = \
	cache_subject_observer.h \
	main.cpp \
	DemoSubject.cpp \
	DemoCollMgr.cpp \
	DemoObserver.cpp \
	DemoCollMgr.h \
	DemoObserver.h \
	DemoSubject.h

noinst_LTLIBRARIES = libinfra.la
libinfra_la_LDFLAGS = -static
libinfra_la_SOURCES = \
	sender.cpp \
	subject_observer.cpp

# This section is disabled
# (just keep one for future use)
#noinst_PROGRAMS = cache_test

#cache_test_LDADD = \
#	libinfra.la

#cache_test_SOURCES  =  \
#	main.cpp \
#	cache_subject_observer.h \
#	DemoSubject.cpp \
#	DemoCollMgr.cpp \
#	DemoObserver.cpp \
#	DemoCollMgr.h \
#	DemoObserver.h \
#	DemoSubject.h

#cache_test_CXXFLAGS = -g

#cache_test_DEPENDENCIES = \
#	libinfra.la \
#	$(top_builddir)/src/vlogger/libvlogger.la

