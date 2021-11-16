AM_CPPFLAGS := -I$(top_srcdir)/src

noinst_LTLIBRARIES = libutils.la
libutils_la_LDFLAGS = -static
libutils_la_LIBADD = -lrt
libutils_la_SOURCES = \
	asm-arm64.h \
	asm-ppc64.h \
	asm-x86.h \
	asm.h \
	atomic.h \
	bullseye.h \
	clock.h \
	lock_wrapper.h \
	rdtsc.h \
	types.h \
	compiler.h
