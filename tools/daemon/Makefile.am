sbin_PROGRAMS = vmad

vmad_LDADD =

vmad_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/vma

vmad_LDFLAGS  = 
vmad_CFLAGS = 

vmad_SOURCES = \
	daemon.c \
	loop.c \
	hash.c \
	store.c \
	flow.c \
	message.c \
	notify.c \
	nl.c \
	tc.c

noinst_HEADERS = \
	daemon.h \
	hash.h \
	bitmap.h \
	nl.h \
	tc.h
