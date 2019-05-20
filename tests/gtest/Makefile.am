noinst_PROGRAMS = gtest

CXXFLAGS = $(GTEST_CXXFLAGS)

gtest_LDADD =

gtest_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/vma \
	-I$(top_srcdir)/tests/gtest

gtest_LDFLAGS  = $(GTEST_LDFLAGS) -no-install
gtest_CXXFLAGS = $(GTEST_CXXFLAGS) -g -O3 -fno-tree-vectorize

gtest_SOURCES = \
	main.cc \
	\
	common/gtest-all.cc \
	common/sys.cc \
	\
	common/base.cc \
	\
	sock/sock_base.cc \
	sock/sock_socket.cc \
	\
	mix/mix_base.cc \
	mix/sg_array.cc \
	mix/mix_list.cc \
	\
	tcp/tcp_base.cc \
	tcp/tcp_bind.cc \
	tcp/tcp_connect.cc \
	tcp/tcp_connect_nb.cc \
	tcp/tcp_event.cc \
	tcp/tcp_send.cc \
	tcp/tcp_sendto.cc \
	\
	udp/udp_base.cc \
	udp/udp_bind.cc \
	udp/udp_send.cc \
	udp/udp_sendto.cc \
	\
	vma/vma_base.cc \
	vma/vma_ring.cc \
	vma/vma_poll.cc \
	vma/vma_sockopt.cc \
	\
	vmad/vmad_base.cc \
	vmad/vmad_bitmap.cc \
	vmad/vmad_hash.cc \
	vmad/vmad_init.cc \
	vmad/vmad_state.cc \
	vmad/vmad_flow.cc

noinst_HEADERS = \
	common/gtest.h \
	common/tap.h \
	common/def.h \
	common/sys.h \
	common/log.h \
	common/cmn.h \
	\
	common/base.h \
	\
	sock/sock_base.h \
	\
	mix/mix_base.h \
	\
	tcp/tcp_base.h \
	\
	udp/udp_base.h \
	\
	vma/vma_base.h


# This workaround allows to compile files located
# at another directory.
# This place resolve make distcheck isue
nodist_gtest_SOURCES = \
	hash.c

CLEANFILES = hash.c

hash.c:
	@echo "#include \"$(top_builddir)/tools/daemon/$@\"" >$@


.PHONY: test gdb valgrind


all-local: gtest


#
# List variables
#
GTEST_FILTER        ?= *
GTEST_EXTRA_ARGS    =
LAUNCHER            = LD_PRELOAD=$(abs_top_builddir)/src/vma/.libs/libvma.so
VALGRIND_EXTRA_ARGS =

GTEST_ARGS = \
	--gtest_filter=$(GTEST_FILTER) \
	$(GTEST_EXTRA_ARGS)

VALGRIND_ARGS = \
	--tool=memcheck \
	--leak-check=full \
	--track-origins=yes \
	--fair-sched=try \
	$(VALGRIND_EXTRA_ARGS)

#
# List of rules
#
libvma:
	$(MAKE) -C $(top_builddir)

help:
	@echo
	@echo "Targets:"
	@echo "  list          : List unit tests."
	@echo "  test          : Run unit tests."
	@echo "  test_gdb      : Run unit tests with GDB."
	@echo "  test_valgrind : Run unit tests with Valgrind."
	@echo
	@echo "Environment variables:"
	@echo "  GTEST_FILTER        : Unit tests filter (\"$(GTEST_FILTER)\")"
	@echo "  GTEST_EXTRA_ARGS    : Additional arguments for gtest (\"$(GTEST_EXTRA_ARGS)\")"
	@echo "  LAUNCHER            : Custom launcher for gtest executable (\"$(LAUNCHER)\")"
	@echo "  VALGRIND_EXTRA_ARGS : Additional arguments for Valgrind (\"$(VALGRIND_EXTRA_ARGS)\")"
	@echo

#
# List unit tests
#
list: gtest
	$(abs_builddir)/gtest --gtest_list_tests $(GTEST_ARGS)

#
# Run unit tests
#
test: libvma gtest
	@rm -f core.*
	env $(LAUNCHER) $(abs_builddir)/gtest $(GTEST_ARGS)

#
# Run unit tests with GDB
#
test_gdb: libvma gtest
	echo -e 'r\ninit-if-undefined $$_exitcode=-1\nif $$_exitcode>=0\n\tq\nend' > .gdbcommands
	env $(LAUNCHER) \
		gdb -x .gdbcommands --args $(GDB_ARGS) \
			$(abs_builddir)/gtest $(GTEST_ARGS)

#
# Run unit tests with valgrind
#
test_valgrind: libvma gtest
	env $(LAUNCHER) LD_LIBRARY_PATH="$(VALGRIND_LIBPATH):${LD_LIBRARY_PATH}" \
	valgrind $(VALGRIND_ARGS) $(abs_builddir)/gtest $(GTEST_ARGS)
