# Indicate that we require autoconf 2.59 or later. Ths is needed because we
# use some autoconf macros only available in 2.59.
#
AC_PREREQ(2.59)


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 1: Setting product version
dnl===
dnl===-----------------------------------------------------------------------===

# Definitions will be placed in this file rather than
# in the DEFS variable
#
AC_CONFIG_HEADER([config.h])

# Update version number here:
#
define([vma_ver_major], 8)
define([vma_ver_minor], 4)
define([vma_ver_revision], 10)
define([vma_ver_release], 0)


# Initialize autoconf and define the package name, version number and
# email address for reporting bugs.
#
AC_INIT(libvma, [vma_ver_major.vma_ver_minor.vma_ver_revision], support@mellanox.com)

VMA_LIBRARY_MAJOR=8
VMA_LIBRARY_MINOR=3
VMA_LIBRARY_REVISION=5
VMA_LIBRARY_RELEASE=0

AC_DEFINE_UNQUOTED(VMA_LIBRARY_MAJOR, ${VMA_LIBRARY_MAJOR}, [VMA Major Version])
AC_SUBST(VMA_LIBRARY_MAJOR)
AC_DEFINE_UNQUOTED(VMA_LIBRARY_MINOR, ${VMA_LIBRARY_MINOR}, [VMA Minor Version])
AC_SUBST(VMA_LIBRARY_MINOR)
AC_DEFINE_UNQUOTED(VMA_LIBRARY_REVISION, ${VMA_LIBRARY_REVISION}, [VMA Revision])
AC_SUBST(VMA_LIBRARY_REVISION)
AC_DEFINE_UNQUOTED(VMA_LIBRARY_RELEASE, ${VMA_LIBRARY_RELEASE}, [VMA Release])
AC_SUBST(VMA_LIBRARY_RELEASE)

AM_CONDITIONAL(IS_RELEASE_ZERO, test ${VMA_LIBRARY_RELEASE} -eq 0)

GIT_VER=`git describe --long --abbrev=40 --dirty --tags 2> /dev/null || echo ""`
if test -n "$GIT_VER"; then GIT_VER=`echo $GIT_VER | sed -e 's/-dirty/+/' | sed s/.*-g//`; else  GIT_VER=""; fi

AC_DEFINE_UNQUOTED(VMA_GIT_VERSION, "${GIT_VER}", [VMA Git Version])

AC_SUBST([BUILD_DATE], [$(date +'%b/%d/%Y')])
AC_SUBST([BUILD_TIME], [$(date +'%H:%M:%S')])
AC_SUBST([BUILD_DATE_CHANGELOG], [$(date +'%a, %d %b %Y %T %z')])

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 2: Initialization & Setup
dnl===
dnl===-----------------------------------------------------------------------===

# Verify that the source directory is valid.
#
AC_CONFIG_SRCDIR(src)

# Place for the extra autoconf files.
#
AC_CONFIG_AUX_DIR(config/aux)

# Place all our m4 macro into the config subdirectory.
#
AC_CONFIG_MACRO_DIR(config/m4)

# Init automake and libtool
#
AM_INIT_AUTOMAKE(foreign [subdir-objects])

# Set non-verbose make by default
#
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

m4_include([config/m4/func.m4])
m4_include([config/m4/opt.m4])
m4_include([config/m4/pkg.m4])
m4_include([config/m4/verbs.m4])
m4_include([config/m4/prof.m4])

FUNC_CONFIGURE_INIT


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 3: Checking for programs we need
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Configure build tools"

# Find compiler, libtools, etc
#
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_YACC
AM_PROG_LEX

#VMA_LIBRARY_MAJOR-vma_ver_major
VMA_LIBRARY_MAJOR=8
AC_SUBST(VMA_LIBRARY_MAJOR)

#VMA_LIBRARY_MINOR-vma_ver_minor
VMA_LIBRARY_MINOR=4
AC_SUBST(VMA_LIBRARY_MINOR)

#VMA_LIBRARY_REVISION-vma_ver_revision
VMA_LIBRARY_REVISION=10
AC_SUBST(VMA_LIBRARY_REVISION)

#VMA_LIBRARY_RELEASE-vma_ver_release
VMA_LIBRARY_RELEASE=0
AC_SUBST(VMA_LIBRARY_RELEASE)

#LIBALIC_FLAG
LIBALIC_FLAG=""
AC_SUBST(LIBALIC_FLAG)
dateopt=""
if test -n "$SOURCE_DATE_EPOCH" ; then
    dateopt="-u -d @$SOURCE_DATE_EPOCH"
fi
AC_SUBST([BUILD_DATE], [$(date $dateopt +'%b/%d/%y')])
AC_SUBST([BUILD_TIME], [$(date $dateopt +'%H:%M:%S')])
AC_SUBST([BUILD_DATE_CHANGELOG], [$(date $dateopt +'%a, %d %b %Y %T %z')])

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 4: Setting compiler specific options
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Setting compiler specific options"

AC_MSG_CHECKING([for compiler])
case $CC in
    gcc*|g++*)
        AC_MSG_RESULT([gcc])
        ;;
    icc*|icpc*)
        AC_MSG_RESULT([icc])
        ;;
    clang*|clang++*)
        AC_MSG_RESULT([clang])
        CFLAGS="$CFLAGS -Wno-format-security -Wno-self-assign"
        CXXFLAGS="$CXXFLAGS -Wno-overloaded-virtual"
        ;;
    *)
        AC_MSG_RESULT([unknown])
        ;;
esac


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 5: Checking for project configuration
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Configure project"

OPT_VMA_LOGGING
PROF_IBPROF_SETUP
PROF_RDTSC_SETUP
VERBS_CAPABILITY_SETUP

with_debug_info=yes
with_debug=no

AC_MSG_CHECKING([md5 version of VMA statistics is])
STATS_PROTOCOL_VER=`md5sum ${srcdir}/src/vma/util/vma_stats.h | awk '{ print $1}'`
AC_DEFINE_UNQUOTED(STATS_PROTOCOL_VER, "${STATS_PROTOCOL_VER}", [Stats Protocol Version])
AC_SUBST(STATS_PROTOCOL_VER)
AC_MSG_RESULT(${STATS_PROTOCOL_VER})


OS=`cat /etc/issue | awk '{ print $3}'`

AC_ARG_ENABLE([build32],
    AC_HELP_STRING([--enable-build32],
        [Force build 32 bit]),
    [CFLAGS="-m32 -L/usr/lib $CFLAGS"; CXXFLAGS="-m32 -L/usr/lib $CXXFLAGS"; LWIP_FLAG="-m32"; LDFLAGS='-m32 -L/usr/lib'; FFLAGS='-m32 -L/usr/lib'],
    [CFLAGS="$CFLAGS"; CXXFLAGS="$CXXFLAGS"; LWIP_FLAG=""])

# gcov support
AC_ARG_ENABLE([gcov],
    AC_HELP_STRING([--enable-gcov],
        [turn on code coverage analysis tools]),
    [CFLAGS+=" --coverage -O0"; CXXFLAGS+=" --coverage -O0"; LIBS+=" -lgcov";VMA_GCOV=1],
    [VMA_GCOV=0])

# time_measure support
AC_ARG_ENABLE([time_measure],
    AC_HELP_STRING([--enable-time_measure],
        [turn on time measuring]),
    [CPPFLAGS+=" -DVMA_TIME_MEASURE";],[])

#
# Valgrind support
#
AC_ARG_WITH([valgrind],
    AC_HELP_STRING([--with-valgrind],
        [Enable Valgrind annotations (small runtime overhead, default NO)]),
    [],
    [with_valgrind=no]
)

AS_IF([test "x$with_valgrind" == xno],
      [AC_DEFINE([NVALGRIND], 1, [Define to 1 to disable Valgrind annotations.])
      ],
      [AC_CHECK_HEADER([valgrind/memcheck.h], [],
                       [AC_MSG_ERROR([Valgrind memcheck support requested, but <valgrind/memcheck.h> not found, install valgrind-devel rpm.])])
       if test -d $with_valgrind; then
          CPPFLAGS="$CPPFLAGS -I$with_valgrind/include"
       fi
      ]
)

#
# VMAPOLL
#
AC_ARG_ENABLE([vmapoll],
    AC_HELP_STRING([--enable-vmapoll],
        [Enable alternative API to standard sockets API for receiving packets (default=no)]))
AC_MSG_CHECKING(
    [if vmapoll API is enabled])
if test "x$enable_vmapoll" = xyes; then
    AC_CHECK_HEADERS([infiniband/mlx5_hw.h],
        [AC_DEFINE([DEFINED_VMAPOLL], 1, [Define to 1 if vmapoll was enabled at configure time])],
        [AC_MSG_ERROR([vmapoll mode is not supported with the current installed OFED version])])  
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

#
# Thread locking control
#
AC_ARG_ENABLE([thread-lock],
    AC_HELP_STRING([--enable-thread-lock],
        [Enable thread locking (default=yes)]))
AC_MSG_CHECKING(
    [if thread locking is enabled])
if test "x$enable_thread_lock" = "xno"; then
    if test "x$enable_vmapoll" = xyes; then
        AC_DEFINE([DEFINED_NO_THREAD_LOCK], 1, [Define to 1 to disable thread locking])
        AC_MSG_RESULT([no])
    else
        AC_MSG_RESULT([yes (vmapoll is not enabled)])
    fi
else
    AC_MSG_RESULT([yes])
fi

#
# debug configuration.
#
AC_ARG_ENABLE([debug],
	AC_HELP_STRING([--enable-debug],
	    [Enable debug mode build]),
	[with_debug=yes])

AC_ARG_ENABLE([debuginfo],
    AC_HELP_STRING([--disable-debuginfo],
        [Don't include debug information]),
	[with_debug_info=no; with_debug=no])

if test "x${with_debug}" = "xyes" ; then
	CFLAGS="-g -D_DEBUG $CFLAGS"
	CXXFLAGS="-g -D_DEBUG $CXXFLAGS"
else
	CFLAGS="$CFLAGS -O3"
	CXXFLAGS="$CXXFLAGS -O3"
	
	if test "x${with_debug_info}" = "xyes" ; then
		CFLAGS="-g $CFLAGS"
        	CXXFLAGS="-g $CXXFLAGS"
	fi
fi

if test  ${date:-""} != "" ; then
	CFLAGS="-DVMA_DATE_TIME='\"$date-$time\"' $CFLAGS"
	CXXFLAGS="-DVMA_DATE_TIME='\"$date-$time\"' $CXXFLAGS"
fi

if test  ${revision:-0} -ne 0 ; then
	CFLAGS="-DVMA_SVN_REVISION=$revision $CFLAGS"
    	CXXFLAGS="-DVMA_SVN_REVISION=$revision $CXXFLAGS"
fi


if test -e "/etc/infiniband/info" ; then
        ac_cv_ofed_path=`grep prefix /etc/infiniband/info | awk -F "=" '{print $2}'`
else
        ac_cv_ofed_path="/usr"
fi

if test -e "include/voltaire/vma_extra.h" ; then
    	CFLAGS="-DUSING_VMA_EXTRA_API $CFLAGS"
    	CXXFLAGS="-DUSING_VMA_EXTRA_API $CXXFLAGS"
fi

AC_ARG_WITH(ofed,
        AC_HELP_STRING([--with-ofed], [Path to OFED install]),
        [ac_cv_ofed_path=$withval])
if test -d "$ac_cv_ofed_path/lib64" ; then
        LDFLAGS="$LDFLAGS -L$ac_cv_ofed_path/lib64"
else
        LDFLAGS="$LDFLAGS -L$ac_cv_ofed_path/lib"
fi

CFLAGS="-D_GNU_SOURCE -fPIC $CFLAGS -I$ac_cv_ofed_path/include"
CXXFLAGS="-D_GNU_SOURCE -fPIC $CXXFLAGS -I$ac_cv_ofed_path/include"


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 6: Checking for header files
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for header files"

# Look for Standard headers
#
AC_HEADER_STDC

AC_CHECK_HEADERS([infiniband/verbs.h], ,
    [AC_MSG_ERROR([Unable to find the libibverbs-devel header files])])

AC_CHECK_HEADERS([rdma/rdma_cma.h], ,
    [AC_MSG_ERROR([Unable to find the librdmacm-devel header files])])

AC_CHECK_HEADERS([infiniband/mlx5_hw.h])

AC_CHECK_HEADERS([sys/prctl.h sys/inotify.h sys/fanotify.h])


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 7: Checking for libraries
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for libraries"

AC_CHECK_LIB(ibverbs,
    ibv_get_device_list, [],
    AC_MSG_ERROR([ibv_get_device_list() not found.]))

AC_CHECK_LIB(rdmacm,
    rdma_create_id, [],
    AC_MSG_ERROR([rdma_create_id() not found.]))

AC_CHECK_LIB([stdc++], [atoi])
AC_CHECK_LIB([dl], [dlsym])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pthread], [pthread_create])

have_libnl=no
PKG_CHECK_MODULES([LIBNL3],[libnl-route-3.0], have_libnl=yes AC_DEFINE([HAVE_LIBNL3], [1], [Use libnl-route-3.0]), [:])
if test "$have_libnl" = yes; then
	AC_SUBST([LIBNL_LIBS], "$LIBNL3_LIBS")
	AC_SUBST([LIBNL_CFLAGS], "$LIBNL3_CFLAGS")
	AC_SUBST([LIBNLX_DEVEL], "libnl3-devel")
else
	PKG_CHECK_MODULES([LIBNL1],[libnl-1], have_libnl=yes AC_DEFINE([HAVE_LIBNL1], [1], [Use libnl-1]),  AC_MSG_ERROR([libnl3-devel or libnl-devel must be installed in order to build VMA]))
	AC_SUBST([LIBNL_LIBS], "$LIBNL1_LIBS")
	AC_SUBST([LIBNL_CFLAGS], "$LIBNL1_CFLAGS")
	AC_SUBST([LIBNLX_DEVEL], "libnl-devel")
fi

AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl" = "yes"])


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 8: Checking for types and structures
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for functions, types and structures"

# Does this compiler have built-in functions for atomic memory access?
AC_MSG_CHECKING([if gcc supports atomic memory access (__sync_bool_compare_and_swap)])
AC_TRY_LINK(,
[
  int variable = 1;
  return (__sync_bool_compare_and_swap(&variable, 1, 2)
         && __sync_add_and_fetch(&variable, 1)) ? 1 : 0;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(HAVE_BUILTIN_ATOMIC, 1, [Define to 1 if gcc supports __sync_bool_compare_and_swap() a.o.])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if SOF_TIMESTAMPING_SOFTWARE is defined])
AC_TRY_LINK(
#include <linux/net_tstamp.h>
,
[
  int ts = (int)SOF_TIMESTAMPING_SOFTWARE;
  ts = ts;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_MISSING_NET_TSTAMP, 0, [Define to 0 if linux/net_tstamp.h exists])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_MISSING_NET_TSTAMP, 1, [Define to 1 if linux/net_tstamp.h is missing])
])

AC_MSG_CHECKING([if 'FRA_OIFNAME' enum value is defined])
AC_TRY_LINK(
#include <linux/fib_rules.h>
,
[
  int oif = (int)FRA_OIFNAME;
  oif = oif;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_FRA_OIFNAME, 1, [Define to 1 if enum value FRA_OIFNAME exists in linux/fib_rules.h])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_FRA_OIFNAME, 0, [Define to 0 if enum value FRA_OIFNAME does not exist in linux/fib_rules.h])
])

AC_CHECK_TYPES([struct mmsghdr],[],[],[#include <sys/socket.h>])

AC_MSG_CHECKING([if 'struct timespec' for recvmmsg() is const])
AC_TRY_LINK(
#include <sys/socket.h>
,
[
  const struct timespec ts = {0,0};
  recvmmsg(0,0,0,0,&ts);
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(RECVMMSG_WITH_CONST_TIMESPEC, 1, [Define to 1 if 'struct timespec' for recvmmsg() is 'const struct timespec'])
],
[
  AC_MSG_RESULT([no])
])

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 9: Configure makefiles
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Configure makefiles"
AC_CONFIG_FILES([
		Makefile
		src/Makefile
		src/vma/Makefile
		src/vma/infra/Makefile
		src/vma/netlink/Makefile
		src/utils/Makefile
		src/vlogger/Makefile
		src/stats/Makefile
		src/state_machine/Makefile
		tests/Makefile
		tests/gtest/Makefile
		tests/pps_test/Makefile
		tests/latency_test/Makefile
		tests/throughput_test/Makefile
		tools/Makefile
		tools/daemon/Makefile
		contrib/scripts/vma.init
		build/libvma.spec
		debian/changelog
		VMA_VERSION
		])

AC_OUTPUT

show_summary_title
