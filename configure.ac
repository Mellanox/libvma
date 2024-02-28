# Indicate that we require autoconf 2.59 or later. Ths is needed because we
# use some autoconf macros only available in 2.59.
#
AC_PREREQ(2.59)


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 1: Setting product version
dnl===
dnl===-----------------------------------------------------------------------===

# Update version number here:
#
define([prj_ver_major], 9)
define([prj_ver_minor], 8)
define([prj_ver_revision], 60)
define([prj_ver_release], esyscmd([echo ${PRJ_RELEASE:=0}]))


# Initialize autoconf and define the package name, version number and
# email address for reporting bugs.
#
AC_INIT(libvma, [prj_ver_major.prj_ver_minor.prj_ver_revision], support@mellanox.com)

# Definitions will be placed in this file rather than
# in the DEFS variable
#
AC_CONFIG_HEADER([config.h])

PRJ_LIBRARY_MAJOR=prj_ver_major
PRJ_LIBRARY_MINOR=prj_ver_minor
PRJ_LIBRARY_REVISION=prj_ver_revision
PRJ_LIBRARY_RELEASE=prj_ver_release

AC_DEFINE_UNQUOTED(PRJ_LIBRARY_MAJOR, ${PRJ_LIBRARY_MAJOR}, [VMA Major Version])
AC_SUBST(PRJ_LIBRARY_MAJOR)
AC_DEFINE_UNQUOTED(PRJ_LIBRARY_MINOR, ${PRJ_LIBRARY_MINOR}, [VMA Minor Version])
AC_SUBST(PRJ_LIBRARY_MINOR)
AC_DEFINE_UNQUOTED(PRJ_LIBRARY_REVISION, ${PRJ_LIBRARY_REVISION}, [VMA Revision])
AC_SUBST(PRJ_LIBRARY_REVISION)
AC_DEFINE_UNQUOTED(PRJ_LIBRARY_RELEASE, ${PRJ_LIBRARY_RELEASE}, [VMA Release])
AC_SUBST(PRJ_LIBRARY_RELEASE)

GIT_VER=`git describe --long --abbrev=40 --dirty --tags 2> /dev/null || echo ""`
if test -n "$GIT_VER"; then GIT_VER=`echo $GIT_VER | sed -e 's/-dirty/+/' | sed s/.*-g//`; else  GIT_VER=""; fi

AC_DEFINE_UNQUOTED(PRJ_GIT_VERSION, "${GIT_VER}", [VMA Git Version])

dateopt=""
    if test -n "$SOURCE_DATE_EPOCH" ; then
    dateopt="-u -d @$SOURCE_DATE_EPOCH"
fi
AC_SUBST([BUILD_DATE], [$(date $dateopt +'%d %b %Y')])
AC_SUBST([BUILD_TIME], [$(date $dateopt +'%H:%M:%S')])
AC_SUBST([BUILD_DATE_CHANGELOG], [$(date $dateopt +'%a, %d %b %Y %T %z')])

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
m4_include([config/m4/verbs.m4])
m4_include([config/m4/nl.m4])
m4_include([config/m4/prof.m4])
m4_include([config/m4/compiler.m4])

FUNC_CONFIGURE_INIT()


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 3: Checking for programs we need
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Configure build tools"

# Cleanup predefined compilation flags
#
: ${CPPFLAGS=""}
: ${CFLAGS=""}
: ${CXXFLAGS=""}

# Find compiler, libtools, etc
#
LT_INIT([disable-static])
AC_PROG_CC
AC_PROG_CXX
AC_PROG_YACC
AM_PROG_LEX

# Check for pkg-config package
#
AC_CHECK_PROG(
    [have_pkg_config],
    [pkg-config],
    m4_ifdef([PKG_PROG_PKG_CONFIG], yes, no_pkg_m4),
    no_pkg_config)
case "$have_pkg_config" in
    no_pkg_m4)
        AC_MSG_ERROR([
        *** You do not have pkg.m4 properly installed.
        *** aclocal can not find one.
        *** Set the environment variable ACLOCAL="aclocal -I/path/to/pkg.m4"
        ])
        ;;
    no_pkg_config)
        AC_MSG_ERROR([
        *** The pkg-config is required to build the library.
        *** Make sure it is installed or set path to pkg-config.
        ])
        ;;
    *)
        ;;
esac
PKG_PROG_PKG_CONFIG()


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 4: Setting compiler specific options
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Setting compiler specific options"

COMPILER_CAPABILITY_SETUP()

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 5: Checking for project configuration
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Configure project"

# Performance time points support
#
AC_MSG_CHECKING(
    [for time measurement support])
AC_ARG_ENABLE([time_measure],
    AS_HELP_STRING([--enable-time-measure],
        [turn on time measuring]),
    [CPPFLAGS+=" -DVMA_TIME_MEASURE";
     AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])]
)

# Valgrind support
#
AC_ARG_WITH([valgrind],
    AS_HELP_STRING([--with-valgrind],
        [Enable Valgrind annotations (small runtime overhead, default NO)]),
    [],
    [with_valgrind=no]
)

AC_MSG_CHECKING(
    [for valgrind support])
AS_IF([test "x$with_valgrind" == xno],
      [AC_DEFINE([NVALGRIND], 1, [Define to 1 to disable Valgrind annotations.])
       AC_MSG_RESULT([no])
      ],
      [AC_CHECK_HEADER([valgrind/memcheck.h], [],
                       [AC_MSG_ERROR([Valgrind memcheck support requested, but <valgrind/memcheck.h> not found, install valgrind-devel rpm.])])
       if test -d $with_valgrind; then
          CPPFLAGS="$CPPFLAGS -I$with_valgrind/include"
       fi
       AC_MSG_RESULT([yes])
      ]
)

# OFED configuration.
#
AC_MSG_CHECKING([for OFED path])
AC_ARG_WITH(ofed,
    AS_HELP_STRING([--with-ofed], [Path to OFED install]),
    [ac_cv_ofed_path=$withval],
    [if test -e "/etc/infiniband/info" ; then
         ac_cv_ofed_path=`grep prefix /etc/infiniband/info | awk -F "=" '{print $2}'`
     else
         ac_cv_ofed_path="/usr"
     fi])
CPPFLAGS="$CPPFLAGS -I$ac_cv_ofed_path/include"
if test -d "$ac_cv_ofed_path/lib64" ; then
    LDFLAGS="$LDFLAGS -L$ac_cv_ofed_path/lib64"
elif test -d "$ac_cv_ofed_path/lib/$(uname -m)-linux-*" ; then
    LDFLAGS="$LDFLAGS -L$(ls -d $ac_cv_ofed_path/lib/$(uname -m)-linux-*)"
else
    LDFLAGS="$LDFLAGS -L$ac_cv_ofed_path/lib"
fi
AC_MSG_RESULT($ac_cv_ofed_path)

VERBS_CAPABILITY_SETUP()
OPT_VMA_LOGGING()
PROF_IBPROF_SETUP()

# Enable internal performance counters
# Note: uncomment setup to activate this ability
#
#PROF_RDTSC_SETUP()

# Thread locking control
#
AC_ARG_ENABLE([thread-lock],
    AS_HELP_STRING([--enable-thread-lock],
        [Enable thread locking (default=yes)]))
AC_MSG_CHECKING(
    [for thread locking support])
if test "x$enable_thread_lock" = "xno"; then
    if test "x$enable_socketxtreme" = xyes; then
        AC_DEFINE([DEFINED_NO_THREAD_LOCK], 1, [Define to 1 to disable thread locking])
        AC_MSG_RESULT([no])
    else
        AC_MSG_RESULT([yes (socketxtreme is not enabled)])
    fi
else
    AC_MSG_RESULT([yes])
fi

# Enable tcp tx window availability
#
AC_ARG_ENABLE([tcp-tx-wnd-availability],
    AS_HELP_STRING([--enable-tcp-tx-wnd-availability],
        [Enable TCP Tx window availability
         (TCP packets will only be sent if their size (hdr options + data) is less than or equal to the window size.
         Otherwise -1 is returned and errno is set to EAGAIN)  (default=no)]))
AC_MSG_CHECKING(
    [for tcp tx window availability support])
if test "x$enable_tcp_tx_wnd_availability" = "xyes"; then
    AC_DEFINE(DEFINED_TCP_TX_WND_AVAILABILITY, 1, [Define to 1 to enable TCP Tx window availability])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

# Control TSO usage
#
AC_ARG_ENABLE([tso],
    AS_HELP_STRING([--enable-tso],
        [Enable TSO availability (default=no)]))
AC_MSG_CHECKING(
    [for tso support])
if test "x$enable_tso" = xyes -a "x$vma_cv_attribute_ex_OPCODE_TSO" = xyes; then
    AC_DEFINE_UNQUOTED([DEFINED_TSO], [1], [Define to 1 to use TSO])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([for md5 version of VMA statistics is])
STATS_PROTOCOL_VER=`md5sum ${srcdir}/src/vma/util/vma_stats.h | awk '{ print $1}'`
AC_DEFINE_UNQUOTED(STATS_PROTOCOL_VER, "${STATS_PROTOCOL_VER}", [Stats Protocol Version])
AC_SUBST(STATS_PROTOCOL_VER)
AC_MSG_RESULT(${STATS_PROTOCOL_VER})


dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 6: Checking for header files
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for header files"

# Look for Standard headers
#
AC_HEADER_STDC

AC_CHECK_HEADERS([sys/prctl.h sys/inotify.h sys/fanotify.h sys/capability.h])
AC_CHECK_HEADERS([linux/ethtool.h linux/tls.h])

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 7: Checking for libraries
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for libraries"

AC_CHECK_LIB([stdc++], [atoi])
AC_CHECK_LIB([dl], [dlsym])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pthread], [pthread_create])

CHECK_NL_LIB()

dnl===-----------------------------------------------------------------------===
dnl===
dnl=== SECTION 8: Checking for types and structures
dnl===
dnl===-----------------------------------------------------------------------===
show_section_title "Check for functions, types and structures"

# Check fortified glibc functions
#
AC_CHECK_FUNCS(__read_chk __recv_chk __recvfrom_chk __poll_chk __ppoll_chk)

AC_MSG_CHECKING([for SOF_TIMESTAMPING_SOFTWARE support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  #include <linux/net_tstamp.h>
]],
[[
  int ts = (int)SOF_TIMESTAMPING_SOFTWARE;
  ts = ts;
]])],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_MISSING_NET_TSTAMP, 0, [Define to 0 if linux/net_tstamp.h exists])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_MISSING_NET_TSTAMP, 1, [Define to 1 if linux/net_tstamp.h is missing])
])

AC_MSG_CHECKING([for FRA_OIFNAME enum value support])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <linux/fib_rules.h>
]],
[[
  int oif = (int)FRA_OIFNAME;
  oif = oif;
]])],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_FRA_OIFNAME, 1, [Define to 1 if enum value FRA_OIFNAME exists in linux/fib_rules.h])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_FRA_OIFNAME, 0, [Define to 0 if enum value FRA_OIFNAME does not exist in linux/fib_rules.h])
])

AC_CHECK_TYPES([struct mmsghdr],[],[],[#include <sys/socket.h>])

AC_MSG_CHECKING([for 'struct timespec' for recvmmsg() const])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/socket.h>
]],
[[
  const struct timespec ts = {0,0};
  recvmmsg(0,0,0,0,&ts);
]])],
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
		tests/timetest/Makefile
		tests/gtest/Makefile
		tests/pps_test/Makefile
		tests/latency_test/Makefile
		tests/throughput_test/Makefile
		tools/Makefile
		tools/daemon/Makefile
		docs/man/Makefile
		contrib/scripts/vma.init
		contrib/scripts/vma.service
		contrib/scripts/libvma.spec
		debian/changelog
		])

AC_OUTPUT

show_summary_title
