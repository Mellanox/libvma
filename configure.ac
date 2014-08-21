AC_PREREQ(2.59)

# Update version number here:
#
define([vma_ver_major], 6)
define([vma_ver_minor], 7)
define([vma_ver_revision], 2)
define([vma_ver_release], 0)

AC_INIT(libvma, [vma_ver_major.vma_ver_minor.vma_ver_revision], support@mellanox.com)
AC_DEFINE(VMA_LIBRARY_MAJOR, vma_ver_major, [VMA Major Version])
AC_DEFINE(VMA_LIBRARY_MINOR, vma_ver_minor, [VMA Minor Version])
AC_DEFINE(VMA_LIBRARY_REVISION, vma_ver_revision, [VMA Revision])
AC_DEFINE(VMA_LIBRARY_RELEASE, vma_ver_release, [VMA Release])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR(src)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)

AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_YACC
AM_PROG_LEX

#VMA_LIBRARY_MAJOR-vma_ver_major
VMA_LIBRARY_MAJOR=6
AC_SUBST(VMA_LIBRARY_MAJOR)

#VMA_LIBRARY_MINOR-vma_ver_minor
VMA_LIBRARY_MINOR=7
AC_SUBST(VMA_LIBRARY_MINOR)

#VMA_LIBRARY_REVISION-vma_ver_revision
VMA_LIBRARY_REVISION=2
AC_SUBST(VMA_LIBRARY_REVISION)

#VMA_LIBRARY_RELEASE-vma_ver_release
VMA_LIBRARY_RELEASE=0
AC_SUBST(VMA_LIBRARY_RELEASE)

#SOCKPERF_FLAG-sockperf configure flags
SOCKPERF_FLAG=""
AC_SUBST(SOCKPERF_FLAG)

#LIBALIC_FLAG
LIBALIC_FLAG=""
AC_SUBST(LIBALIC_FLAG)

with_debug_info=yes
with_debug=no

OS=`cat /etc/issue | awk '{ print $3}'`
OFED_VERSION=`ofed_info | grep "^OFED" | cut -d '-' -f 2,3 | cut -d '-' -f 2| sed 's/\.//'`
AC_DEFINE_UNQUOTED(OFED_VERSION, ${OFED_VERSION}, [OFED Version])
AC_SUBST(OFED_VERSION)

AC_ARG_ENABLE(build32,
        AC_HELP_STRING([--enable-build32], [Force build 32 bit]),
        [CFLAGS="-m32 -L/usr/lib";CXXFLAGS="-m32 -L/usr/lib";SOCKPERF_FLAG="--enable-build32 $SOCKPERF_FLAG";LIBALIC_FLAG="--enable-build32 $LIBALIC_FLAG";LWIP_FLAG="-m32";LDFLAGS='-m32 -L/usr/lib';FFLAGS='-m32 -L/usr/lib'],
        [CFLAGS="";CXXFLAGS="";SOCKPERF_FLAG="";LIBALIC_FLAG="";LWIP_FLAG=""])

# gcov support
AC_ARG_ENABLE(gcov, AC_HELP_STRING([--enable-gcov], [turn on code coverage analysis tools]),[CFLAGS+="--coverage -O0";CPPFLAGS+="--coverage -O0";LIBS+="-lgcov";VMA_GCOV=1],[VMA_GCOV=0])

# time_measure support
AC_ARG_ENABLE(time_measure, AC_HELP_STRING([--enable-time_measure], [turn on time measuring]),[CFLAGS+="-DVMA_TIME_MEASURE";CPPFLAGS+="-DVMA_TIME_MEASURE";],[])

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

# debug configuration. Kills CFLAGS/CXXFLAGS
#

AC_ARG_ENABLE(debug,
	AC_HELP_STRING([--enable-debug], [Enable debug mode build]),
	[with_debug=yes])

AC_ARG_ENABLE(debuginfo, AC_HELP_STRING([--disable-debuginfo], [Don't include debug information]),
	[with_debug_info=no;with_debug=no])

if test "x${with_debug}" = "xyes" ; then
	CFLAGS="-g -D_DEBUG $CFLAGS"
	CXXFLAGS="-g -D_DEBUG $CXXFLAGS"
	SOCKPERF_FLAG="--enable-debug $SOCKPERF_FLAG"
	LIBALIC_FLAG="--enable-debug $LIBALIC_FLAG"
else
	CFLAGS="-O3 $CFLAGS"
	CXXFLAGS="-O3 $CXXFLAGS"
	
	if test "x${with_debug_info}" = "xyes" ; then
		CFLAGS="-g $CFLAGS"
        	CXXFLAGS="-g $CXXFLAGS"
	        SOCKPERF_FLAG="--enable-debuginfo $SOCKPERF_FLAG"
        	LIBALIC_FLAG="--enable-debuginfo $LIBALIC_FLAG"
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

AM_CONDITIONAL(IS_RELEASE_ZERO, test $VMA_LIBRARY_RELEASE -eq 0)

if test -e "/etc/infiniband/info" ; then
        ac_cv_ofed_path=`grep prefix /etc/infiniband/info | awk -F "=" '{print $2}'`
else
        ac_cv_ofed_path="/usr/local/ofed"
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

if test "x${GCC}" = "xyes" ; then
        AC_MSG_CHECKING([for gcc version])
        GCC_VER="`${CC} -dumpversion`"
        GCC_MAJOR_VER="`echo ${GCC_VER} | cut -d. -f1`"
        GCC_MINOR_VER="`echo ${GCC_VER} | cut -d. -f2`"
        if test "${GCC_MAJOR_VER}" -ge "4" ; then
                if test "${GCC_MINOR_VER}" -ge "6" ; then
                        WNO_FLAGS="-Wno-format-security -Wno-unused-result -Wno-unused-but-set-variable -Wno-array-bounds"
                        AC_MSG_RESULT([>= 4.6])
                else
                        WNO_FLAGS=""
                        AC_MSG_RESULT([< 4.6])
                fi
        else
                AC_MSG_RESULT([< 4])
        fi
        CFLAGS="-Wall -Wextra -Werror $WNO_FLAGS $CFLAGS"
        CXXFLAGS="-Wall -Wextra -Werror $WNO_FLAGS $CXXFLAGS"
fi

AC_HEADER_STDC

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

AC_MSG_CHECKING([if IBV_QPT_RAW_PACKET is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int qp_type = (int)IBV_QPT_RAW_PACKET;
  return qp_type;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_QPT_RAW_PACKET, 1, [Define to 1 if IBV_QPT_RAW_PACKET is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_WC_WITH_VLAN is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int  vlan_flag = (int)IBV_WC_WITH_VLAN;
  return vlan_flag;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_WC_WITH_VLAN, 1, [Define to 1 if IBV_WC_WITH_VLAN is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_ACCESS_ALLOCATE_MR is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_ACCESS_ALLOCATE_MR;
  return access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_CQ_MODERATION is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_CQ_MODERATION;
  return access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_CQ_MODERATION, 1, [Define to 1 if IBV_EXP_CQ_MODERATION is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_ACCESS_ALLOCATE_MR;
  return access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_IBV_OLD_VERBS_MLX_OFED, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
])

AC_MSG_CHECKING([if IBV_EXP_FLOW_SPEC_IB is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_FLOW_SPEC_IB;
  return access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_FLOW_SPEC_IB, 1, [Define to 1 if IBV_EXP_FLOW_SPEC_IB is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_FLOW_SPEC_IB is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_FLOW_SPEC_IB;
  return access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_FLOW_SPEC_IB, 1, [Define to 1 if IBV_FLOW_SPEC_IB is defined])
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
  return ts;
],
[
  AC_MSG_RESULT([yes])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_MISSING_NET_TSTAMP, 1, [Define to 1 if linux/net_tstamp.h is missing])
])

AC_MSG_CHECKING([if 'struct mmsghdr' for recvmmsg() is defined])
AC_TRY_LINK(
#include <sys/socket.h>
,
[
  struct mmsghdr my_mmsghdr;
  my_mmsghdr.msg_len = 0;
],
[
  AC_MSG_RESULT([yes])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_MISSING_STRUCT_MMSGHDR, 1, [Define to 1 if 'struct mmsghdr' is missing])
])

AC_CHECK_LIB([stdc++], [atoi])
AC_CHECK_LIB([dl], [dlsym])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pthread], [pthread_create])
#AC_CHECK_LIB([rdmacm], [rdma_create_id]) - doing it here requires rdmacm & libibverbs for udp_lat even on Ethernet only machines
#AC_CHECK_LIB([ibverbs], [ibv_cmd_poll_cq])


AC_CONFIG_FILES([
		Makefile
		src/Makefile
		src/vma/Makefile
		src/vma/infra/Makefile
		src/vma/netlink/Makefile
		src/vlogger/Makefile
		src/stats/Makefile
		src/state_machine/Makefile
		src/lwip/Makefile
		src/lwip/src/Makefile
		tests/Makefile
		tests/pps_test/Makefile
		tests/latency_test/Makefile
		tests/throughput_test/Makefile
		])

AC_OUTPUT

