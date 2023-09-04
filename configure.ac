AC_PREREQ(2.59)

# Update version number here:
#
define([vma_ver_major], 8)
define([vma_ver_minor], 4)
define([vma_ver_revision], 104)
define([vma_ver_release], 0)

AC_INIT(libvma, [vma_ver_major.vma_ver_minor.vma_ver_revision], support@mellanox.com)
AC_DEFINE(VMA_LIBRARY_MAJOR, vma_ver_major, [VMA Major Version])
AC_DEFINE(VMA_LIBRARY_MINOR, vma_ver_minor, [VMA Minor Version])
AC_DEFINE(VMA_LIBRARY_REVISION, vma_ver_revision, [VMA Revision])
AC_DEFINE(VMA_LIBRARY_RELEASE, vma_ver_release, [VMA Release])

GIT_VER=`git describe --long --abbrev=40 --dirty --tags 2> /dev/null || echo ""`
if test -n "$GIT_VER"; then GIT_VER=`echo $GIT_VER | sed -e 's/-dirty/+/' | sed s/.*-g//`; else  GIT_VER=""; fi

AC_DEFINE_UNQUOTED(VMA_GIT_VERSION, "${GIT_VER}", [VMA Git Version])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR(src)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config/m4)

AM_INIT_AUTOMAKE(foreign [subdir-objects])

AC_CONFIG_HEADER([config.h])

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
VMA_LIBRARY_REVISION=104
AC_SUBST(VMA_LIBRARY_REVISION)

#VMA_LIBRARY_RELEASE-vma_ver_release
VMA_LIBRARY_RELEASE=0
AC_SUBST(VMA_LIBRARY_RELEASE)

#LIBALIC_FLAG
LIBALIC_FLAG=""
AC_SUBST(LIBALIC_FLAG)
AC_SUBST([BUILD_DATE], [$(date +'%b/%d/%Y')])
AC_SUBST([BUILD_TIME], [$(date +'%H:%M:%S')])
AC_SUBST([BUILD_DATE_CHANGELOG], [$(date +'%a, %d %b %Y %T %z')])

m4_include([config/m4/opt.m4])

##########################
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
PKG_PROG_PKG_CONFIG

with_debug_info=yes
with_debug=no

AC_CHECK_HEADERS([sys/prctl.h sys/inotify.h sys/fanotify.h])

AC_CHECK_HEADERS([infiniband/verbs.h], ,
                 [AC_MSG_ERROR([Unable to find the libibverbs-devel header files])])

AC_CHECK_HEADERS([rdma/rdma_cma.h], ,
                 [AC_MSG_ERROR([Unable to find the librdmacm-devel header files])])

#
# Chech if infiniband/mlx5_hw.h can be used
#
AC_CHECK_HEADER([infiniband/mlx5_hw.h],
	[AC_CHECK_MEMBERS([struct mlx5_qp.ctrl_seg, struct mlx5_qp.gen_data],
		[AC_DEFINE([HAVE_INFINIBAND_MLX5_HW_H],1,[infiniband/mlx5_hw.h can be used])],
		[ac_cv_header_infiniband_mlx5_hw_h="no"],
		[[#include <infiniband/mlx5_hw.h>]] )],
	[],[]
)

AC_MSG_CHECKING([md5 version of VMA statistics is])
STATS_PROTOCOL_VER=`md5sum ${srcdir}/src/vma/util/vma_stats.h | awk '{ print $1}'`
AC_DEFINE_UNQUOTED(STATS_PROTOCOL_VER, "${STATS_PROTOCOL_VER}", [Stats Protocol Version])
AC_SUBST(STATS_PROTOCOL_VER)
AC_MSG_RESULT(${STATS_PROTOCOL_VER})


OS=`cat /etc/issue | awk '{ print $3}'`

AC_ARG_ENABLE(build32,
        AC_HELP_STRING([--enable-build32], [Force build 32 bit]),
        [CFLAGS="-m32 -L/usr/lib $CFLAGS";CXXFLAGS="-m32 -L/usr/lib $CXXFLAGS";LIBALIC_FLAG="--enable-build32  $LIBALIC_FLAG";LWIP_FLAG="-m32";LDFLAGS='-m32 -L/usr/lib';FFLAGS='-m32 -L/usr/lib'],
        [CFLAGS="$CFLAGS";CXXFLAGS="$CXXFLAGS";LIBALIC_FLAG="";LWIP_FLAG=""])

# gcov support
AC_ARG_ENABLE(gcov, AC_HELP_STRING([--enable-gcov], [turn on code coverage analysis tools]),[CFLAGS+=" --coverage -O0";CXXFLAGS+=" --coverage -O0";LIBS+=" -lgcov";VMA_GCOV=1],[VMA_GCOV=0])

# time_measure support
AC_ARG_ENABLE(time_measure, AC_HELP_STRING([--enable-time-measure], [turn on time measuring]),[CPPFLAGS+=" -DVMA_TIME_MEASURE";],[])

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
# Enable tcp tx window availability
#
AC_ARG_ENABLE([tcp-tx-wnd-availability],
    AC_HELP_STRING([--enable-tcp-tx-wnd-availability],
                   [Enable TCP Tx window availability (TCP packets will only be sent if their size (hdr options + data) is less than or equal to the window size. Otherwise -1 is returned and errno is set to EAGAIN)]),
    [AC_DEFINE(DEFINED_TCP_TX_WND_AVAILABILITY, 1, [Define to 1 to enable TCP Tx window availability])],
    [])

#
# Experimental Verbs CQ
#
AC_ARG_ENABLE([exp-cq],
    AC_HELP_STRING([--disable-exp-cq],
                   [Disable experimental Verbs CQ (disables UDP RX HW Timestamp, RX CSUM verification offload and Multi Packet RQ)]),
    [enable_exp_cq=no],
    [enable_exp_cq=yes]
)

AS_IF([test "x$enable_exp_cq" == xyes],
        [AC_DEFINE([DEFINED_IBV_EXP_CQ], 1, [Define to 1 if Experimental Verbs CQ was enabled at configure time])]

	AC_MSG_CHECKING([if IBV_EXP_CQ_TIMESTAMP is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_CQ_TIMESTAMP;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_CQ_TIMESTAMP, 1, [Define to 1 if IBV_EXP_CQ_TIMESTAMP is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_VALUES_CLOCK_INFO is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_VALUES_CLOCK_INFO;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_VALUES_CLOCK_INFO, 1, [Define to 1 if IBV_EXP_VALUES_CLOCK_INFO is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_DEVICE_RX_CSUM_L4_PKT is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_DEVICE_RX_CSUM_L4_PKT;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_DEVICE_RX_CSUM_L4_PKT, 1, [Define to 1 if IBV_EXP_DEVICE_RX_CSUM_L4_PKT is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT, 1, [Define to 1 if IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_FLOW_SPEC_ACTION_TAG is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_FLOW_SPEC_ACTION_TAG;
	  return access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_FLOW_TAG, 1, [Define to 1 if IBV_EXP_FLOW_SPEC_ACTION_TAG is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])
)
#
# On Device Memory
#
AC_CHECK_DECL([IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE],
    [AC_DEFINE(HAVE_IBV_DM, 1, [Define to 1 if IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE is defined])],
    [],
    [[#include <infiniband/verbs_exp.h>]])

#
# VMAPOLL
#
AC_ARG_ENABLE(
    [vmapoll],
    AC_HELP_STRING(
        [--enable-vmapoll],
        [Enable alternative API to standard sockets API for receiving packets (default=no)]))
AC_MSG_CHECKING(
    [if vmapoll API is enabled])
if test "x$enable_vmapoll" = xyes; then
    if test "x$ac_cv_header_infiniband_mlx5_hw_h" != xyes; then
        AC_MSG_ERROR([vmapoll mode is not supported with the current installed OFED version])
    fi
    AC_DEFINE([DEFINED_VMAPOLL], 1, [Define to 1 if vmapoll was enabled at configure time])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

#
# Thread locking control
#
AC_ARG_ENABLE(
    [thread-lock],
    AC_HELP_STRING(
        [--enable-thread-lock],
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
	LIBALIC_FLAG="--enable-debug $LIBALIC_FLAG"
else
	CFLAGS="$CFLAGS -O3"
	CXXFLAGS="$CXXFLAGS -O3"
	
	if test "x${with_debug_info}" = "xyes" ; then
		CFLAGS="-g $CFLAGS"
        	CXXFLAGS="-g $CXXFLAGS"
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

#
# RDTSC measurements support
#
# ****** Total VMA RX******** 
# RDTSC_MEASURE_RX_CQE_RECEIVEFROM
#
# ******* Verbs Poll ***********
# RDTSC_MEASURE_RX_VERBS_IDLE_POLL 
# RDTSC_MEASURE_RX_VERBS_READY_POLL
#
# ******* LWIP ***********
# RDTSC_MEASURE_RX_LWIP 
#
# ******* Other RX ***********
# RDTSC_MEASURE_RX_DISPATCH_PACKET 
# RDTSC_MEASURE_RX_AFTER_PROCCESS_BUFFER_TO_RECIVEFROM 
# RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL 
# RDTSC_MEASURE_RX_READY_POLL_TO_LWIP 
# RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM 
#
# ****** Total VMA TX ******** 
# RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND 

# ******* Verbs Post Send ***********
# RDTSC_MEASURE_TX_VERBS_POST_SEND 

# ******* App ***********
# RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
AC_MSG_CHECKING([if rdtsc-rx-cqe-recvfrom is enabled])
AC_ARG_WITH([rdtsc-rx-cqe-recvfrom],
    AC_HELP_STRING([--with-rdtsc-rx-cqe-recvfrom],
                   [Enable rdtsc measurement of rx CQE recvfrom]),
    [],
    [with_rdtsc_rx_cqe_recvfrom=no]
)

AS_IF([test "x$with_rdtsc_rx_cqe_recvfrom" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_CQE_RECEIVEFROM], 1, [Define to 1 to enable rdtsc measurement of rx CQE recvfrom.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)


AC_MSG_CHECKING([if rdtsc-rx-verbs-idle-poll is enabled])
AC_ARG_WITH([rdtsc-rx-verbs-idle-poll],
    AC_HELP_STRING([--with-rdtsc-rx-verbs-idle-poll],
                   [Enable rdtsc measurement of rx verbs idle poll]),
    [],
    [with_rdtsc_rx_verbs_idle_poll=no]
)

AS_IF([test "x$with_rdtsc_rx_verbs_idle_poll" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_VERBS_IDLE_POLL], 1, [Define to 1 to enable rdtsc measurement of rx verbs idle poll.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-verbs-ready-poll is enabled])
AC_ARG_WITH([rdtsc-rx-verbs-ready-poll],
    AC_HELP_STRING([--with-rdtsc-rx-verbs-ready-poll],
                   [Enable rdtsc measurement of rx verbs ready poll]),
    [],
    [with_rdtsc_rx_verbs_ready_poll=no]
)

AS_IF([test "x$with_rdtsc_rx_verbs_ready_poll" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_VERBS_READY_POLL], 1, [Define to 1 to enable rdtsc measurement of rx verbs ready poll.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-lwip is enabled])
AC_ARG_WITH([rdtsc-rx-lwip],
    AC_HELP_STRING([--with-rdtsc-rx-lwip],
                   [Enable rdtsc measurement of rx lwip]),
    [],
    [with_rdtsc_rx_lwip=no]
)

AS_IF([test "x$with_rdtsc_rx_lwip" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_LWIP], 1, [Define to 1 to enable rdtsc measurement of rx lwip.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-dispatch-packet is enabled])
AC_ARG_WITH([rdtsc-rx-dispatch-packet],
    AC_HELP_STRING([--with-rdtsc-rx-dispatch-packet],
                   [Enable rdtsc measurement of rx dispatch packet]),
    [],
    [with_rdtsc_rx_dispatch_packet=no]
)

AS_IF([test "x$with_rdtsc_rx_dispatch_packet" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_DISPATCH_PACKET], 1, [Define to 1 to enable rdtsc measurement of rx dispatch packet.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-after-process-buffer-to-receivefrom is enabled])
AC_ARG_WITH([rdtsc-rx-after-process-buffer-to-receivefrom],
    AC_HELP_STRING([--with-rdtsc-rx-after-process-buffer-to-receivefrom],
                   [Enable rdtsc measurement of rx after process buffer to receivefrom]),
    [],
    [with_rdtsc_rx_after_process_buffer_to_receivefrom=no]
)

AS_IF([test "x$with_rdtsc_rx_after_process_buffer_to_receivefrom" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_AFTER_PROCCESS_BUFFER_TO_RECIVEFROM], 1, [Define to 1 to enable rdtsc measurement of rx after process buffer to receivefrom.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-vma-tcp-idle-poll is enabled])
AC_ARG_WITH([rdtsc-rx-vma-tcp-idle-poll],
    AC_HELP_STRING([--with-rdtsc-rx-vma-tcp-idle-poll],
                   [Enable rdtsc measurement of rx vma tcp idle poll]),
    [],
    [with_rdtsc_rx_vma_tcp_idle_poll=no]
)

AS_IF([test "x$with_rdtsc_rx_vma_tcp_idle_poll" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_VMA_TCP_IDLE_POLL], 1, [Define to 1 to enable rdtsc measurement of rx vma tcp idle poll.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-ready-poll-to-lwip is enabled])
AC_ARG_WITH([rdtsc-rx-ready-poll-to-lwip],
    AC_HELP_STRING([--with-rdtsc-rx-ready-poll-to-lwip],
                   [Enable rdtsc measurement of rx ready poll to lwip]),
    [],
    [with_rdtsc_rx_ready_poll_to_lwip=no]
)

AS_IF([test "x$with_rdtsc_rx_ready_poll_to_lwip" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_READY_POLL_TO_LWIP], 1, [Define to 1 to enable rdtsc measurement of rx ready poll to lwip.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-rx-lwip-to-receivefrom is enabled])
AC_ARG_WITH([rdtsc-rx-lwip-to-receivefrom],
    AC_HELP_STRING([--with-rdtsc-rx-lwip-to-receivefrom],
                   [Enable rdtsc measurement of rx lwip to receivefrom]),
    [],
    [with_rdtsc_rx_lwip_to_receivefrom=no]
)

AS_IF([test "x$with_rdtsc_rx_lwip_to_receivefrom" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM], 1, [Define to 1 to enable rdtsc measurement of rx lwip to receivefrom.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

 
AC_MSG_CHECKING([if rdtsc-tx-sendto-to-after-post-send is enabled])
AC_ARG_WITH([rdtsc-tx-sendto-to-after-post-send],
    AC_HELP_STRING([--with-rdtsc-tx-sendto-to-after-post-send],
                   [Enable rdtsc measurement of tx sendto to after post send]),
    [],
    [with_rdtsc_tx_sendto_to_after_post_send=no]
)

AS_IF([test "x$with_rdtsc_tx_sendto_to_after_post_send" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND], 1, [Define to 1 to enable rdtsc measurement of tx sendto to after port send.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

AC_MSG_CHECKING([if rdtsc-tx-verbs-post-send is enabled])
AC_ARG_WITH([rdtsc-tx-verbs-post-send],
    AC_HELP_STRING([--with-rdtsc-tx-verbs-post-send],
                   [Enable rdtsc measurement of tx verbs post send]),
    [],
    [with_rdtsc_tx_verbs_post_send=no]
)

AS_IF([test "x$with_rdtsc_tx_verbs_post_send" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_TX_VERBS_POST_SEND], 1, [Define to 1 to enable rdtsc measurement of tx verbs post send.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)


AC_MSG_CHECKING([if rdtsc-receivefrom-to-sendto is enabled])
AC_ARG_WITH([rdtsc-receivefrom-to-sendto],
    AC_HELP_STRING([--with-rdtsc-receivefrom-to-sendto],
                   [Enable rdtsc measurement of receivefrom to sendto]),
    [],
    [with_rdtsc_receivefrom_to_sendto=no]
)

AS_IF([test "x$with_rdtsc_receivefrom_to_sendto" == xyes],
	[AC_DEFINE([RDTSC_MEASURE], 1, [Define to 1 to enable rdtsc measurements.])]
	[AC_DEFINE([RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO], 1, [Define to 1 to enable rdtsc measurement of receivefrom to sendto.])]
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])]
)

CFLAGS="-D_GNU_SOURCE -fPIC $CFLAGS -I$ac_cv_ofed_path/include"
CXXFLAGS="-D_GNU_SOURCE -fPIC $CXXFLAGS -I$ac_cv_ofed_path/include"

if test "x${GCC}" = "xyes" ; then
        AC_MSG_CHECKING([for gcc version])
        GCC_VER="`${CC} -dumpversion`"
        GCC_MAJOR_VER="`echo ${GCC_VER} | cut -d. -f1`"
        GCC_MINOR_VER="`echo ${GCC_VER} | cut -d. -f2`"
        if test "${GCC_MAJOR_VER}" -ge "4" ; then
                if test "${GCC_MINOR_VER}" -ge "6" ; then
                        WNO_FLAGS=""
                        AC_MSG_RESULT([>= 4.6])
                else
                        WNO_FLAGS=""
                        AC_MSG_RESULT([< 4.6])
                fi
        else
                AC_MSG_RESULT([< 4])
        fi
        SHARED_FLAGS="-Wall -Wextra -Werror -Wundef -ffunction-sections -fdata-sections -Wsequence-point -pipe -Winit-self -Wmissing-include-dirs"
        CFLAGS="$SHARED_FLAGS $CFLAGS $WNO_FLAGS"
        CXXFLAGS="$SHARED_FLAGS -Wshadow $CXXFLAGS"
fi

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
  qp_type = qp_type;
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
  vlan_flag = vlan_flag;
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
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
])

# Check if MLNX_OFED's experimental CQ moderiation API is supported
# This API allows VMA to implement the CQ manual and automatic interrupt moderation logic
# If it is not supported then VMA code will disable all of it's CQ interrupt moderation logic
AC_MSG_CHECKING([if IBV_EXP_CQ_MODERATION is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_CQ_MODERATION;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_CQ_MODERATION, 1, [Define to 1 if IBV_EXP_CQ_MODERATION is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_WR_NOP is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_WR_NOP;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_WR_NOP, 1, [Define to 1 if IBV_EXP_WR_NOP is defined])
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
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_IBV_OLD_VERBS_MLX_OFED, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
])

AC_MSG_CHECKING([if IBV_DEVICE_RAW_IP_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_DEVICE_RAW_IP_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_DEVICE_RAW_IP_CSUM, 1, [Define to 1 if IBV_DEVICE_RAW_IP_CSUM is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_SEND_IP_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_SEND_IP_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_SEND_IP_CSUM, 1, [Define to 1 if IBV_SEND_IP_CSUM is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN, 1, [Define to 1 if IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_FLOW_SPEC_IB is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_FLOW_SPEC_IB;
  access = access;
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
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_FLOW_SPEC_IB, 1, [Define to 1 if IBV_FLOW_SPEC_IB is defined])
],
[
  AC_MSG_RESULT([no])
])


AC_MSG_CHECKING([if MLX5_ETH_WQE_L3_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/mlx5_hw.h>
,
[
  int access = (int)MLX5_ETH_WQE_L3_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_MLX5_HW_ETH_WQE_HEADER, 1, [Define to 1 if MLX5_ETH_WQE_L3_CSUM is defined])
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

AC_CHECK_DECLS([IBV_EXP_QP_RATE_LIMIT],
	[AC_DEFINE(DEFINED_IBV_EXP_QP_RATE_LIMIT, 1, [Define to 1 if IBV_EXP_QP_RATE_LIMIT defined])],
	[], [[#include <infiniband/mlx5_hw.h>]])

AC_CHECK_LIB([stdc++], [atoi])
AC_CHECK_LIB([dl], [dlsym])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pthread], [pthread_create])

TMP_LDFLAGS=$LDFLAGS
AC_SEARCH_LIBS([rdma_create_id],[rdmacm],
		[LDFLAGS="$LDFLAGS -lrdmacm" VERBS_FLAGS="$VERBS_FLAGS -lrdmacm"],
		[])
AC_CHECK_FUNCS_ONCE([rdma_lib_reset])
AC_CHECK_LIB([ibverbs], [ibv_cmd_poll_cq], [VERBS_FLAGS="$VERBS_FLAGS -libverbs"],
		[])
AC_SUBST([VERBS_FLAGS])

have_mp_rq=yes
AC_CHECK_DECLS([IBV_EXP_DEVICE_ATTR_VLAN_OFFLOADS,
		IBV_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN,
		IBV_EXP_CQ_RX_UDP_PACKET,
		MLX5_CQE_L3_HDR_TYPE_MASK,
		MLX5_CQE_L4_OK,
		MLX5_CQE_L4_HDR_TYPE_UDP],
		[],
		[have_mp_rq=no],
		[[#include <infiniband/verbs_exp.h>]
		 [#include <infiniband/mlx5_hw.h>]])

AC_MSG_CHECKING([multi packet RQ])
AS_IF([test "x$have_mp_rq" == xyes -a "x$enable_exp_cq" == xyes],
	[AC_DEFINE([HAVE_MP_RQ], 1, [MP_RQ QP supported])] [AC_MSG_RESULT([enabled])],
	[AC_MSG_RESULT([disabled])])

LDFLAGS=$TMP_LDFLAGS

# checking for libnl1 or libnl3 in libibverbs
if test -f "$ac_cv_ofed_path/lib64/libibverbs.so" ; then
	libibverbs_file="$ac_cv_ofed_path/lib64/libibverbs.so"
else 
	libibverbs_file="$ac_cv_ofed_path/lib/libibverbs.so"
fi

have_libnl1=no
have_libnl3=no

ldd $libibverbs_file | grep libnl >/dev/null 2>&1
if test $? -eq 0 ; then
	ldd $libibverbs_file | grep -e 'libnl3' -e 'libnl-3' >/dev/null 2>&1
	if test $? -eq 0 ; then
		# libnl3 case
		PKG_CHECK_MODULES([LIBNL3],[libnl-route-3.0],have_libnl3=yes AC_DEFINE([HAVE_LIBNL3], [1], [Use libnl-route-3.0]),[:])
		if test "$have_libnl3" == no; then
			AC_MSG_ERROR([libibverbs is linked with libnl3 while libnl3-devel is not installed. Please install libnl3-devel and try again])	
		fi
		AC_SUBST([LIBNL_LIBS], "$LIBNL3_LIBS")
		AC_SUBST([LIBNL_CFLAGS], "$LIBNL3_CFLAGS")
		AC_SUBST([LIBNLX_DEVEL], "libnl3-devel")
	else
		# libnl1 case
		PKG_CHECK_MODULES([LIBNL1],[libnl-1], have_libnl1=yes AC_DEFINE([HAVE_LIBNL1], [1], [Use libnl-1]), [:]) 
		if test "$have_libnl1" == no; then
			AC_MSG_ERROR([libibverbs is linked with libnl1 while libnl1-devel is not installed. Please install libnl1-devel and try again])	
		fi
		AC_SUBST([LIBNL_LIBS], "$LIBNL1_LIBS")
		AC_SUBST([LIBNL_CFLAGS], "$LIBNL1_CFLAGS")
		AC_SUBST([LIBNLX_DEVEL], "libnl-devel")
	fi
fi

AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl1" = "yes" -o "$have_libnl3" = "yes"])

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

