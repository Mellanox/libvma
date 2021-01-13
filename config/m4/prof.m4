# prof.m4 - Profiling, instrumentation
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2021. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# libibprof profiling support
#
AC_DEFUN([PROF_IBPROF_SETUP],
[
AC_ARG_WITH([ibprof],
    AS_HELP_STRING([--with-ibprof],
                   [Search ibprof location (default NO)]),
    [],
    [with_ibprof=no]
)

AS_IF([test "x$with_ibprof" == xno],
    [],
    [AC_CHECK_HEADER(
        [$with_ibprof/include/ibprof_api.h],
        [
         CFLAGS="$CFLAGS -DVMA_TIME_IBPROF"
         CXXFLAGS="$CXXFLAGS -DVMA_TIME_IBPROF"
         CPPFLAGS="$CPPFLAGS -I$with_ibprof/include"
         if test -d "$with_ibprof/lib64"; then
             LDFLAGS="$LDFLAGS -L$with_ibprof/lib64 -Wl,--rpath,$with_ibprof/lib64"
         else
             LDFLAGS="$LDFLAGS -L$with_ibprof/lib -Wl,--rpath,$with_ibprof/lib"
         fi
         AC_SUBST([LIBIBPROF_LIBS], "-libprof")
        ],
        [AC_MSG_ERROR([ibprof support requested, but <$with_ibprof/include/ibprof_api.h> not found.])])
])
])

##########################
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
#
AC_DEFUN([PROF_RDTSC_SETUP],
[
AC_MSG_CHECKING([if rdtsc-rx-cqe-recvfrom is enabled])
AC_ARG_WITH([rdtsc-rx-cqe-recvfrom],
    AS_HELP_STRING([--with-rdtsc-rx-cqe-recvfrom],
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
    AS_HELP_STRING([--with-rdtsc-rx-verbs-idle-poll],
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
    AS_HELP_STRING([--with-rdtsc-rx-verbs-ready-poll],
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
    AS_HELP_STRING([--with-rdtsc-rx-lwip],
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
    AS_HELP_STRING([--with-rdtsc-rx-dispatch-packet],
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
    AS_HELP_STRING([--with-rdtsc-rx-after-process-buffer-to-receivefrom],
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
    AS_HELP_STRING([--with-rdtsc-rx-vma-tcp-idle-poll],
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
    AS_HELP_STRING([--with-rdtsc-rx-ready-poll-to-lwip],
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
    AS_HELP_STRING([--with-rdtsc-rx-lwip-to-receivefrom],
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
    AS_HELP_STRING([--with-rdtsc-tx-sendto-to-after-post-send],
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
    AS_HELP_STRING([--with-rdtsc-tx-verbs-post-send],
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
    AS_HELP_STRING([--with-rdtsc-receivefrom-to-sendto],
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
])