# opt.m4 - Macros to control optimization
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2020.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Logging control
#
# VMA defined log levels
#
AC_DEFUN([OPT_VMA_LOGGING],
[
AC_DEFINE(DEFINED_VLOG_INIT,       -2, VMA Log Init Definition)
AC_DEFINE(DEFINED_VLOG_NONE,       -1, VMA Log None Definition)
AC_DEFINE(DEFINED_VLOG_PANIC,       0, VMA Log Panic Definition)
AC_DEFINE(DEFINED_VLOG_ERROR,       1, VMA Log Error Definition)
AC_DEFINE(DEFINED_VLOG_WARNING,     2, VMA Log Warning Definition)
AC_DEFINE(DEFINED_VLOG_INFO,        3, VMA Log Info Definition)
AC_DEFINE(DEFINED_VLOG_DETAILS,     4, VMA Log Details Definition)
AC_DEFINE(DEFINED_VLOG_DEBUG,       5, VMA Log Debug Definition)
AC_DEFINE(DEFINED_VLOG_FINE,        6, VMA Log Fine Definition)
AC_DEFINE(DEFINED_VLOG_FINER,       7, VMA Log Finer Definition)
AC_DEFINE(DEFINED_VLOG_ALL,         8, VMA Log All Definition)

AC_ARG_ENABLE([opt-log],
    AC_HELP_STRING([--enable-opt-log],
        [Optimize latency (none, medium, high) by limiting max log level (default=medium)]),,
    enableval=medium)
AC_MSG_CHECKING([for logging optimization])
enable_opt_log=DEFINED_VLOG_ALL
case "$enableval" in
    no | none)
        ;;
    yes | medium)
        enable_opt_log=DEFINED_VLOG_DEBUG
        ;;
    high)
        enable_opt_log=DEFINED_VLOG_DETAILS
        ;;
    *)
        AC_MSG_ERROR([Unrecognized --enable-opt-log parameter as $enableval])
        ;;
esac
AC_DEFINE_UNQUOTED([VMA_MAX_DEFINED_LOG_LEVEL], [$enable_opt_log], [Log optimization level])
AC_MSG_RESULT([$enableval])
])
