# opt.m4 - Macros to control optimization
# 
# Copyright (C) Mellanox Technologies Ltd. 2016.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Logging control
#
AC_ARG_ENABLE(
    [opt-log],
    AC_HELP_STRING(
        [--enable-opt-log],
        [Optimize logging output (default=no)]))
AC_MSG_CHECKING(
    [checking for logging optimization])
if test "x$enable_opt_log" = "xyes"; then
    CPPFLAGS="$CPPFLAGS -DVMA_OPTIMIZE_LOG -DNDEBUG"
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

