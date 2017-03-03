# opt.m4 - Macros to control optimization
# 
# Copyright (C) Mellanox Technologies Ltd. 2016-2017.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Logging control
#
AC_ARG_ENABLE(
    [opt-log],
    AC_HELP_STRING(
        [--enable-opt-log],
        [Optimize logging output: none, auto, details, debug, func (default=no)]),,
    enableval=none)
AC_MSG_CHECKING(
    [checking for logging optimization])
case "$enableval" in
    yes | auto)
        CPPFLAGS="$CPPFLAGS -DVMA_OPTIMIZE_LOG=5 -DNDEBUG"
        ;;
    no | none)
        ;;
    details)
        CPPFLAGS="$CPPFLAGS -DVMA_OPTIMIZE_LOG=4 -DNDEBUG"
        ;;
    debug)
        CPPFLAGS="$CPPFLAGS -DVMA_OPTIMIZE_LOG=5 -DNDEBUG"
        ;;
    func)
        CPPFLAGS="$CPPFLAGS -DVMA_OPTIMIZE_LOG=6 -DNDEBUG"
        ;;
    *)
        AC_MSG_ERROR([Unrecognized --enable-opt-log parameter as $enableval])
        ;;
esac
AC_MSG_RESULT([$enableval])

