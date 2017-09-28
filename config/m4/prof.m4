# prof.m4 - Profiling, instrumentation
# 
# Copyright (C) Mellanox Technologies Ltd. 2016.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# libibprof profiling support
#
AC_ARG_WITH([ibprof],
    AC_HELP_STRING([--with-ibprof],
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

