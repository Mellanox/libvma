# dpcp.m4 - Library to operate with DevX
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2021. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# libdpcp usage support
#
AC_DEFUN([DPCP_CAPABILITY_SETUP],
[
AC_ARG_WITH([dpcp],
    AS_HELP_STRING([--with-dpcp(=DIR)],
                   [Search for dpcp headers and libraries in DIR (default NO)]),
    [],
    [with_dpcp=no]
)

if test "x$vma_cv_directverbs" != x3 && test "x$with_dpcp" != xno; then
    AC_MSG_ERROR([dpcp can be used under RDMA-core subsystem only])
fi

vma_cv_dpcp=0
AS_IF([test "x$with_dpcp" == xno],
    [],
    [
    if test -z "$with_dpcp" || test "$with_dpcp" = "yes"; then
        with_dpcp=/usr
    fi

    FUNC_CHECK_WITHDIR([dpcp], [$with_dpcp], [include/mellanox/dpcp.h])

    vma_cv_dpcp_save_CPPFLAGS="$CPPFLAGS"
    vma_cv_dpcp_save_CXXFLAGS="$CXXFLAGS"
    vma_cv_dpcp_save_CFLAGS="$CFLAGS"
    vma_cv_dpcp_save_LDFLAGS="$LDFLAGS"
    vma_cv_dpcp_save_LIBS="$LIBS"

    vma_cv_dpcp_CPPFLAGS="-I$with_dpcp/include"
    vma_cv_dpcp_LIBS="-ldpcp -lmlx5"
    vma_cv_dpcp_LDFLAGS="-L$with_dpcp/lib -Wl,--rpath,$with_dpcp/lib"
    if test -d "$with_dpcp/lib64"; then
        vma_cv_dpcp_LDFLAGS="-L$with_dpcp/lib64 -Wl,--rpath,$with_dpcp/lib64"
    fi

    CPPFLAGS="$vma_cv_dpcp_CPPFLAGS $CPPFLAGS"
    CXXFLAGS="-std=c++11 $CXXFLAGS"
    LDFLAGS="$vma_cv_dpcp_LDFLAGS $LDFLAGS"
    LIBS="$vma_cv_dpcp_LIBS $LIBS"

    AC_LANG_PUSH([C++])
    AC_CHECK_HEADER(
        [mellanox/dpcp.h],
        [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <mellanox/dpcp.h>]],
             [[dpcp::provider *provider;
               dpcp::provider::get_instance(provider);]])],
             [vma_cv_dpcp=1])
        ])
    AC_LANG_POP()

    CPPFLAGS="$vma_cv_dpcp_save_CPPFLAGS"
    CXXFLAGS="$vma_cv_dpcp_save_CXXFLAGS"
    CFLAGS="$vma_cv_dpcp_save_CFLAGS"
    LDFLAGS="$vma_cv_dpcp_save_LDFLAGS"
    LIBS="$vma_cv_dpcp_save_LIBS"
    ])

AC_MSG_CHECKING([for dpcp support])
if test "$vma_cv_dpcp" -ne 0; then
    CPPFLAGS="$CPPFLAGS $vma_cv_dpcp_CPPFLAGS"
    LDFLAGS="$LDFLAGS $vma_cv_dpcp_LDFLAGS"
    AC_SUBST([DPCP_LIBS], ["-ldpcp"])
    AC_DEFINE_UNQUOTED([DEFINED_DPCP], [1], [Define to 1 to use DPCP])
    AC_MSG_RESULT([yes])
else
    AS_IF([test "x$with_dpcp" == xno],
        [AC_MSG_RESULT([no])],
        [AC_MSG_ERROR([dpcp support requested but not present])])
fi
])
