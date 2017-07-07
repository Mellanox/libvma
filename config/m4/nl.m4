# nl.m4 - Detect nl package
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2017.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Checking nl library
#
AC_DEFUN([CHECK_NL_LIB],
[
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
])
