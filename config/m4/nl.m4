# nl.m4 - Detect nl package
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2021. ALL RIGHTS RESERVED.
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
elif test -f "$(ls -d $ac_cv_ofed_path/lib/$(uname -m)-linux-*)/libibverbs.so" ; then
	libibverbs_file="$(ls -d $ac_cv_ofed_path/lib/$(uname -m)-linux-*)/libibverbs.so"
else
	libibverbs_file="$ac_cv_ofed_path/lib/libibverbs.so"
fi

PKG_CHECK_MODULES([LIBNL3],[libnl-route-3.0],[use_libnl3=yes] ,[use_libnl3=no])
PKG_CHECK_MODULES([LIBNL1],[libnl-1], [use_libnl1=yes] , [use_libnl1=no])

ldd $libibverbs_file | grep libnl >/dev/null 2>&1
if test $? -eq 0 ; then
	# When linking with libibverbs library, we must ensure that we pick the same version
	# of libnl that libibverbs picked.  Prefer libnl-3 unless libibverbs linked to libnl-1
	ldd $libibverbs_file | grep -e 'libnl3' -e 'libnl-3' >/dev/null 2>&1
	if test $? -eq 0 ; then
		# libnl3 case
		if test "$use_libnl3" == no; then
			AC_MSG_ERROR([libibverbs is linked with libnl3 while libnl3-devel\libnl3-route-devel are not installed. Please install libnl3-devel\libnl3-route-devel and try again])
		fi
		use_libnl1=no
	else
		# libnl1 case
		if test "$use_libnl1" == no; then
			AC_MSG_ERROR([libibverbs is linked with libnl1 while libnl1-devel is not installed. Please install libnl1-devel and try again])
		fi
		use_libnl3=no
	fi
fi

if test "$use_libnl3" == yes; then
	AC_SUBST([LIBNL_LIBS], "$LIBNL3_LIBS")
	AC_SUBST([LIBNL_CFLAGS], "$LIBNL3_CFLAGS")
	AC_SUBST([LIBNLX_DEVEL], "libnl3-devel")
	AC_DEFINE([HAVE_LIBNL3], [1], [Use libnl-3])
elif test "$use_libnl1" == yes; then
	AC_SUBST([LIBNL_LIBS], "$LIBNL1_LIBS")
	AC_SUBST([LIBNL_CFLAGS], "$LIBNL1_CFLAGS")
	AC_SUBST([LIBNLX_DEVEL], "libnl-devel")
	AC_DEFINE([HAVE_LIBNL1], [1], [Use libnl-1])
else
	AC_MSG_ERROR([libvma needs libnl3-devel,libnl3-route-devel\libnl1-devel (better libnl3)])
fi

])
