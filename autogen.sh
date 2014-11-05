#!/bin/sh

#Force libnl-devel softlink to the installed libnl.so.1
if [ ! -e /usr/lib64/libnl.so ] && [ -e /lib64/libnl.so.1 ]; then
	echo Force libnl-devel softlink to the installed libnl.so.1
	sudo ln -s /lib64/libnl.so.1  /usr/lib64/libnl.so
fi

set -x
test -d ./config || mkdir -p config
aclocal -I config
libtoolize --force --copy
autoheader
automake --foreign --add-missing --copy
autoconf
