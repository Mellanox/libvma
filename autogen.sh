#!/bin/sh


set -x
test -d ./config || mkdir -p config
aclocal -I config
libtoolize --force --copy
autoheader
automake --foreign --add-missing --copy
autoconf
