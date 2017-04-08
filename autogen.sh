#!/bin/sh
set -e

oldpwd=$(pwd)
topdir=$(dirname "$0")
cd "$topdir"

CURRENT_VERSION_FILE=./build/current-version
if [ -d .git ] # don't ruin file that might come from build-rpm.sh
then
	. ./build/versioning.sh
	echo $GIT_VER > $CURRENT_VERSION_FILE
	echo $GIT_REF >> $CURRENT_VERSION_FILE
fi

rm -rf autom4te.cache
mkdir -p config
autoreconf -v --install || exit 1
rm -rf autom4te.cache

cd "$oldpwd"
rm -f $CURRENT_VERSION_FILE
exit 0
