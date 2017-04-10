#!/bin/sh

set -e
rm -rf autom4te.cache
mkdir -p config
autoreconf -v --install || exit 1
rm -rf autom4te.cache

exit 0

