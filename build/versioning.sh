#!/bin/bash -e

ver=`git describe --long --abbrev=40 --dirty --tags 2> /dev/null || echo ""`
if [ -n "$ver" ]; then ver=`echo $ver | sed -e 's/-dirty/+/' | sed s/.*-g//`; else  ver=""; fi
GIT_VER=$ver
GIT_REF=`git rev-parse HEAD 2> /dev/null || echo "no.git"`
