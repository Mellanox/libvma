#!/bin/bash

BASE_DIR=`pwd`
script_dir=`dirname $(readlink -f $0)`
cd $script_dir/..

./autogen.sh > build_rpm.log 2>&1

./configure >> build_rpm.log 2>&1
if [ $? -ne 0 ]; then
	echo "configure failed! see build_rpm.log"
	cd $BASE_DIR
	return
fi

make dist >> build_rpm.log 2>&1
if [ $? -ne 0 ]; then
	echo "make dist failed! see build_rpm.log"
	cd $BASE_DIR
	return
fi

rpmbuild -ta libvma*.tar.gz >> build_rpm.log 2>&1
if [ $? -ne 0 ]; then
	echo "rpmbuild failed! see build_rpm.log"
	cd $BASE_DIR
	return
fi

grep Wrote build_rpm.log
rm build_rpm.log

cd $BASE_DIR
