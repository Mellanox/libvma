#!/bin/bash

BASE_DIR=`pwd`
script_dir=`dirname $(readlink -f $0)`
cd $script_dir/..

BUILD_DIR=`pwd`/build_debian
mkdir -p $BUILD_DIR

LOG_FILE=$BUILD_DIR/build_debian.log

echo "Running ./autogen.sh ..."
./autogen.sh > $LOG_FILE 2>&1

echo "Running ./configure ..."
./configure >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
	echo "configure failed! see $LOG_FILE"
	cd $BASE_DIR
	exit 1
fi

echo "Running make dist ..."
make dist >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
	echo "make dist failed! see $LOG_FILE"
	cd $BASE_DIR
	exit 2
fi

cp libvma*.tar.gz $BUILD_DIR/
cd $BUILD_DIR
tar xzvf libvma*.tar.gz >> $LOG_FILE 2>&1
cd $(find . -maxdepth 1 -type d -name "libvma*")
VMA_DIR=`pwd`

echo "Running dpkg-buildpackage ... this might take a while ..."
dpkg-buildpackage -us -uc >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
	echo "dpkg-buildpackage failed! see $LOG_FILE"
	cd $BASE_DIR
	exit 3
fi

cd ..

rm -rf $VMA_DIR

echo "Debian file are under $BUILD_DIR"

rm -rf $LOG_FILE

cd $BASE_DIR
