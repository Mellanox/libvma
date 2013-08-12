#!/bin/sh

VMA_LIBRARY_MAJOR=`grep "VMA_LIBRARY_MAJOR=" configure.ac | cut -f2 -d '='`
VMA_LIBRARY_MINOR=`grep "VMA_LIBRARY_MINOR=" configure.ac | cut -f2 -d '='`
VMA_LIBRARY_REVISION=`grep "VMA_LIBRARY_REVISION=" configure.ac | cut -f2 -d '='`
VMA_LIBRARY_RELEASE=`grep "VMA_LIBRARY_RELEASE=" configure.ac | cut -f2 -d '='`
VMA_VERSION="$VMA_LIBRARY_MAJOR.$VMA_LIBRARY_MINOR.$VMA_LIBRARY_REVISION-$VMA_LIBRARY_RELEASE"

./autogen.sh
#configure without parameters - good if you don't need to install. libvma.so will be in ./src/vma/.libs/libvma.so.
#./configure
#configure with parameters required for install
#example: ./configure --with-ofed=/usr --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include/mellanox --docdir=/usr/share/doc/libvma-6.4.7-0 --sysconfdir=/etc
./configure --with-ofed=/usr --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include/mellanox --docdir="/usr/share/doc/libvma-$VMA_VERSION" --sysconfdir=/etc
make
sudo make install
#make and install sockperf
make sockperf
sudo make install-sockperf

