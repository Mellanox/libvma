Please see https://code.google.com/p/libvma/wiki/Build.

=Building and installing VMA== 

== Prerequisites ==
 1. MLNX_OFED (Download the correct version here - https://code.google.com/p/libvma/wiki/Downloads)
 2. Autoconf, Automake libtool (standart RH6.4 release should come with everything required)

==Build==
 1. ./autogen.sh
 2. ./configure
 3. make

You can find libvma.so in _path_to_vma_dir_/src/vma/.libs/libvma.so.

==Install==
In the previous step, you need to run ./configure with some parameters - please see the file `install.sh`.

After build:
 1. make install

==Run==

Load libvma.so using LD_PRELOAD=_path_to_libvma.so_ before your application, and run your application.


====For example:====
LD_PRELOAD=libvma.so sockperf


====Or:=====
export LD_PRELOAD=libvma.so

sockperf

==NOTES==
1. Download the source by pulling git.

The zip file googlecode offer for download does not contain the required file permissions. 

If you still wish to use the zip file, run:

`find . -name \*.sh -exec chmod 755 {} \;` 

   
`find ./ -exec touch {} \;`

2. DO NOT USE the scripts under ./build .

These are part of Mellanox internal automation system, and will not work for you.

We do not support manual building of RPM/DEB packages.

You can find the RPM & DEB packages for each version here - https://code.google.com/p/libvma/wiki/Downloads.
