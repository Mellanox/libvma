#!/bin/bash -eEx

source $(dirname $0)/globals.sh

check_filter "Checking for test ..." "on"

cd $WORKSPACE

#rm -rf $test_dir
#mkdir -p $test_dir
cd $test_dir

test_lib=$install_dir/lib/libvma.so
test_app=sockperf
if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
    git clone https://github.com/Mellanox/sockperf.git sockperf
    cd sockperf
    ./autogen.sh
    ./configure --prefix=$PWD/install
    make install
    test_app="$PWD/install/bin/sockperf"
fi

test_tap=${WORKSPACE}/${prefix}/test.tap
echo "1..1" > $test_tap

cd $test_dir
eval "LD_PRELOAD=$test_lib $test_app sr --tcp  > /dev/null 2>&1 &"
sleep 5

eval "LD_PRELOAD=$test_lib $test_app pp --tcp -m202 -t5"
echo "ok 1 simple" > $test_tap

pkill -9 sockperf
