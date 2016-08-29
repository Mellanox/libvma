#!/bin/bash -eExl

source $(dirname $0)/globals.sh

check_filter "Checking for valgrind ..." "on"

# This unit requires module so check for existence
if [ $(command -v module >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] module tool does not exist"
	exit 0
fi
module load tools/valgrind

cd $WORKSPACE

rm -rf $vg_dir
mkdir -p $vg_dir
cd $vg_dir

${WORKSPACE}/configure --prefix=${vg_dir} --with-valgrind $jenkins_test_custom_configure

make $make_opt all
rc=$?

test_ip="$(get_ip)"
test_lib=$install_dir/lib/libvma.so
test_app=sockperf

if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
	test_app=${test_dir}/sockperf/install/bin/sockperf
	if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
	    echo can not find $test_app
	    exit 1
	fi
fi

vg_args="-v --log-file=${vg_dir}/valgrind.log \
    --memcheck:leak-check=full --track-origins=yes --read-var-info=yes \
    --undef-value-errors=yes --db-attach=no --track-fds=yes --show-reachable=yes \
    --num-callers=32 \
    --fullpath-after=${WORKSPACE} \
    --suppressions=${WORKSPACE}/contrib/valgrind/valgrind_vma.supp \
    --suppressions=${WORKSPACE}/contrib/valgrind/valgrind_libc.supp \
    --suppressions=${WORKSPACE}/contrib/valgrind/valgrind_sockperf.supp \
    --suppressions=${WORKSPACE}/contrib/valgrind/valgrind_rdma.supp \
    "

vg_tests=1

eval "env VMA_TX_BUFS=20000 VMA_RX_BUFS=20000 LD_PRELOAD=$test_lib $test_app sr --tcp -i ${test_ip} > /dev/null 2>&1 &"
sleep 5

eval "env VMA_TX_BUFS=20000 VMA_RX_BUFS=20000 LD_PRELOAD=$test_lib valgrind $vg_args $test_app pp --tcp -i ${test_ip} -m202 -t5"

pkill -9 sockperf

vg_tap=${WORKSPACE}/${prefix}/vg.tap

nerrors=$(cat ${vg_dir}/valgrind.log | awk '/ERROR SUMMARY: [0-9]+ errors?/ { print $4 }' | head -n1)

echo "1..1" > $vg_tap
if [ $nerrors -gt 0 ]; then
    echo "not ok 1 Valgrind Detected $nerrors failures" >> $vg_tap
    info="Valgrind found $nerrors errors"
    status="error"
else
    echo ok 1 Valgrind found no issues >> $vg_tap
    info="Valgrind found no issues"
    status="success"
fi

vg_url="$BUILD_URL/valgrindResult/"

if [ -n "$ghprbGhRepository" ]; then
    context="MellanoxLab/valgrind"
    do_github_status "repo='$ghprbGhRepository' sha1='$ghprbActualCommit' target_url='$vg_url' state='$status' info='$info' context='$context'"
fi

module unload tools/valgrind

rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
