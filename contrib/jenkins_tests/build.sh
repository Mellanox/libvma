#!/bin/bash -eExl

source $(dirname $0)/globals.sh

check_filter "Checking for building with gcc ..." "off"

cd $WORKSPACE

rm -rf ${build_dir}
mkdir -p ${build_dir}
cd ${build_dir}

build_list="\
default: \
debug:--enable-debug \
opt-log:--enable-opt-log"

build_tap=${WORKSPACE}/${prefix}/build.tap
echo "1..$(echo $build_list | tr " " "\n" | wc -l)" > $build_tap

test_id=0
for build in $build_list; do
    IFS=':' read build_name build_option <<< "$build"
    test_id=$((test_id+1))
    if [ $test_id -eq 1 ]; then
        test_exec='${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure && make $make_opt install'
    else
        mkdir -p ${build_dir}/${test_id}
        cd ${build_dir}/${test_id}
        test_exec='${WORKSPACE}/configure --prefix=${build_dir}/${test_id}/install $build_option $jenkins_test_custom_configure && make $make_opt all'
    fi
    check_result "$test_exec" "$test_id" "$build_name" "$build_tap"
    cd ${build_dir}
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
