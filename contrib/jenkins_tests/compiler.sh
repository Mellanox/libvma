#!/bin/bash -eExl

source $(dirname $0)/globals.sh

check_filter "Checking for compiler ..." "on"

# This unit requires module so check for existence
if [ $(command -v module >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] module tool does not exist"
	exit 0
fi
module load intel/ics-15.0.1

cd $WORKSPACE

rm -rf $compiler_dir
mkdir -p $compiler_dir
cd $compiler_dir

compiler_list="icc:icpc clang:clang++"

compiler_tap=${WORKSPACE}/${prefix}/compiler.tap
echo "1..$(echo $compiler_list | tr " " "\n" | wc -l)" > $compiler_tap

test_id=0
for compiler in $compiler_list; do
    IFS=':' read cc cxx <<< "$compiler"
    mkdir -p ${compiler_dir}/${test_id}
    cd ${compiler_dir}/${test_id}
    test_id=$((test_id+1))
    test_exec='${WORKSPACE}/configure --prefix=$compiler_dir-$cc CC=$cc CXX=$cxx $jenkins_test_custom_configure && make $make_opt all'
    check_result "$test_exec" "$test_id" "$compiler" "$compiler_tap"
    cd ${compiler_dir}
done

module unload intel/ics-15.0.1

echo "[${0##*/}]..................exit code = $rc"
exit $rc
