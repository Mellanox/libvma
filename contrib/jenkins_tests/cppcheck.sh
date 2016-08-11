#!/bin/bash -xeEl

source $(dirname $0)/globals.sh

check_filter "Checking for cppcheck ..." "on"

# This unit requires module so check for existence
if [ $(command -v cppcheck >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] cppcheck tool does not exist"
	exit 0
fi

cd $WORKSPACE

rm -rf $cppcheck_dir
mkdir -p $cppcheck_dir
cd $cppcheck_dir

set +eE
eval "cppcheck --std=c99 \
	--inline-suppr --suppress=memleak:config_parser.y \
	--template='{severity}: {id}: {file}:{line}: {message}' \
	${WORKSPACE}/src 2> ${cppcheck_dir}/cppcheck.err 1> ${cppcheck_dir}/cppcheck.out"
rc=$(($rc+$?))
set -eE

nerrors=$(cat ${cppcheck_dir}/cppcheck.err | grep error | wc -l)
rc=$(($rc+$nerrors))

cppcheck_tap=${WORKSPACE}/${prefix}/cppcheck.tap

echo 1..1 > $cppcheck_tap
if [ $rc -gt 0 ]; then
    echo "not ok 1 cppcheck Detected $nerrors failures # $cov_url" >> $cppcheck_tap
    info="cppcheck found $nerrors errors"
    status="error"
else
    echo ok 1 cppcheck found no issues >> $cppcheck_tap
    info="cppcheck found no issues"
    status="success"
fi


echo "[${0##*/}]..................exit code = $rc"
exit $rc
