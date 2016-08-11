#!/bin/bash -xeEl

source $(dirname $0)/globals.sh

check_filter "Checking for coverity ..." "on"

# This unit requires module so check for existence
if [ $(command -v module >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] module tool does not exist"
	exit 0
fi
module load tools/cov

cd $WORKSPACE

rm -rf $cov_dir
mkdir -p $cov_dir
cd $cov_dir

cov_exclude_file_list="tests"

cov_build_id="cov_build_${BUILD_NUMBER}"
cov_build="$cov_dir/$cov_build_id"

set +eE

${WORKSPACE}/configure --prefix=${cov_dir}/install $jenkins_test_custom_configure
make clean
eval "cov-build --dir $cov_build make"
rc=$(($rc+$?))

for excl in $cov_exclude_file_list; do
    cov-manage-emit --dir $cov_build --tu-pattern "file('$excl')" delete
    sleep 1
done

eval "cov-analyze --enable-fnptr --fnptr-models --all --paths 20000 --dir $cov_build"
rc=$(($rc+$?))

set -eE

cov_web_path="$(echo $cov_build | sed -e s,$WORKSPACE,,g)"
nerrors=$(cov-format-errors --dir $cov_build | awk '/Processing [0-9]+ errors?/ { print $2 }')
rc=$(($rc+$nerrors))

index_html=$(cd $cov_build && find . -name index.html | cut -c 3-)
cov_url="$WS_URL/$cov_web_path/${index_html}"
cov_file="$cov_build/${index_html}"

rm -f jenkins_sidelinks.txt

coverity_tap=${WORKSPACE}/${prefix}/coverity.tap

echo 1..1 > $coverity_tap
if [ $rc -gt 0 ]; then
    echo "not ok 1 Coverity Detected $nerrors failures # $cov_url" >> $coverity_tap
    info="Coverity found $nerrors errors"
    status="error"
else
    echo ok 1 Coverity found no issues >> $coverity_tap
    info="Coverity found no issues"
    status="success"
fi

if [ -n "$ghprbGhRepository" ]; then
    context="MellanoxLab/coverity"
    do_github_status "repo='$ghprbGhRepository' sha1='$ghprbActualCommit' target_url='$cov_url' state='$status' info='$info' context='$context'"
fi

echo Coverity report: $cov_url
printf "%s\t%s\n" Coverity $cov_url >> jenkins_sidelinks.txt

module unload tools/cov

echo "[${0##*/}]..................exit code = $rc"
exit $rc
