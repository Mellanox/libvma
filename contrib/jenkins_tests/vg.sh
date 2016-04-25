#!/bin/bash -eEx

source $(dirname $0)/globals.sh

check_filter "Checking for valgrind ..." "on"

cd $WORKSPACE

rm -rf $style_dir
mkdir -p $style_dir
cd $style_dir


module load tools/valgrind
module load tools/mofed_valgrind

${WORKSPACE}/configure --prefix=$install_dir --with-valrind $jenkins_test_custom_configure

set +x

make $make_opt all
rc=$?

vg_tests=$(cd test && ls -1 |wc -l)

vg_url="$BUILD_URL/valgrindResult/"

if [ -n "$ghprbGhRepository" ]; then
    context="MellanoxLab/valgrind"
    if [ "$rc" = "0" ]; then
        info="Valgrind passed $vg_tests"
        status="success"
    else
        info="Valgrind failed"
        status="error"
    fi
    do_github_status "repo='$ghprbGhRepository' sha1='$ghprbActualCommit' target_url='$vg_url' state='$status' info='$info' context='$context'"
fi
set -x


module unload tools/mofed_valgrind
module unload tools/valgrind
