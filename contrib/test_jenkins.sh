#!/bin/bash -xeEl

echo
echo "# starting on host --------->  $(hostname) "
echo "# arguments called with ---->  ${@}        "
echo "# path to me --------------->  ${0}        "
echo "# parent path -------------->  ${0%/*}     "
echo "# name --------------------->  ${0##*/}    "
echo

source $(dirname $0)/jenkins_tests/globals.sh

export PATH=${PATH}:/hpc/local/bin
env

rel_path=$(dirname $0)
abs_path=$(readlink -f $rel_path)

jenkins_test_build=${jenkins_test_build:="yes"}
jenkins_test_run=${jenkins_test_run:="yes"}

jenkins_test_compiler=${jenkins_test_compiler:="yes"}
jenkins_test_rpm=${jenkins_test_rpm:="yes"}
jenkins_test_cov=${jenkins_test_cov:="yes"}
jenkins_test_vg=${jenkins_test_vg:="no"}
jenkins_test_style=${jenkins_test_style:="no"}


echo Starting on host: $(hostname)

cd $WORKSPACE

# check go/not go
check_env

rm -rf ${WORKSPACE}/${prefix}
rm -rf autom4te.cache

./autogen.sh -s

cd $WORKSPACE
if [ "$jenkins_test_build" = "yes" ]; then
    check_filter "Checking for building with gcc ..." "off"

    rm -rf ${build_dir}
    mkdir -p ${build_dir}
    cd ${build_dir}

    ${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
    rc=$((rc + $?))
    make $make_opt install
    rc=$((rc + $?))
fi


set +e
if [ "$jenkins_test_compiler" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/compiler.sh
    rc=$((rc + $?))
fi
if [ "$jenkins_test_rpm" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/rpm.sh
    rc=$((rc + $?))
fi
if [ "$jenkins_test_cov" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/cov.sh
    rc=$((rc + $?))
fi
if [ "$jenkins_test_run" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/test.sh
    rc=$((rc + $?))
fi
if [ "$jenkins_test_vg" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/vg.sh
    rc=$((rc + $?))
fi
if [ "$jenkins_test_style" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/style.sh
    rc=$((rc + $?))
fi
set -e

rm -rf $WORKSPACE/config.cache

echo "[${0##*/}]..................exit code = $rc"
exit $rc
