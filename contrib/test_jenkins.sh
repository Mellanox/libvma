#!/bin/bash -El

echo
echo "# starting on host --------->  $(hostname) "
echo "# arguments called with ---->  ${@}        "
echo "# path to me --------------->  ${0}        "
echo "# parent path -------------->  ${0%/*}     "
echo "# name --------------------->  ${0##*/}    "
echo

PATH=${PATH}:/hpc/local/bin:/hpc/local/oss/vma/
MODULEPATH=${MODULEPATH}:/hpc/local/etc/modulefiles
env
for f in autoconf automake libtool ; do $f --version | head -1 ; done

source $(dirname $0)/jenkins_tests/globals.sh

set -xe
# check go/not go
#
check_env

rel_path=$(dirname $0)
abs_path=$(readlink -f $rel_path)

jenkins_test_build=${jenkins_test_build:="yes"}
jenkins_test_run=${jenkins_test_run:="yes"}

jenkins_test_compiler=${jenkins_test_compiler:="yes"}
jenkins_test_rpm=${jenkins_test_rpm:="yes"}
jenkins_test_cov=${jenkins_test_cov:="yes"}
jenkins_test_cppcheck=${jenkins_test_cppcheck:="yes"}
jenkins_test_vg=${jenkins_test_vg:="no"}
jenkins_test_style=${jenkins_test_style:="no"}


echo Starting on host: $(hostname)

cd $WORKSPACE

rm -rf ${WORKSPACE}/${prefix}
rm -rf autom4te.cache

./autogen.sh -s

# check building and exit immediately in case failure
#
if [ "$jenkins_test_build" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/build.sh
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
if [ "$jenkins_test_cppcheck" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/cppcheck.sh
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
