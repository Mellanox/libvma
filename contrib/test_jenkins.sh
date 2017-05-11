#!/bin/bash -El
#
# Testing script for VMA, to run from Jenkins CI
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2017.  ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#
#
# Environment variables set by Jenkins CI:
#  - WORKSPACE         : path to working directory
#  - BUILD_NUMBER      : jenkins build number
#  - JOB_URL           : jenkins job url
#  - JENKINS_RUN_TESTS : whether to run unit tests
#  - TARGET            : target configuration
#

echo "======================================================"
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
echo "======================================================"

source $(dirname $0)/jenkins_tests/globals.sh

set -xe
# check go/not go
#
do_check_env

rel_path=$(dirname $0)
abs_path=$(readlink -f $rel_path)

jenkins_test_build=${jenkins_test_build:="yes"}
jenkins_test_run=${jenkins_test_run:="yes"}

jenkins_test_gtest=${jenkins_test_gtest:="yes"}
jenkins_test_compiler=${jenkins_test_compiler:="yes"}
jenkins_test_rpm=${jenkins_test_rpm:="yes"}
jenkins_test_cov=${jenkins_test_cov:="yes"}
jenkins_test_cppcheck=${jenkins_test_cppcheck:="yes"}
jenkins_test_csbuild=${jenkins_test_csbuild:="yes"}
jenkins_test_vg=${jenkins_test_vg:="no"}
jenkins_test_style=${jenkins_test_style:="no"}
jenkins_test_tool=${jenkins_test_tool:="yes"}


echo Starting on host: $(hostname)

cd $WORKSPACE

rm -rf ${WORKSPACE}/${prefix}
rm -rf autom4te.cache

./autogen.sh -s


for target_v in "${target_list[@]}"; do
    IFS=':' read target_name target_option <<< "$target_v"

    export jenkins_test_artifacts="${WORKSPACE}/${prefix}/vma-${BUILD_NUMBER}-$(hostname -s)-${target_name}"
    export jenkins_test_custom_configure="${target_option}"
    export jenkins_target="${target_name}"
    set +x
    echo "======================================================"
    echo "Jenkins is checking for [${target_name}] target ..."
    echo "======================================================"
    set -x

    if [ "${target_name}" = "vmapoll" ]; then
        if [ $(echo ${jenkins_ofed} | grep 3.[3-9] >/dev/null 2>&1 || echo $?) ]; then
            set +x
            echo "======================================================"
            echo "Jenkins is skipping [${target_name}] target ..."
            echo "Reason: unsupported ofed version as [${jenkins_ofed}]"
            echo "======================================================"
            set -x
            continue
        fi
        jenkins_test_gtest="no"
        jenkins_test_run="no"
    fi

    # check building and exit immediately in case failure
    #
    if [ "$jenkins_test_build" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/build.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [build: rc=$rc]"
        fi
    fi

    set +e
    # check other units w/o forcing exiting
    #
    if [ "$jenkins_test_compiler" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/compiler.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [compiler: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_rpm" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/rpm.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [rpm: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_cov" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/cov.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [cov: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_cppcheck" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/cppcheck.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [cppcheck: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_csbuild" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/csbuild.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [csbuild: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_run" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/test.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [test: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_gtest" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/gtest.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [gtest: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_vg" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/vg.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [vg: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_style" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/style.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [style: rc=$rc]"
        fi
    fi
    if [ "$jenkins_test_tool" = "yes" ]; then
        $WORKSPACE/contrib/jenkins_tests/tool.sh
        rc=$((rc + $?))
        if [ $rc -gt 0 ]; then
           do_err "FAILURE: [tool: rc=$rc]"
        fi
    fi
    set -e

    # Archive all logs in single file
    do_archive "${WORKSPACE}/${prefix}/*.tap"
    gzip "${jenkins_test_artifacts}.tar"

    set +x
    echo "======================================================"
    echo "Jenkins result for [${target_name}] target: return $rc"
    echo "Artifacts: ${jenkins_test_artifacts}.tar.gz"
    echo "======================================================"
    set -x

done

rm -rf $WORKSPACE/config.cache

echo "[${0##*/}]..................exit code = $rc"
exit $rc
