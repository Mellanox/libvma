#!/bin/bash -xeE

echo Starting on host: $(hostname)

source $(dirname $0)/jenkins_tests/globals.sh

export PATH=/hpc/local/bin::/usr/local/bin:/bin:/usr/bin:/usr/sbin:${PATH}

rel_path=$(dirname $0)
abs_path=$(readlink -f $rel_path)

jenkins_test_build_gcc=${jenkins_test_build_gcc:="yes"}
jenkins_test_build_icc=${jenkins_test_build_icc:="yes"}
jenkins_test_custom_configure=${jenkins_test_custom_configure:=""}
jenkins_test_run=${jenkins_test_run:="yes"}

jenkins_test_rpm=${jenkins_test_rpm:="yes"}
jenkins_test_cov=${jenkins_test_cov:="yes"}
jenkins_test_vg=${jenkins_test_vg:="no"}
jenkins_test_style=${jenkins_test_style:="no"}


rc=0

echo Starting on host: $(hostname)

cd $WORKSPACE

rm -rf ${WORKSPACE}/${prefix}
rm -rf autom4te.cache
rm -rf config
rm -f config.*

./autogen.sh -s

cd $WORKSPACE
if [ "$jenkins_test_build_gcc" = "yes" ]; then
    check_filter "Checking for building with gcc ..." "off"

    rm -rf ${build_dir}
    mkdir -p ${build_dir}
    cd ${build_dir}

    ${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
    make $make_opt install
fi

cd $WORKSPACE
if [ "$jenkins_test_build_icc" = "yes" ]; then
    check_filter "Checking for building with icc ..." "on"

    rm -rf ${build_dir}/icc
    mkdir -p ${build_dir}/icc
    cd ${build_dir}/icc

    module load hpcx-gcc
    module load intel/ics

    ${WORKSPACE}/configure --prefix=$install_dir CC=icc $jenkins_test_custom_configure
    make $make_opt all
    make $make_opt distclean

    module unload intel/ics
    module unload hpcx-gcc
fi


if [ "$jenkins_test_rpm" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/rpm.sh
fi
if [ "$jenkins_test_cov" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/cov.sh
fi
if [ "$jenkins_test_vg" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/vg.sh
fi
if [ "$jenkins_test_style" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/style.sh
fi
if [ "$jenkins_test_run" = "yes" ]; then
    $WORKSPACE/contrib/jenkins_tests/test.sh
fi

rm -rf $WORKSPACE/config.cache

exit $rc
