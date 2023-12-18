#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for rpm ..."

cd $WORKSPACE

rm -rf $rpm_dir
mkdir -p $rpm_dir
cd $rpm_dir

rpm_tap=${WORKSPACE}/${prefix}/rpm.tap

opt_tarball=1
opt_srcrpm=1
opt_binrpm=1
opt_checkpkg=1
opt_rpm=0

${WORKSPACE}/configure --prefix=${rpm_dir}/install $jenkins_test_custom_configure > "${rpm_dir}/rpm.log" 2>&1

if [ -x /usr/bin/dpkg-buildpackage ]; then
    echo "Build on debian"
    opt_rpm=0
else
    echo "Build rpms"
    opt_rpm=1
    rpmspec=${build_dir}/0/contrib/scripts/libvma.spec
    rpmmacros="--define='_rpmdir ${rpm_dir}/rpm-dist' \
               --define='_srcrpmdir ${rpm_dir}/rpm-dist' \
               --define='_sourcedir ${rpm_dir}' \
               --define='_specdir ${rpm_dir}' \
               --define='_builddir ${rpm_dir}' \
               --define='_tmppath ${rpm_dir}/_tmp'"
    rpmopts="--buildroot='${rpm_dir}/_rpm'"
fi

echo "1..$(($opt_tarball + $opt_srcrpm + $opt_binrpm + $opt_checkpkg))" > $rpm_tap

# SuSE can not create this folder
mkdir -p ${rpm_dir}/rpm-dist
mkdir -p ${rpm_dir}/deb-dist

test_id=0
if [ $opt_tarball -eq 1 ]; then
    # Automake 1.10.1 has a bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=456632
    if [ -n "$(automake --version | grep 'automake (GNU automake) 1.10.1')" ]; then
        test_exec='make $make_opt dist'
    else
        test_exec='make $make_opt dist && make $make_opt distcheck'
    fi

    do_check_result "$test_exec" "$test_id" "tarball" "$rpm_tap" "${rpm_dir}/rpm-${test_id}"
    test_id=$((test_id+1))
fi

if [ $opt_rpm -eq 0 ]; then
    cd ${rpm_dir}/deb-dist
    tar xzvf ${rpm_dir}/libvma*.tar.gz
    cd $(find . -maxdepth 1 -type d -name "libvma*")
fi

if [ $opt_srcrpm -eq 1 ]; then
    if [ $opt_rpm -eq 1 ]; then
        test_exec="env RPM_BUILD_NCPUS=${NPROC} rpmbuild -bs $rpmmacros $rpmopts $rpmspec"
    else
        test_exec="dpkg-buildpackage -us -uc -S"
    fi
    do_check_result "$test_exec" "$test_id" "srcrpm" "$rpm_tap" "${rpm_dir}/rpm-${test_id}"
    test_id=$((test_id+1))
fi

if [ $opt_binrpm -eq 1 ]; then
    if [ $opt_rpm -eq 1 ]; then
        test_exec="env RPM_BUILD_NCPUS=${NPROC} rpmbuild -bb $rpmmacros $rpmopts $rpmspec"
    else
        test_exec="dpkg-buildpackage -us -uc -b"
    fi
    do_check_result "$test_exec" "$test_id" "binrpm" "$rpm_tap" "${rpm_dir}/rpm-${test_id}"
    test_id=$((test_id+1))
fi

if [ $opt_checkpkg -eq 1 ]; then
    test_exec="env RPM_BUILD_NCPUS=${NPROC} PRJ_RELEASE=1 ${WORKSPACE}/contrib/build_pkg.sh -b -s -a \"configure_options=$jenkins_test_custom_configure\" -i ${WORKSPACE} -o ${rpm_dir}/dist-pkg"
    do_check_result "$test_exec" "$test_id" "checkpkg" "$rpm_tap" "${rpm_dir}/rpm-${test_id}"
    test_id=$((test_id+1))
fi

echo "[${0##*/}]..................exit code = $rc"
exit $rc
