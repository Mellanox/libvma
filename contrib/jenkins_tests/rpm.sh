#!/bin/bash -eEx

source $(dirname $0)/globals.sh

check_filter "Checking for rpm ..." "off"

cd $WORKSPACE

rm -rf $rpm_dir
mkdir -p $rpm_dir
cd $rpm_dir

#${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
cd $build_dir


if [ -x /usr/bin/dpkg-buildpackage ]; then
    echo "Build on debian"
    ${WORKSPACE}/build/build_deb.sh
else
    echo "Build rpms"
    rpmspec=${WORKSPACE}/build/libvma.spec
    rpmmacros="--define='_rpmdir ${rpm_dir}/rpm-dist' --define='_srcrpmdir ${rpm_dir}/rpm-dist' --define='_sourcedir ${rpm_dir}' --define='_specdir ${rpm_dir}' --define='_builddir ${rpm_dir}'"
    rpmopts="--nodeps --buildroot='${rpm_dir}/_rpm'"

    opt_tarball=1
    opt_srcrpm=1
    opt_binrpm=1

	rpm_tap=${WORKSPACE}/${prefix}/rpm.tap
    echo "1..$(($opt_tarball + $opt_srcrpm + $opt_binrpm))" > $rpm_tap

    test_id=0
    if [ $opt_tarball -eq 1 ]; then
        test_id=$((test_id+1))
        test_exec='make dist'
        check_result "$test_exec" "$test_id" "tarball" "$rpm_tap"
        eval $timeout_exe cp libvma*.tar.gz ${rpm_dir}
    fi
	
    if [ $opt_srcrpm -eq 1 ]; then
        test_id=$((test_id+1))
        test_exec='echo rpmbuild -bs $rpmmacros $rpmopts $rpmspec | bash -eEx'
        check_result "$test_exec" "$test_id" "srcrpm" "$rpm_tap"
    fi

    if [ $opt_binrpm -eq 1 ]; then
        test_id=$((test_id+1))
        test_exec='echo rpmbuild -bb $rpmmacros $rpmopts $rpmspec | bash -eEx'
        check_result "$test_exec" "$test_id" "binrpm" "$rpm_tap"
    fi
fi
