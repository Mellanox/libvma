#!/bin/bash -eExl

source $(dirname $0)/globals.sh

check_filter "Checking for rpm ..." "off"

cd $WORKSPACE

rm -rf $rpm_dir
mkdir -p $rpm_dir
cd $rpm_dir

#${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure
cd $build_dir

rpm_tap=${WORKSPACE}/${prefix}/rpm.tap

if [ -x /usr/bin/dpkg-buildpackage ]; then
    echo "Build on debian"
    set +e
    ${WORKSPACE}/build/build_deb.sh
    rc=$((rc + $?))
    set -e
	echo "1..1" > $rpm_tap
	if [ $rc -gt 0 ]; then
	    echo "not ok 1 Debian package" >> $rpm_tap
	else
	    echo ok 1 Debian package >> $rpm_tap
	fi
else
    echo "Build rpms"
    rpmspec=${build_dir}/build/libvma.spec
    rpmmacros="--define='_rpmdir ${rpm_dir}/rpm-dist' --define='_srcrpmdir ${rpm_dir}/rpm-dist' --define='_sourcedir ${rpm_dir}' --define='_specdir ${rpm_dir}' --define='_builddir ${rpm_dir}'"
    rpmopts="--nodeps --buildroot='${rpm_dir}/_rpm'"

    opt_tarball=1
    opt_srcrpm=1
    opt_binrpm=1

    echo "1..$(($opt_tarball + $opt_srcrpm + $opt_binrpm))" > $rpm_tap

    # SuSE can not create this folder
    mkdir -p ${rpm_dir}/rpm-dist

    test_id=0
    if [ $opt_tarball -eq 1 ]; then
        test_id=$((test_id+1))
        # Automake 1.10.1 has a bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=456632
        if [ -n "$(automake --version | grep 'automake (GNU automake) 1.10.1')" ]; then
            test_exec='make dist'
        else
            test_exec='make dist && make distcheck'
        fi

        check_result "$test_exec" "$test_id" "tarball" "$rpm_tap"
        eval $timeout_exe cp libvma*.tar.gz ${rpm_dir}
    fi
	
    if [ $opt_srcrpm -eq 1 ]; then
        test_id=$((test_id+1))
        test_exec="rpmbuild -bs $rpmmacros $rpmopts $rpmspec"
        check_result "$test_exec" "$test_id" "srcrpm" "$rpm_tap"
    fi

    if [ $opt_binrpm -eq 1 ]; then
        test_id=$((test_id+1))
        test_exec="rpmbuild -bb $rpmmacros $rpmopts $rpmspec"
        check_result "$test_exec" "$test_id" "binrpm" "$rpm_tap"
    fi
fi

echo "[${0##*/}]..................exit code = $rc"
exit $rc
