#!/bin/bash

opt_srcpkg=0
opt_binpkg=0
opt_co=""
opt_defines=""
opt_exports=""

while test "$1" != ""; do
    case $1 in
        --input|-i)
            opt_input=$2
            shift
            ;;
        --output|-o)
            opt_output=$2
            shift
            ;;
        --srcpkg|-s)
            opt_srcpkg=1
            ;;
        --binpkg|-b)
            opt_binpkg=1
            ;;
        --co|-c)
            opt_co=$2
            shift
            ;;
        --arg|-a)
            arg_deb="$2"
            arg_rpm="${arg_deb/=/ }"
            opt_exports="$opt_exports :$arg_deb";
            opt_defines="$opt_defines --define='$arg_rpm'";
            shift
            ;;
        *)
            cat <<EOF
Unrecognized argument: $1
Valid arguments:
--input   |-i <dir>            Sources location
--output  |-o <dir>            Packages location
--srcpkg  |-s                  Create source package
--binpkg  |-b                  Create binary package
--checkout|-c <branch|tag>     Checkout from SCM
--argument|-a <key=value>      Pass options into build procedure
Example:
 * Prepare source package only
contrib/build_pkg.sh -s
 * Prepare source package directly from github using tag or branch
contrib/build_pkg.sh -s -i /tmp/libvma-9.0.2 -c 9.0.2
 * Pass none default configuration options
contrib/build_pkg.sh -b -s -a "configure_options=--enable-tso"
 * Create release
env PRJ_RELEASE=1 contrib/build_pkg.sh -b -s -a "configure_options=--enable-tso"
EOF
            exit 1
            ;;
    esac
    shift
done

opt_input=${opt_input:=$(pwd)}
opt_output=${opt_output:=${opt_input}/pkg}

pkg_name=libvma
pkg_url="https://github.com/Mellanox/${pkg_name}"
pkg_dir=${opt_output}
pkg_log=${pkg_dir}/build_pkg.log
pkg_src="${pkg_name}*"
pkg_tarball="${pkg_dir}/${pkg_src}.tar.gz"
pkg_indir=${opt_input}
pkg_outdir=${pkg_dir}/packages
pkg_spec=${pkg_name}.spec
pkg_rpm=0
pkg_label="[${pkg_name}] "
pkg_cleanup=""

rc=0
pushd $(pwd) > /dev/null 2>&1

if [ ! -d ${pkg_indir} ]; then
    mkdir -p ${pkg_indir}
elif [ -n "$opt_co" ]; then
    echo ${pkg_label} echo "Failure: can not clone at existing folder"
    exit 1
fi

echo ${pkg_label} "Using sources from ${pkg_indir} ..."
echo ${pkg_label} "Putting output at ${pkg_outdir} ..."

if [ -n "$opt_co" -a "$rc" -eq 0 ]; then
    echo ${pkg_label} "Getting ${opt_co} from ${pkg_url} ..."
    git clone -b "$opt_co" --depth=1 ${pkg_url} ${pkg_indir}
    rc=$?
fi

rm -rf ${pkg_dir}
mkdir -p ${pkg_dir}
mkdir -p ${pkg_outdir} >> ${pkg_log} 2>&1

cd ${pkg_indir}

if [ "$rc" -eq 0 ]; then
    echo ${pkg_label} "Running ./autogen.sh ..."
    ./autogen.sh -s >> ${pkg_log} 2>&1
    rc=$((rc + $?))
fi

cd ${pkg_dir}

if [ "$rc" -eq 0 ]; then
    echo ${pkg_label} "Running ./configure ..."
    ${pkg_indir}/configure >> ${pkg_log} 2>&1
    rc=$((rc + $?))
fi

if [ "$rc" -eq 0 ]; then
    echo ${pkg_label} "Getting tarball ..."
    make dist >> ${pkg_log} 2>&1
    rc=$((rc + $?))
fi

if [ ! -f ${pkg_tarball} ]; then
    echo ${pkg_label} echo "Failure: tarball does not exist at $PWD current rc=$rc (see: ${pkg_log})"
    exit 1
fi

if [ -x /usr/bin/dpkg-buildpackage ]; then
    pkg_rpm=0
    tar xzvf ${pkg_tarball} -C ${pkg_outdir} >> ${pkg_log} 2>&1
    rc=$((rc + $?))
    cd $(find ${pkg_outdir} -maxdepth 1 -type d -name "${pkg_src}") >> ${pkg_log} 2>&1
    rc=$((rc + $?))
    pkg_cleanup="${pkg_cleanup} $PWD"
else
    pkg_rpm=1
    mkdir -p ${pkg_dir}/{BUILD,BUILDROOT,SOURCES,SPECS} >> ${pkg_log} 2>&1
    rc=$((rc + $?))
    cp ${pkg_tarball} ${pkg_dir}/SOURCES/ >> ${pkg_log} 2>&1
    rc=$((rc + $?))
    cp ${pkg_dir}/contrib/scripts/${pkg_spec} ${pkg_dir}/SPECS/ >> ${pkg_log} 2>&1
    rc=$((rc + $?))
    rpmspec=${pkg_dir}/SPECS/${pkg_spec}
    rpmmacros="--define='_rpmdir ${pkg_outdir}' \
               --define='_srcrpmdir ${pkg_outdir}' \
               --define='_sourcedir ${pkg_dir}/SOURCES' \
               --define='_specdir ${pkg_dir}/SPECS' \
               --define='_builddir ${pkg_dir}/BUILD' \
               --define='_tmppath ${pkg_dir}/_tmp' \
               --define='dist %{nil}'"
    rpmopts="--buildroot='${pkg_dir}/BUILDROOT'"
    pkg_cleanup="${pkg_cleanup} ${pkg_dir}/BUILD ${pkg_dir}/BUILDROOT ${pkg_dir}/SOURCES ${pkg_dir}/SPECS"
fi

if [ $opt_srcpkg -eq 1 -a "$rc" -eq 0 ]; then
    echo ${pkg_label} "Getting source package ..."
    if [ $pkg_rpm -eq 1 ]; then
        eval rpmbuild -bs $rpmmacros $rpmopts $rpmspec $opt_defines >> ${pkg_log} 2>&1
    else
        IFS=$':'
        env $(echo $opt_exports | xargs) dpkg-buildpackage -us -uc -S >> ${pkg_log} 2>&1
        rc=$((rc + $?))
        unset IFS
    fi
    rc=$((rc + $?))
fi

if [ $opt_binpkg -eq 1 -a "$rc" -eq 0 ]; then
    echo ${pkg_label} "Getting binary package ..."
    if [ $pkg_rpm -eq 1 ]; then
        eval rpmbuild -bb $rpmmacros $rpmopts $rpmspec $opt_defines >> ${pkg_log} 2>&1
    else
        IFS=$':'
        env $(echo $opt_exports | xargs) dpkg-buildpackage -us -uc -b >> ${pkg_log} 2>&1
        rc=$((rc + $?))
        unset IFS
    fi
    rc=$((rc + $?))
fi

if [ "$rc" -eq 0 ]; then
    echo ${pkg_label} "Cleanup ..."
    rm -rf ${pkg_cleanup} >> ${pkg_log} 2>&1
fi

popd > /dev/null 2>&1

echo ${pkg_label} "Result: ${pkg_outdir}"
echo ${pkg_label} "Log file: ${pkg_log}"
echo ${pkg_label} "Exit: $rc"
exit $rc
