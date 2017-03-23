#!/bin/bash

[ "x${WORKSPACE}" == "x" ] && { echo "Please set WORKSPACE"; exit 1; }

C_DIR=${PWD}

DEST_DIR="${C_DIR}/PKGS"

[ ! -z "${GHNL}" ] && . ${GHNL}

if [ -x /usr/bin/dpkg-buildpackage ] ; then
	PKGM="deb"
	PKG_DIR=${C_DIR}/deb
else
	PKGM="rpm"
	PKG_DIR=${C_DIR}/rpm
	SRC_PKG_DIR="${PKG_DIR}/SRC"
	PKG_SPEC=${WORKSPACE}/build/libvma.spec
fi

err()
{
	echo "Error: $1"
	exit 1
}

prep_rpm_env()
{
	mkdir -p ${PKG_DIR}/rpm-dist
	mkdir -p ${SRC_PKG_DIR}
}

prep_deb_env()
{
	echo "deb"
}

make_dist()
{
	cd ${WORKSPACE} ; ${WORKSPACE}/autogen.sh ; ${WORKSPACE}/configure
	dist=$(make dist | grep  tardir=libvma | awk -F ' ' '{print $1}' | awk -F '=' '{print $2}') ; dist+=".tar.gz"
	[ -f  "${WORKSPACE}/${dist}" ] && cp ${WORKSPACE}/${dist} ${SRC_PKG_DIR}/${dist} || err "file not found ${dist}"
	cd ${C_DIR} 
}

build_rpm_stage()
{
	local rpmspec=$1 ; local stage=$2 ; local src_dir=$3 ; local rpm_dir=$4
	rpmmacros=" --define='_rpmdir ${rpm_dir}/rpm-dist'"
	rpmmacros+=" --define='_srcrpmdir ${rpm_dir}/rpm-dist'"
	rpmmacros+=" --define='_sourcedir ${src_dir}'"
	rpmmacros+=" --define='_specdir ${rpm_dir}'"
	rpmmacros+=" --define='_builddir ${rpm_dir}'"
	rpmopts=" --nodeps --buildroot='${rpm_dir}/_rpm'"
	eval rpmbuild ${stage} -v ${rpmmacros} ${rpmopts} ${rpmspec}
}

build_rpm()
{
	local rpm_spec=$1 ; local src_dir=$2 ; local rpm_dir=$3
	build_rpm_stage "${rpm_spec}" "-bs" "${src_dir}" "${rpm_dir}"
	build_rpm_stage "${rpm_spec}" "-bb" "${src_dir}" "${rpm_dir}"
}

clean_rpm()
{
	rm -rf ${PKG_DIR}
}

copy_rpm()
{
	[ ! -d "${DEST_DIR}" ] && mkdir -p ${DEST_DIR} || rm -f ${DEST_DIR}/*.rpm
	cp -v ${PKG_DIR}/rpm-dist/*.rpm ${DEST_DIR}
	cp -v ${PKG_DIR}/rpm-dist/x86_64/*.rpm ${DEST_DIR}
}

build_deb()
{
	cd ${WORKSPACE}
	${WORKSPACE}/build/build_deb.sh
	cd ${C_DIR}
}

copy_deb()
{
	${WORKSPACE}/build/build_debian/* ${DEST_DIR}
}

usage()
{
cat << eOm
	usage:$0 -b|-build -c|-copy -clean -h
eOm
}

case "$1" in
	-b|-build)
		prep_${PKGM}_env
		make_dist
		build_${PKGM} "${PKG_SPEC}" "${SRC_PKG_DIR}" "${PKG_DIR}"
		copy_${PKGM}
		;;
	-c|-copy)
		copy_${PKGM}
		;;
	-clean)
		clean_${PKGM}
		;;
	*)
		usage
		;;
esac

exit 0;
# </buildpkgs.sh>

