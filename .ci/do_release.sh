#!/bin/bash -Exel

echo "**********************************"
echo "Starting do_release.sh script..."
echo "**********************************"

set -o pipefail

print_help() {
    set +xv  
    echo -e "\n\n"
    echo "--------------------------------------------------"
    echo "Usage: release_folder=<release folder> release_tag=<release tag> [revision=<revision>] [do_release=<true|false>] $0"
    echo "       Where release folder is a path to NFS folder to copy the package into"
    echo "       Where release tag is a git tag to release (must be already tagged in the git repo)"
    echo "       Where revision is a number postfix to add the to package indicating which version of the tag it is - OPTIONAL, default value 1"
    echo "       Where do_release is a boolean value indicating if the script will copy the created package into the release folder location - OPTIONAL, default value false"
    exit 1
}

if [ -z "${release_folder}" ]; then
    echo "ERROR: 'release_folder' was not set."
    print_help
fi

if [ ! -e "${release_folder}" ] || [ ! -d "${release_folder}" ]; then
    echo "ERROR: [${release_folder}] directory doesn't exist."
    print_help
fi

if [ -z "${release_tag}" ]; then
    echo "ERROR: 'release_tag' was not set."
    print_help
fi

if [ -z "${revision}" ]; then
    echo "WARN: 'revision' was not set, defaulting to 1"
    revision=1
fi

if [ -z "${do_release}" ]; then
    echo "WARN: 'do_release' was not set, defaulting to false (package will not be release)"
    do_release=false
fi

env PRJ_RELEASE="${revision}" contrib/build_pkg.sh -s

MAJOR_VERSION=$(grep -e "define(\[prj_ver_major\]" configure.ac | awk '{ printf $2 };' | sed  's/)//g')
MINOR_VERSION=$(grep -e "define(\[prj_ver_minor\]" configure.ac | awk '{ printf $2 };' | sed  's/)//g')
REVISION_VERSION=$(grep -e "define(\[prj_ver_revision\]" configure.ac | awk '{ printf $2 };' | sed  's/)//g')
configure_ac_version="${MAJOR_VERSION}.${MINOR_VERSION}.${REVISION_VERSION}"
DST_DIR=${release_folder}/vma_v_${release_tag}-0/src
echo "FULL_VERSION from configure.ac: [${configure_ac_version}]"

if [[ "${release_tag}" != "${configure_ac_version}" ]]; then
    echo "ERROR: FULL_VERSION: ${configure_ac_version} from configure.ac doesn't match tag: ${release_tag} provided! Exit"
    exit 1
fi

if [ "${do_release}" = true ] ; then
    echo "do_release is set to true, will release package into ${DST_DIR}"

    cd pkg/packages || { echo "pkg folder is missing, exiting..."; exit 1; }
    pkg_name=$(ls -1 libvma-"${release_tag}"-"${revision}".src.rpm)

    if [[ -e "${DST_DIR}/${pkg_name}" ]]; then 
        echo "ERROR: [${DST_DIR}/${pkg_name}] file already exist. Exit"
        exit 1
    fi

    sudo -E -u swx-jenkins mkdir -p "$DST_DIR"
    sudo -E -u swx-jenkins cp -v "${pkg_name}" "$DST_DIR"
    sudo -E -u swx-jenkins ln -s "${DST_DIR}/${pkg_name}" "${release_folder}/source_rpms/${pkg_name}"
    echo "Release found at $DST_DIR"
else
     echo "do_release is set to false, skipping package release."
fi

set +x
echo "**********************************"
echo "Finished do_release.sh script..."
echo "**********************************"
