#!/bin/bash -uxe

echo -e "\n\n**********************************"
echo -e "\n\nStarting antivirus.sh script...\n\n"
echo -e "**********************************\n\n"

[[ -z "${WORKSPACE:-}" ]] && { echo "ERROR: WORKSPACE variable is empty"; exit 1; }
[[ ! -d "${WORKSPACE}" ]] && { echo "ERROR: ${WORKSPACE} does not exist"; exit 1; }
[[ -z "${release_folder:-}" ]] && { echo "ERROR: release_folder variable is empty"; exit 1; }
[[ ! -d "${release_folder}" ]] && { echo "ERROR: ${release_folder} does not exist"; exit 1; }
[[ -z "${release_tag:-}" ]] && { echo "ERROR: release_tag variable is empty"; exit 1; }

if [ -z "${revision:-}" ]; then
    echo "WARN: 'revision' was not set, defaulting to 1"
    revision=1
fi

mkdir -p "${WORKSPACE}/logs/"

release_src_folder="${release_folder}/vma_v_${release_tag}-0/src"
pkg_name="libvma-${release_tag}-${revision}.src.rpm"
tarball_name="libvma-${release_tag}.tar.gz"
rpm_log="${WORKSPACE}/logs/${pkg_name}_antivirus.log"
tarball_log="${WORKSPACE}/logs/${tarball_name}_antivirus.log"

[[ ! -d "${release_src_folder}" ]] && { echo "ERROR: ${release_src_folder} does not exist."; exit 1; }
[[ ! -e "${release_src_folder}/${pkg_name}" ]] && { echo "ERROR: ${release_src_folder}/${pkg_name} does not exist."; exit 1; }
[[ ! -e "${release_src_folder}/${tarball_name}" ]] && { echo "ERROR: ${release_src_folder}/${tarball_name} does not exist."; exit 1; }

/auto/GLIT/SCRIPTS/HELPERS/antivirus-scan.sh "${release_src_folder}/${pkg_name}" |& tee "${rpm_log}"
/auto/GLIT/SCRIPTS/HELPERS/antivirus-scan.sh "${release_src_folder}/${tarball_name}" |& tee "${tarball_log}"

if grep -q 'Possibly Infected:.............     0' "${rpm_log}" && grep -q 'Possibly Infected:.............     0' "${tarball_log}"; then
    exit 0
else
    exit 1
fi
