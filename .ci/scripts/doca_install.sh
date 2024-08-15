#!/bin/bash

set -xvEe -o pipefail

DOCA_REPO_PATH="https://doca-repo-prod.nvidia.com/internal/repo/doca"
TARGET=${TARGET:=all}
DOCA_VERSION=${DOCA_VERSION:='2.8.0'}
DOCA_BRANCH=${DOCA_BRANCH:="latest"}
GPG_KEY="GPG-KEY-Mellanox.pub"

function error_handler() {
    bc="$BASH_COMMAND"
    set +xv
    echo "================================= DEBUG info start ================================="
    echo "Exited with ERROR in line $1"
    echo "Failed CMD: ${bc}"
    echo "Current directory is ${PWD}"
    echo "It took $(date -d@${SECONDS} -u +%H:%M:%S) to execute $0"
    echo "================================= DEBUG info end ================================="
    exit 1
}

trap 'error_handler $LINENO' ERR

function map_os_and_arch {
    . /etc/os-release

    ARCH=$(uname -m)

    # Determine OS and ARCH
    case "$ARCH" in
        x86_64)
            ARCH="x86_64"
            ;;
        aarch64)
            ARCH="arm64-sbsa"
            ;;
        *)
            echo "Unsupported architecture for $ID: $ARCH"
            return 1
    esac

    case "$ID" in
        ubuntu)
            if [[ "$VERSION_ID" =~ ^2[0-9]\.04$ ]]; then
                OS="${ID}${VERSION_ID}"
            else
                echo "Unsupported Ubuntu version: $VERSION_ID"
                exit 1
            fi
            GPG_KEY_CMD='cat "${GPG_KEY}" | gpg --dearmor > /etc/apt/trusted.gpg.d/"${GPG_KEY}"'
            REPO_CMD='echo deb [signed-by=/etc/apt/trusted.gpg.d/"${GPG_KEY}"] "${REPO_URL}" ./ >> /etc/apt/sources.list.d/doca.list'
            PKG_MGR="apt"
            UPDATE_CMD="update"
            CURL_INSTALL=""
            ;;

        rhel|ol)
            OS="${ID}${VERSION_ID}"
            GPG_KEY_CMD='rpm --import "${GPG_KEY}"'
            REPO_CMD='yum install -y yum-utils && yum-config-manager --add-repo "${REPO_URL}"'
            PKG_MGR="yum --nogpgcheck"
            UPDATE_CMD="makecache"
            CURL_INSTALL=""
            ;;
        sles)
            VERSION_ID=${VERSION_ID/./sp}
            OS="${ID}${VERSION_ID}"
            GPG_KEY_CMD='rpm --import "${GPG_KEY}"'
            REPO_CMD='zypper addrepo "${REPO_URL}" doca'
            PKG_MGR="zypper --no-gpg-checks"
            UPDATE_CMD="refresh"
            CURL_INSTALL="zypper install -y curl"
            ;;
        *)
            echo "Unsupported OS: $ID"
            return 1
    esac

    echo "OS=${OS}"
    echo "ARCH=${ARCH}"
    echo "PKG_MGR=${PKG_MGR}"
    echo "UPDATE_CMD=${UPDATE_CMD}"
    echo "GPG_KEY_CMD=${GPG_KEY_CMD}"
    echo "REPO_CMD=${REPO_CMD}"
    echo "CURL_INSTALL=${CURL_INSTALL}"
}

# Set up os-dependend variables
map_os_and_arch

# Install DOCA repo GPG key
${CURL_INSTALL}; curl -o "${GPG_KEY}" "${DOCA_REPO_PATH}/${DOCA_VERSION}/${OS}/${ARCH}/${DOCA_BRANCH}/${GPG_KEY}" 
eval "${GPG_KEY_CMD}"

# Install DOCA repo
REPO_URL="${DOCA_REPO_PATH}/${DOCA_VERSION}/${OS}/${ARCH}/${DOCA_BRANCH}/"
eval "${REPO_CMD}"

# Install DOCA
${PKG_MGR} ${UPDATE_CMD} 

${PKG_MGR} install -y doca-ofed-userspace

echo "=============================================="
echo 
echo "DOCA for Host has been successfully installed"
echo
echo "=============================================="
