#!/bin/bash

main()
{
WORKSPACE=${WORKSPACE:=$(pwd)}
BUILD_NUMBER=${BUILD_NUMBER:=0}

# exit code
rc=0

jenkins_test_custom_configure=${jenkins_test_custom_configure:=""}
jenkins_test_custom_prefix=${jenkins_test_custom_prefix:="jenkins"}

prefix=${jenkins_test_custom_prefix}/${jenkins_target}
build_dir=${WORKSPACE}/${prefix}/build/
install_dir=${WORKSPACE}/${prefix}/install
compiler_dir=${WORKSPACE}/${prefix}/compiler
test_dir=${WORKSPACE}/${prefix}/test
gtest_dir=${WORKSPACE}/${prefix}/gtest
rpm_dir=${WORKSPACE}/${prefix}/rpm
cov_dir=${WORKSPACE}/${prefix}/cov
cppcheck_dir=${WORKSPACE}/${prefix}/cppcheck
csbuild_dir=${WORKSPACE}/${prefix}/csbuild
vg_dir=${WORKSPACE}/${prefix}/vg
style_dir=${WORKSPACE}/${prefix}/style
tool_dir=${WORKSPACE}/${prefix}/tool
commit_dir=${WORKSPACE}/${prefix}/commit

prj_lib=libvma.so
prj_service=vmad

nproc=$(grep processor /proc/cpuinfo|wc -l)
make_opt="-j$(($nproc / 2 + 1))"
if [ $(command -v timeout >/dev/null 2>&1 && echo $?) ]; then
    timeout_exe="timeout -s SIGKILL 20m"
fi

trap "on_exit" INT TERM ILL KILL FPE SEGV ALRM
}

function on_exit()
{
    rc=$((rc + $?))
    echo "[${0##*/}]..................exit code = $rc"
    pkill -9 sockperf
    pkill -9 vma
    pkill -9 ${prj_service}
}

function do_cmd()
{
    cmd="$*"
    set +e
    eval $cmd >> /dev/null 2>&1
    ret=$?
    set -e
    if [ $ret -gt 0 ]; then
        exit $ret
    fi
}

function do_export()
{
    export PATH="$1/bin:${PATH}"
    export LD_LIBRARY_PATH="$1/lib:${LD_LIBRARY_PATH}"
    export MANPATH="$1/share/man:${MANPATH}"
}

function do_archive()
{
    cmd="tar -rvf ${jenkins_test_artifacts}.tar $*"
    set +e
    eval $cmd >> /dev/null 2>&1
    set -e
}

# Test if an environment module exists and load it if yes.
# Otherwise, return error code.
# $1 - module name
#
function do_module()
{
    echo "Checking module $1"
    if [[ $(module avail 2>&1 | grep "$1" -q > /dev/null || echo $?) ]]; then
	    echo "[SKIP] module tool does not exist"
	    exit 0
	else
        module load "$1"
    fi
}

# format text
#
function do_format()
{
    set +x
    local is_format=true
    if [[ $is_format == true ]] ; then
        res=""
        for ((i=2; i<=$#; i++)) ; do
            case "${!i}" in
                "bold" ) res="$res\e[1m" ;;
                "underline" ) res="$res\e[4m" ;;
                "reverse" ) res="$res\e[7m" ;;
                "red" ) res="$res\e[91m" ;;
                "green" ) res="$res\e[92m" ;;
                "yellow" ) res="$res\e[93m" ;;
            esac
        done
        echo -e "$res$1\e[0m"
    else
        echo "$1"
    fi
    set -x
}

# print error message
#
function do_err()
{
    set +x
    echo -e $(do_format "FAILURE: $1" "red" "bold") 2>&1
    if [ -n "$2" ]; then
        echo ">>>"
        cat $2
        echo ">>>"
    fi
    set -x
}

# Verify if current environment is suitable.
#
function do_check_env()
{
    echo "Checking system configuration"
    if [ $(command -v pkill >/dev/null 2>&1 || echo $?) ]; then
        echo "pkill is not found"
        echo "environment [NOT OK]"
        exit 1
    fi

    if [ "$(whoami)" == "root" ]; then
        export sudo_cmd=""
    else
        export sudo_cmd="sudo"
    fi

    if [ $(${sudo_cmd} pwd >/dev/null 2>&1 || echo $?) ]; then
        echo "${sudo_cmd} does not work"
        echo "environment [NOT OK]"
        exit 1
    fi

    if [ $(command -v ofed_info >/dev/null 2>&1 || echo $?) ]; then
        echo "Configuration: INBOX : ${ghprbTargetBranch}"
        export jenkins_ofed=inbox
    else
        echo "Configuration: MOFED[$(ofed_info -s)] : ${ghprbTargetBranch}"
        export jenkins_ofed=$(ofed_info -s | sed 's/.*[l|X]-\([0-9\.]\+\).*/\1/')
    fi

    echo "environment [OK]"
}

# Launch command and detect result of execution
# $1 - test command
# $2 - test id
# $3 - test name
# $4 - test tap file
# $5 - files for stdout/stderr
#
function do_check_result()
{
    set +e
    if [ -z "$5" ]; then
        eval $timeout_exe $1
        ret=$?
    else
        eval $timeout_exe $1 2>> "${5}.err" 1>> "${5}.log"
        ret=$?
        do_archive "${5}.err" "${5}.log"
    fi
    set -e
    if [ $ret -gt 0 ]; then
        echo "not ok $2 $3" >> $4
        if [ -z "$5" ]; then
            do_err "$1"
        else
            do_err "$1" "${5}.err"
        fi
    else
        echo "ok $2 $3" >> $4
    fi
    rc=$((rc + $ret))
}

# Detect interface ip
# $1 - [ib|eth] to select link type or empty to select the first found
# $2 - [empty|mlx4|mlx5]
# $3 - ip address not to get
#
function do_get_ip()
{
    sv_ifs=${IFS}
    netdevs=$(ibdev2netdev | grep Up | grep "$2" | cut -f 5 -d ' ')
    IFS=$'\n' read -rd '' -a netdev_ifs <<< "${netdevs}"
    lnkifs=$(ip -o link | awk '{print $2,$(NF-2)}')
    IFS=$'\n' read -rd '' -a lnk_ifs <<< "${lnkifs}"
    IFS=${sv_ifs}
    ifs_array=()

    for nd_if in "${netdev_ifs[@]}" ; do
        found_if=''
        for v_if in "${lnk_ifs[@]}" ; do
            if [ ! -z "$(echo ${v_if} | grep ${nd_if})" ] ; then
                mac=$(echo "${v_if}"| awk '{ print $NF }') #; echo "mac=$mac"
                for p_if in "${lnk_ifs[@]}" ; do
                    if [ ! -z "$(echo ${p_if} | grep -E ${mac} | grep -Ei eth)" ] ; then
                        if_name=$(echo "${p_if}"| awk '{ print $1}')
                        ifs_array+=(${if_name::-1})
                        #-#echo "${nd_if} --> ${if_name::-1} "
                        found_if=1
                        break 2
                    fi
                done
            fi
        done
        # use the netdevice if needed
        [ -z "${found_if}" ] && {
            ifs_array+=(${nd_if})
        }
    done

    if [ "${#ifs_array[@]}" -le 1 ] ; then
        if (dmesg | grep -i hypervisor > /dev/null 2>&1) ; then
           ifs_array=(eth1 eth2)
        fi
    fi

    for ip in ${ifs_array[@]}; do
        if [ -n "$1" -a "$1" == "ib" -a -n "$(ip link show $ip | grep 'link/inf')" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
            if [ -n "$(ibdev2netdev | grep $ip | grep mlx5)" ]; then
                local ofed_v=$(ofed_info -s | grep OFED | sed 's/.*[l|X]-\([0-9\.]\+\).*/\1/')
                if [ $(echo $ofed_v | grep 4.[1-9] >/dev/null 2>&1 || echo $?) ]; then
                    echo "$ip is CX4 device that does not support IPoIB in OFED: $ofed_v"
                    unset found_ip
                fi
            fi
        elif [ -n "$1" -a "$1" == "eth" -a -n "$(ip link show $ip | grep 'link/eth')" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        elif [ -z "$1" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        fi
        if [ -n "$found_ip" -a "$found_ip" != "$3" ]; then
            echo $found_ip
            break
        fi
    done
}

do_version_check()
{
    local version="$1" operator="$2" value="$3"
    awk -vv1="$version" -vv2="$value" 'BEGIN {
        split(v1, a, /\./); split(v2, b, /\./);
        if (a[1] == b[1]) {
            exit (a[2] '$operator' b[2]) ? 0 : 1
        }
        else {
            exit (a[1] '$operator' b[1]) ? 0 : 1
        }
    }'
}

do_check_dpcp()
{
    local ret=0
    local version=$(echo "${jenkins_ofed}" | cut -f1-2 -d.)

    if do_version_check $version '<' '5.2' ; then
        return
    fi
    echo "Checking dpcp usage"

    ret=0
    pushd $(pwd) > /dev/null 2>&1
    dpcp_dir=${WORKSPACE}/${prefix}/dpcp
    mkdir -p ${dpcp_dir} > /dev/null 2>&1
    cd ${dpcp_dir}

    set +e
    if [ $ret -eq 0 ]; then
        eval "timeout -s SIGKILL 20s git clone git@github.com:Mellanox/dpcp.git . " > /dev/null 2>&1
        ret=$?
    fi

    if [ $ret -eq 0 ]; then
        last_tag=$(git tag -l --format "%(refname:short)" --sort=-version:refname | head -n1)
        if [ -z "$last_tag" ]; then
            ret=1
        fi
    fi

    if [ $ret -eq 0 ]; then
        eval "git checkout $last_tag" > /dev/null 2>&1
        ret=$?
    fi

    if [ $ret -eq 0 ]; then
        eval "./autogen.sh && ./configure --prefix=${dpcp_dir}/install && make $make_opt install" > /dev/null 2>&1
        ret=$?
    fi
    set -e

    popd > /dev/null 2>&1
    if [ $ret -eq 0 ]; then
        eval "$1=${dpcp_dir}/install"
        echo "dpcp: $last_tag : ${dpcp_dir}/install"
    else
        echo "dpcp: no"
    fi
}

#######################################################
#
main "$@"
