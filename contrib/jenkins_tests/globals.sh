#!/bin/bash

WORKSPACE=${WORKSPACE:=$PWD}
if [ -z "$BUILD_NUMBER" ]; then
    echo Running interactive
    BUILD_NUMBER=1
    WS_URL=file://$WORKSPACE
    JENKINS_RUN_TESTS=yes
else
    echo Running under jenkins
    WS_URL=$JOB_URL/ws
fi

# exit code
rc=0

jenkins_test_custom_configure=${jenkins_test_custom_configure:=""}

prefix=jenkins
build_dir=${WORKSPACE}/${prefix}/build
install_dir=${WORKSPACE}/${prefix}/install
compiler_dir=${WORKSPACE}/${prefix}/compiler
test_dir=${WORKSPACE}/${prefix}/test
rpm_dir=${WORKSPACE}/${prefix}/rpm
cov_dir=${WORKSPACE}/${prefix}/cov
vg_dir=${WORKSPACE}/${prefix}/vg
style_dir=${WORKSPACE}/${prefix}/style


timeout_exe=${timout_exe:="timeout -s SIGKILL 20m"}
nproc=$(grep processor /proc/cpuinfo|wc -l)
make_opt="-j$(($nproc / 2 + 1))"

trap "on_exit" INT TERM ILL KILL FPE SEGV ALRM

function on_exit
{
    rc=$((rc + $?))
    echo "[${0##*/}]..................exit code = $rc"
    pkill -9 sockperf
}

function do_github_status()
{
    echo "Calling: github $1"
    eval "local $1"

    local token=""
    if [ -z "$tokenfile" ]; then
        tokenfile="$HOME/.mellanox-github"
    fi

    if [ -r "$tokenfile" ]; then
        token="$(cat $tokenfile)"
    else
        echo Error: Unable to read tokenfile: $tokenfile
        return
    fi

    curl \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"state\": \"$state\", \"context\": \"$context\",\"description\": \"$info\", \"target_url\": \"$target_url\"}" \
    "https://api.github.com/repos/$repo/statuses/${sha1}?access_token=$token"
}

function check_env()
{
    if [ $(command -v ofed_info >/dev/null 2>&1 || echo $?) ]; then
        echo "Configuration: INBOX : ${ghprbTargetBranch}"
        echo "environment [NOT OK]"
        exit 0
    elif [ -n "$ghprbTargetBranch" -a "$ghprbTargetBranch" != "master" ]; then
        echo "Configuration: MOFED[$(ofed_info -s)] : ${ghprbTargetBranch}"

        if [ -n "$(uname -m | grep ppc)" ]; then
            echo "environment [NOT OK]"
            exit 0
        fi

        ofed_v=$(ofed_info -s | grep OFED | sed 's/.*[l|X]-\([0-9\.]\+\).*/\1/')
        if [ $(echo $ofed_v | grep 3.[2-9] >/dev/null 2>&1 || echo $?) ]; then
            echo "environment [NOT OK]"
            exit 0
        fi
    else
        echo "Configuration: MOFED[$(ofed_info -s)] : master"
    fi

    echo "environment [OK]"
}

# $1 - output message
# $2 - [on|off] if on - skip this case if JENKINS_RUN_TESTS variable is OFF
function check_filter()
{
    local msg=$1
    local filter=$2

    if [ -n "$filter" -a "$filter" == "on" ]; then
        if [ -z "$JENKINS_RUN_TESTS" -o "$JENKINS_RUN_TESTS" == "no" ]; then
            echo "$msg [SKIP]"
            exit 0
        fi
    fi

    echo "$msg [OK]"
}

# $1 - test command
# $2 - test id
# $3 - test name
# $4 - test tap file
function check_result()
{
    set +e
    eval $timeout_exe $1
    ret=$?
    set -e
    if [ $ret -gt 0 ]; then
        echo "not ok $2 $3" >> $4
    else
        echo "ok $2 $3" >> $4
    fi
    rc=$((rc + $ret))
}

# $1 - [ib|eth] to select link type or empty to select the first found
function get_ip()
{
    for ip in $(ibdev2netdev | grep Up | cut -f 5 -d ' '); do
        if [ -n "$1" -a "$1" == "ib" -a -n "$(ip link show $ip | grep 'link/inf')" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        elif [ -n "$1" -a "$1" == "eth" -a -n "$(ip link show $ip | grep 'link/eth')" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        elif [ -z "$1" ]; then
            found_ip=$(ip -4 address show $ip | grep 'inet' | sed 's/.*inet \([0-9\.]\+\).*/\1/')
        fi
        if [ -n "$found_ip" ]; then
            echo $found_ip
            break
        fi
    done
}
