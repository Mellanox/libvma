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

prefix=jenkins
install_dir=${WORKSPACE}/${prefix}/install
build_dir=${WORKSPACE}/${prefix}/build
test_dir=${WORKSPACE}/${prefix}/test
rpm_dir=${WORKSPACE}/${prefix}/rpm
cov_dir=${WORKSPACE}/${prefix}/cov
vg_dir=${WORKSPACE}/${prefix}/vg
style_dir=${WORKSPACE}/${prefix}/style


timeout_exe=${timout_exe:="timeout -s SIGKILL 10m"}
nproc=$(grep processor /proc/cpuinfo|wc -l)
make_opt="-j$(($nproc / 2 + 1))"


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
}
