#!/bin/bash -eExl

source $(dirname $0)/globals.sh

check_filter "Checking for tool ..." "off"

cd $WORKSPACE

rm -rf $tool_dir
mkdir -p $tool_dir
cd $tool_dir

tool_list="daemon"

tool_tap=${WORKSPACE}/${prefix}/tool.tap
echo "1..$(echo $tool_list | tr " " "\n" | wc -l)" > $tool_tap

function check_daemon()
{
    local ret=0
    local out_log=$1

    rm -rf ${out_log}
    pkill -9 vmad

    echo "daemon check output: ${install_dir}/sbin/vmad" > ${out_log}
    if [ $(sudo ${install_dir}/etc/init.d/vma start >>${out_log} 2>&1 || echo $?) ]; then
        ret=1
    fi
    if [ "0" == "$ret" -a "" != "$(pgrep vma >>${out_log} 2>&1 || echo $?)" ]; then
        ret=1
    fi
    if [ $(sudo ${install_dir}/etc/init.d/vma status >>${out_log} 2>&1 || echo $?) ]; then
        ret=1
    fi
    if [ $(sudo ${install_dir}/etc/init.d/vma stop >>${out_log} 2>&1 || echo $?) ]; then
        ret=1
    fi
    if [ "0" == "$ret" -a "" = "$(pgrep vma >>${out_log} 2>&1 || echo $?)" ]; then
        ret=1
    fi

    pkill -9 vmad

    echo "$ret"
}

test_id=0
for tool in $tool_list; do
    mkdir -p ${tool_dir}/${tool}
    cd ${tool_dir}/${tool}
    test_id=$((test_id+1))
    test_exec="[ 0 = $(check_daemon "${tool_dir}/${tool}/output.log") ]"
    check_result "$test_exec" "$test_id" "$tool" "$tool_tap"
    cd ${tool_dir}
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
