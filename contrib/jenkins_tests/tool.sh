#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for tool ..."

# Check dependencies
if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
	exit 1
fi

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
    local service="vma"

    rm -rf ${out_log}
    eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"

    if systemctl >/dev/null 2>&1; then
        service=${install_dir}/sbin/${prj_service}
        service_arg=${install_dir}/lib/systemd/system/vma.service

        echo "System has been booted with SystemD" >> ${out_log}
        echo "daemon check output: ${service}" >> ${out_log}

        if [ $(sudo systemd-analyze verify ${service_arg} >>${out_log} 2>&1 || echo $?) ]; then
            ret=1
        fi
        sleep 3
        if [ $(sudo ${service} >>${out_log} 2>&1 || echo $?) ]; then
            ret=1
        fi
        sleep 3
        if [ "0" == "$ret" -a "" == "$(pgrep ${prj_service})" ]; then
            ret=1
        fi
        sudo pkill -9 ${prj_service} >>${out_log} 2>&1
        sleep 3
        if [ "0" == "$ret" -a "" != "$(pgrep ${prj_service})" ]; then
            ret=1
        fi
    fi

    eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"

    echo "$ret"
}

test_id=0
for tool in $tool_list; do
    mkdir -p ${tool_dir}/${tool}
    cd ${tool_dir}/${tool}
    test_id=$((test_id+1))
    test_exec="[ 0 = $(check_daemon "${tool_dir}/${tool}/output.log") ]"
    do_check_result "$test_exec" "$test_id" "$tool" "$tool_tap" "${tool_dir}/tool-${test_id}"
    do_archive "${tool_dir}/${tool}/output.log"
    cd ${tool_dir}
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
