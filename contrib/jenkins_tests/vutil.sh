#!/bin/bash

HOST=${HOSTNAME}

server_success_msgs="'Test end', 'interrupted by', 'exit'"
server_failure_msgs="'Segmentation fault', 'Assertion', 'ERROR'"

client_success_ul_msgs="'Test ended', 'Summary: Latency is'"
client_success_pp_msgs="'Test ended', 'Summary: Latency is'"
client_success_tp_msgs="'Test ended', 'Summary: Message Rate'"
client_failure_msgs="'Segmentation fault', 'Assertion', 'ERROR', 'server down'"

dlm=~

############
ts_tcp_pp()
############
{
	local sperf=$1 local ipaddr=$2 local opts=$3
	#1
	ts_tcp_pp_tc1="#1 - ping-pong w/o arguments"${dlm}
	ts_tcp_pp_tc1+="${sperf} pp -i ${ipaddr} --tcp ${opts}"${dlm}
	ts_tcp_pp_tc1+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc1+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc1+="client_success='Test ended', 'Summary: Latency is', 'Warmup stage (sending a few dummy messages)...'"${dlm}
	ts_tcp_pp_tc1+=${client_failure_msgs}
	#2
	ts_tcp_pp_tc2="#2 - ping-pong option --dontwarmup"${dlm}
	ts_tcp_pp_tc2+="${sperf} pp -i ${ipaddr} --tcp --dontwarmup ${opts}"${dlm}
	ts_tcp_pp_tc2+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc2+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc2+=${client_success_pp_msgs}${dlm}
	ts_tcp_pp_tc2+="client_failure='Segmentation fault', 'Assertion', 'ERROR', 'server down', 'Warmup stage (sending a few dummy messages)...'"
	#3
	ts_tcp_pp_tc3="#3 - ping-pong option -b10"${dlm}
	ts_tcp_pp_tc3+="${sperf} pp -i ${ipaddr} --tcp -b10 ${opts}"${dlm}
	ts_tcp_pp_tc3+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc3+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc3+="client_success='Test ended', 'Summary: Latency of burst of 10 messages'"${dlm}
	ts_tcp_pp_tc3+=${client_failure_msgs}
	#4
	ts_tcp_pp_tc4="#4 - ping-pong option -b100"${dlm}
	ts_tcp_pp_tc4+="${sperf} pp -i ${ipaddr} --tcp -b100 ${opts}"${dlm}
	ts_tcp_pp_tc4+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc4+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc4+="client_success='Test ended', 'Summary: Latency of burst of 100 messages'"${dlm}
	ts_tcp_pp_tc4+=${client_failure_msgs}
	#5
	ts_tcp_pp_tc5="#5 - ping-pong option -b1000"${dlm}
	ts_tcp_pp_tc5+="${sperf} pp -i ${ipaddr} --tcp -b1000 ${opts}"${dlm}
	ts_tcp_pp_tc5+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc5+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc5+="client_success='Test ended', 'Summary: Latency of burst of 1000 messages'"${dlm}
	ts_tcp_pp_tc5+=${client_failure_msgs}
	#6
	ts_tcp_pp_tc6="#6 - ping-pong option -t10"${dlm}
	ts_tcp_pp_tc6+="${sperf} pp -i ${ipaddr} --tcp -t10 ${opts}"${dlm}
	ts_tcp_pp_tc6+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc6+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc6+="client_success='Test ended', 'Summary: Latency is', 'RunTime=10'"${dlm}
	ts_tcp_pp_tc6+=${client_failure_msgs}
	#7
	ts_tcp_pp_tc7="#7 - ping-pong option -t30"${dlm}
	ts_tcp_pp_tc7+="${sperf} pp -i ${ipaddr} --tcp -t30 ${opts}"${dlm}
	ts_tcp_pp_tc7+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc7+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc7+="client_success='Test ended', 'Summary: Latency is', 'RunTime=30'"${dlm}
	ts_tcp_pp_tc7+=${client_failure_msgs}
	#8
	ts_tcp_pp_tc8="#8 - ping-pong option -m32"${dlm}
	ts_tcp_pp_tc8+="${sperf} pp -i ${ipaddr} --tcp -m32 ${opts}"${dlm}
	ts_tcp_pp_tc8+=${server_success_mss}${dlm}
	ts_tcp_pp_tc8+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc8+=${client_success_pp_msgs}${dlm}
	ts_tcp_pp_tc8+=${client_failure_msgs}
	#9
	ts_tcp_pp_tc9="#9 - ping-pong option -m4096"${dlm}
	ts_tcp_pp_tc9+="${sperf} pp -i ${ipaddr} --tcp -m4096 ${opts}"${dlm}
	ts_tcp_pp_tc9+=${server_success_msgs}${dlm}
	ts_tcp_pp_tc9+=${server_failure_msgs}${dlm}
	ts_tcp_pp_tc9+=${client_success_pp_msgs}${dlm}
	ts_tcp_pp_tc9+=${client_failure_msgs}
}

############
ts_tcp_tp()
############
{
	local sperf=$1 local ipaddr=$2 local opts=$3
	#1
	ts_tcp_tp_tc1="#1 - throughput w/o arguments"${dlm}
	ts_tcp_tp_tc1+="${sperf} tp -i ${ipaddr} --tcp ${opts}"${dlm}
	ts_tcp_tp_tc1+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc1+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc1+="client_success='Test ended', 'Summary: Message Rate', 'Warmup stage (sending a few dummy messages)...'"${dlm}
	ts_tcp_tp_tc1+=${client_failure_msgs}
	#2
	ts_tcp_tp_tc2="#2 - throughput option --dontwarmup"${dlm}
	ts_tcp_tp_tc2+="${sperf} tp -i ${ipaddr} --tcp --dontwarmup ${opts}"${dlm}
	ts_tcp_tp_tc2+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc2+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc2+="client_success='Test ended', 'Summary: Message Rate'"${dlm}
	ts_tcp_tp_tc2+="client_failure='Segmentation fault', 'Assertion', 'ERROR', 'server down', 'Warmup stage (sending a few dummy messages)...'"${dlm}
	#3
	ts_tcp_tp_tc3="#3 - throughput option -b10"${dlm}
	ts_tcp_tp_tc3+="${sperf} tp -i ${ipaddr} --tcp -b10 ${opts}"${dlm}
	ts_tcp_tp_tc3+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc3+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc3+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc3+=${client_failure_msgs}
	#4
	ts_tcp_tp_tc4="#4 - throughput option -b100"${dlm}
	ts_tcp_tp_tc4+="${sperf} tp -i ${ipaddr} --tcp -b100 ${opts}"${dlm}
	ts_tcp_tp_tc4+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc4+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc4+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc4+=${client_failure_msgs}
	#5
	ts_tcp_tp_tc5="#5 - throughput option -b1000"${dlm}
	ts_tcp_tp_tc5+="${sperf} tp -i ${ipaddr} --tcp -b1000 ${opts}"${dlm}
	ts_tcp_tp_tc5+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc5+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc5+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc5+=${client_failure_msgs}
	#6
	ts_tcp_tp_tc6="#6 - throughput option -t10"${dlm}
	ts_tcp_tp_tc6+="${sperf} tp -i ${ipaddr} --tcp -t10 ${opts}"${dlm}
	ts_tcp_tp_tc6+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc6+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc6+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc6+=${client_failure_msgs}
	#7
	ts_tcp_tp_tc7="#7 - throughput option -t30"${dlm}
	ts_tcp_tp_tc7+="${sperf} tp -i ${ipaddr} --tcp -t30 ${opts}"${dlm}
	ts_tcp_tp_tc7+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc7+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc7+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc7+=${client_failure_msgs}
	#8
	ts_tcp_tp_tc8="#8 - throughput option -m32"${dlm}
	ts_tcp_tp_tc8+="${sperf} tp -i ${ipaddr} --tcp -m32 ${opts}"${dlm}
	ts_tcp_tp_tc8+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc8+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc8+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc8+=${client_failure_msgs}
	#9
	ts_tcp_tp_tc9="#9 - throughput option -m4096"${dlm}
	ts_tcp_tp_tc9+="${sperf} tp -i ${ipaddr} --tcp -m4096 ${opts}"${dlm}
	ts_tcp_tp_tc9+=${server_success_msgs}${dlm}
	ts_tcp_tp_tc9+=${server_failure_msgs}${dlm}
	ts_tcp_tp_tc9+=${client_success_tp_msgs}${dlm}
	ts_tcp_tp_tc9+=${client_failure_msgs}
}

############
ts_tcp_ul()
############
{
	local sperf=$1 local ipaddr=$2 local opts=$3
	#1
	ts_tcp_ul_tc1="#1 - under-load w/o arguments"${dlm}
	ts_tcp_ul_tc1+="${sperf} ul -i ${ipaddr} --tcp ${opts}"${dlm}
	ts_tcp_ul_tc1+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc1+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc1+="client_success='Test ended', 'Summary: Latency is', 'Warmup stage (sending a few dummy messages)...'"${dlm}
	ts_tcp_ul_tc1+=${client_failure_msgs}
	#2
	ts_tcp_ul_tc2="#2 - under-load option --dontwarmup"${dlm}
	ts_tcp_ul_tc2+="${sperf} ul -i ${ipaddr} --tcp --dontwarmup ${opts}"${dlm}
	ts_tcp_ul_tc2+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc2+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc2+=${client_success_ul_msgs}${dlm}
	ts_tcp_ul_tc2+="client_failure='Segmentation fault', 'Assertion', 'ERROR', 'server down', 'Warmup stage (sending a few dummy messages)...'"${dlm}
	#3
	ts_tcp_ul_tc3="#3 - under-load option -b10"${dlm}
	ts_tcp_ul_tc3+="${sperf} ul -i ${ipaddr} --tcp -b10 ${opts}"${dlm}
	ts_tcp_ul_tc3+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc3+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc3+="client_success='Test ended', 'Summary: Latency of burst of 10 messages'"${dlm}
	ts_tcp_ul_tc3+=${client_failure_msgs}
	#4
	ts_tcp_ul_tc4="#4 - under-load option -b100"${dlm}
	ts_tcp_ul_tc4+="${sperf} ul -i ${ipaddr} --tcp -b100 ${opts}"${dlm}
	ts_tcp_ul_tc4+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc4+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc4+="client_success='Test ended', 'Summary: Latency of burst of 100 messages'"${dlm}
	ts_tcp_ul_tc4+=${client_failure_msgs}
	#5
	ts_tcp_ul_tc5="#5 - under-load option -b1000"${dlm}
	ts_tcp_ul_tc5+="${sperf} ul -i ${ipaddr} --tcp -b1000 ${opts}"${dlm}
	ts_tcp_ul_tc5+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc5+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc5+="client_success='Test ended', 'Summary: Latency of burst of 1000 messages'"${dlm}
	ts_tcp_ul_tc5+=${client_failure_msgs}
	#6
	ts_tcp_ul_tc6="#6 - under-load option -t10"${dlm}
	ts_tcp_ul_tc6+="${sperf} ul -i ${ipaddr} --tcp -t10 ${opts}"${dlm}
	ts_tcp_ul_tc6+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc6+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc6+="client_success='Test ended', 'Summary: Latency is', 'RunTime=10'"${dlm}
	ts_tcp_ul_tc6+=${client_failure_msgs}
	#7
	ts_tcp_ul_tc7="#7 - under-load option -t30"${dlm}
	ts_tcp_ul_tc7+="${sperf} ul -i ${ipaddr} --tcp -t10 ${opts}"${dlm}
	ts_tcp_ul_tc7+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc7+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc7+="client_success='Test ended', 'Summary: Latency is', 'RunTime=30'"${dlm}
	ts_tcp_ul_tc7+=${client_failure_msgs}
	#8
	ts_tcp_ul_tc8="#8 - under-load option -m32"${dlm}
	ts_tcp_ul_tc8+="${sperf} ul -i ${ipaddr} --tcp -m32 ${opts}"${dlm}
	ts_tcp_ul_tc8+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc8+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc8+=${client_success_ul_msgs}${dlm}
	ts_tcp_ul_tc8+=${client_failure_msgs}
	#9
	ts_tcp_ul_tc9="#9 - under-load option -m4096"${dlm}
	ts_tcp_ul_tc9+="${sperf} ul -i ${ipaddr} --tcp -m4096 ${opts}"${dlm}
	ts_tcp_ul_tc9+=${server_success_msgs}${dlm}
	ts_tcp_ul_tc9+=${server_failure_msgs}${dlm}
	ts_tcp_ul_tc9+=${client_success_ul_msgs}${dlm}
	ts_tcp_ul_tc9+=${client_failure_msgs}
}

server_pid=""

check_message()
{
	oifs="${IFS}"
	IFS=',' read -r -a array <<< $(echo ${1##*=})
	IFS="${oifs}"
	for im in "${array[@]}" ; do
		im=$(echo ${im} | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^'\''*//' -e 's/'\''*$//')
		[[ "${2}" =~ .*"${im}".* ]] && echo "${im}"
	done
}

start_server()
{
	local env=$1 local ipaddr=$2 local port=$3 local proto=$4 local log_file=$5 local tsnv=$6

	server_cmd="env ${env} ${SERVER_DIR}/sockperf sr -i ${ipaddr} -p ${port} --tcp --load-vma=${SERVER_DIR}/${prj_lib}"

	server_pid=$(ssh root@${ipaddr} ps -ax | grep -i sockperf | grep ${port} | awk '{print $1}')
	[ ! -z "${server_pid}" ] && ssh root@${ipaddr} kill -9 ${server_pid}

	tmp=$(mktemp)
	ssh root@${ipaddr} "${server_cmd}" >> ${tmp} 2>&1 >> ${tmp} & 
	sleep 5
	res=$(cat ${tmp})
	rm -f ${tmp}
	echo "${res}"
	echo "${res}" >> "${log_file}"
	server_fail=$(echo ${tsnv} | awk -F${dlm} '{ print $4 }')
	local chk_res=$(check_message "${server_fail}" "${res}")
	if [ ! -z "${chk_res}" ] ; then
		echo ">> FAIL ${server_cmd}"
	else
		server_success=$(echo ${tsnv} | awk -F${dlm} '{ print $3 }')
		check_message "${server_success}" "${res}"
		echo ">> PASS ${server_cmd}"
	fi
	server_pid=$(tac ${log_file} | grep -m 1 -oP '(?<=Pid: ).*')
}

stop_server()
{
	local ipaddr=$1 local pid=$2 local log_file=$3
	res=$(ssh root@${ipaddr} kill -9 ${pid} >> ${log_file} 2>&1)
	echo ">> Server process ${pid} has finished" >> "${log_file}"
}

log_st()
{
	echo "${2}" >> "${1}"
}

perform_ts()
{
	ts=$1 ns=$2 ne=$3 app_env=$4 sperf=$5 ipaddr=$6 port=$7 opts=$8 log_file=$9
	log_st_file="${log_file%.*}.dump"
	log_st_file=${log_st_file##*/}
	# init ts with params
	ts_${ts} ${sperf} ${ipaddr} ${opts}

	log_st "${log_st_file}" "***********"
	for ((i = ${ns}; i <= ${ne}; i++)); do
		tsn="ts_${ts}_tc${i}"
		if [ ! -z  "${!tsn}" ] ; then
			tsnv=${!tsn}
			start_server "${app_env}" "${ipaddr}" ${port} "--tcp" "${log_file}" "${tsnv}"    

			if [ -z "${dbg_srv}" ] ; then
				name=$(echo ${tsnv} | awk -F${dlm} '{ print $1 }') 
				echo ${name}
				st=$(echo ${tsnv} | awk -F${dlm} '{ print $2 }') 
				cmd_test="env ${app_env} ${st} -p ${port}"
				local res=$(${cmd_test} 2>&1)
				echo "${res}" 
				echo "${res}" >> "${log_file}"
				client_fail=$(echo ${tsnv} | awk -F${dlm} '{ print $6 }')
				chk_res=$(check_message "${client_fail}" "${res}")
				if [ ! -z "${chk_res}" ] ; then
					test_st="FAIL"
				else
					client_success=$(echo ${tcnv} | awk -F${dlm} '{ print $5 }')
					check_message "${client_success}" "${chk_res}"
					test_st="PASS"
				fi
				echo ">> ${test_st} ${cmd_test}"
				log_st "${log_st_file}" "${test_st}    ${ts}    tc${i}        ${name}"
			fi
			stop_server "${ipaddr}" "${server_pid}" "${log_file}"
		else
			break
		fi 
	done
	log_st "${log_st_file}" "***********"
}

prepare_perform_ts()
{
	app_env=$1 app=$2 app_args=$3 task=$4 target=$5 port=$6 log_file=$7
	ts=${task%:*} ; ts=${ts//-/_}
	num_tests=${TASK#*[} ; num_tests=${num_tests%]*}
	start_num=${num_tests%-*}
	end_num=${num_tests#*-}

	HOST=${HOST%%.*}
	[ -z "${SERVER_DIR}" ] && SERVER_DIR="/tmp/sockperf_exec_${HOST}" 

	if [ ! -z "${SRV_OPS}" ] ; then
	if [ "${SRV_OPS}" == "start" ] ; then 
		start_server "${app_env}" ${target} ${port} "--tcp" "${log_file}"
		stop_server ${target} "${server_pid}" "${log_file}"
	fi
	[ "${SRV_OPS}" == "stop" ]  && stop_server "${target}" "${server_pid}" "${log_file}"
	return
	fi
	perform_ts ${ts} ${start_num} ${end_num} "${app_env}" "${app}" ${target} ${port} "${app_args}" "${log_file}"
}

usage()
{
cat << eOm
	usage:$0 -a app [-x|--app-arg 'args'] [-e|--app-env 'vars'] [-t|--task test] [-s|--target address] [-p|--port N] 
			[-l|--log fname] [--server-dir dir] [--dr] [-h]
eOm
	exit 0
}

[ $# -eq 0 ] && usage

OPTS=$(getopt -o ha:x:e:t:s:p:l: -l app:,app-arg:,app-env:,task:,target:,port:,log:,server-dir:,srv-start,srv-stop,help -- "$@")
[[ $? -ne 0 ]] && usage
eval set -- "${OPTS}"

while true ; do
	case "$1" in
	-a|--app)
		APP="$2"
		shift 2
		;;
	-x|--app-arg)
		APP_ARGS="$2"
		shift 2
		;;
	-e|--app-env)
		APP_ENV="$2"
		shift 2
		;;
	-t|--task)
		TASK="$2"
		shift 2
		;;
	-s|--target)
		[[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && TARGET="$2"
		shift 2
		;;
	-p|--port)
		[[ "$2" =~ ^-?[0-9]+$ ]] && PORT="$2"
		shift 2
		;;
	-l|--log)
		LOG_FILE="$2"
		shift 2
		;;
	--srv-start|--srv-stop)
		SRV_OPS=${1##*-}
		shift 1
		;;
	--dr)
		DRY_RUN=1
		shift 1
		;;
	--srv-ops)
		SRV_OPS="$2"
		shift 2
		;;
	-h|--help)
		shift 1
		;;
	--)
		shift
		break
		;;
	*)
		usage
		;;
	esac
done

if [ ! -z "${APP}" ] ; then
	prepare_perform_ts "${APP_ENV}" "${APP}" "${APP_ARGS}" "${TASK}" "${TARGET}" "${PORT}" "${LOG_FILE}"
else
	usage
fi

#</vutil.sh>

