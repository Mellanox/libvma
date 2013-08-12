#!/bin/sh

#
# configurable parameters
# in order to change parameter add PARAMETER_NAME=VALUE before running the script.
#---------------------------------------------------

PPS=${PPS:-"100 1000 10000 50000 125000 500000 1000000 2000000 max"}
#2048 4096 8192 16384 32768 65536"}
M_SIZE=${M_SIZE:-"12 32 64 128 192 256 512 768 1024 1460"}
FD_NUMBER=${FD_NUMBER:-"1 2 5 10 25 50 100 250 500"}
#1000 25000 5000 10000
LOOP=${LOOP:-"1"}
SOCKPERF=${SOCKPERF:-sockperf}
DURATION=${DURATION:-30}
VMA_SELECT_POLL_VAL=${VMA_SELECT_POLL_VAL:-"-1 0 1000 1000000"}
VMA_RX_POLL_VAL=${VMA_RX_POLL_VAL:-"-1"}
VMA_ENV_FLAGS=${VMA_ENV_FLAGS:-"LD_PRELOAD=libvma.so"}
IOMUX_TYPE=${IOMUX_TYPE:-"s p e"}
SERVER_FLAG=${SERVER_FLAG:-" "}
CLIENT_FLAG=${CLIENT_FLAG:=" "}
TEST=${TEST:-"pp_test tp_test tp_udp_mc_imux_test pp_udp_mc_imux_test pp_tcp_imux_test pp_udp_uc_imux_test"}
#----to do---need to add tcp_imux uc_imux

#taskset -c 4,5,6 env

function run_latancy_test
{
#good for ping pong or under load test
#1 - flags
#2 - env_flags
	env ${2} ${SOCKPERF} ${1} ${CLIENT_FLAG} | egrep "Latency|dropped|std-dev|50.00 =|<MAX>|<MIN>|99.99 =|observations"| awk '{" "}; {if ($3=="Latency") printf "%4.3f ",$5 ; if ($4 ~ "std-dev") printf "%s ",$4; if ($4=="50.00") printf "%4.3f ",$6;if ($4=="99.99") printf "%4.3f ",$6; if ($3=="<MAX>") printf "%4.3f ", $6 ; if ($3=="dropped") printf "%s %s %s ", $6 , $11 , $16; if ($3=="<MIN>") printf "%4.3f ", $6 ; if ($9=="observations") printf "%d ", $3}' >> ${OUT_FILE}
	echo " " >> ${OUT_FILE}
	sleep 1
}

function run_throughput_test
{
	#1 - flags
	#2 - env_flags
	env ${2} ${SOCKPERF} tp ${1} ${CLIENT_FLAG}|egrep "Summary:"| awk '{" "} {if ($3=="Message") printf "%d ",$6 ; if ($3=="BandWidth") printf "%4.3f ",$5}'  >> ${OUT_FILE}
	sleep 1
}

function create_feed_file_uni()
{
	#1 size
	#2 ip
	#3 port
	#4 feed file
	port=$1-1
	let port=port+$3
	until [ $port -lt $3 ]; do
		echo "$2:$port" >> $4
		let port-=1
	done
}
function create_feed_file_tcp()
{
	#1 size
	#2 ip
	#3 port
	#4 feed file

#	echo "T:$2:$3" >> "$4_sr"
	port=$1-1
	let port=port+$3
	until [ $port -lt $3 ]; do
		echo "T:$2:$3" >> $4
		let port-=1
	done
}

# different addresses
function create_feed_file_multi()
{
	#1 size
	#2 feed file
	port=10005
	ip_1=224
	ip_2=4
	ip_3=1
	ip_4=3
	counter=0
	while [ $counter -lt $1 ]; do
		echo "$ip_1.$ip_2.$ip_3.$ip_4:$port" >> $2
		let counter=counter+1
		let port=port+1
		let ip_4=ip_4+1
		if [ $ip_4 = 255 ]; then
			let ip_3=ip_3+1
			ip_4=3
		fi
	done
}

#create_feed_file_uni 10 17.17.17.10 10005 ${FEED_FILE}
#create_feed_file_tcp 10 17.17.17.10 10005 ${FEED_FILE}
#cat "${FEED_FILE}_sr"
#create_feed_file_multi 1000 ${FEED_FILE}



#--------------------------------------TP-MC-IMUX-------------------
function tp_udp_mc_imux_test()
{
	echo "TP measurement UDP MC FEED_FILE" >> ${OUT_FILE}
	echo "VMA_SELECT_POLL Imoux_type Fd_number Message-size PPS Message-rate bandwidth" >> ${OUT_FILE}

	for imoux_type in ${IOMUX_TYPE}; do
		for fd_num in ${FD_NUMBER}; do
			rm ${FEED_FILE}
			create_feed_file_multi ${fd_num} ${FEED_FILE}
			scp "${FEED_FILE}" "${SERVER}:${FEED_FILE}"

			for select_poll in ${VMA_SELECT_POLL_VAL}; do
				ssh $SERVER pkill -f sockperf
				sleep 1
				ssh $SERVER env VMA_RX_POLL="-1" VMA_SELECT_POLL=${select_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -f ${FEED_FILE} -F ${imoux_type} ${SERVER_FLAG} &
				sleep 5
				for pps_num in ${PPS}; do
					for j in ${M_SIZE}; do
						echo -n "${select_poll} ${imoux_type} ${fd_num} $j ${pps_num} " >> ${OUT_FILE}
						run_throughput_test "-m ${j} --mps ${pps_num} -t ${DURATION} -f ${FEED_FILE} -F ${imoux_type}" "VMA_SELECT_POLL=${select_poll} VMA_RX_POLL=-1 ${VMA_ENV_FLAGS}"
					done
				done
			done
		done
		rm ${FEED_FILE}
	done
	echo " " >> ${OUT_FILE}
}

#--------------------------------------TP---------------------
function tp_test()
{
	echo "TP measurement UDP MC" >> ${OUT_FILE}
	echo "VMA_RX_POLL Message-size PPS Message-rate bandwidth" >> ${OUT_FILE}

	for rx_poll in ${VMA_RX_POLL_VAL}; do
		ssh $SERVER pkill -f sockperf
		sleep 1
		ssh $SERVER env VMA_SELECT_POLL="-1" VMA_RX_POLL=${rx_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -i ${SERVER_ADD} ${SERVER_FLAG} &
		sleep 5
		for pps_num in ${PPS}; do
			for j in ${M_SIZE}; do
				echo -n "${rx_poll} $j ${pps_num} " >> ${OUT_FILE}
				run_throughput_test "-m ${j} --mps ${pps_num} -t ${DURATION} -i ${SERVER_ADD}" "VMA_SELECT_POLL=-1 VMA_RX_POLL=${rx_poll} ${VMA_ENV_FLAGS}"
			done
		done
	done
	echo " " >> ${OUT_FILE}
}


#--------------------------------------PP-MC-IMUX-------------------
function pp_udp_mc_imux_test()
{
	echo "Latency Ping-pong measurement UDP MC FEED_FILE" >> ${OUT_FILE}
	echo "VMA_SELECT_POLL Imoux_type Fd_number Message-size PPS std-dev dropped-messages duplicated-messages out-of-order-messages Average_Latency Total_observations Max_Latency 99%_percentile 50%_percentile Min_Latency" >> ${OUT_FILE}

	for imoux_type in ${IOMUX_TYPE}; do
		for fd_num in ${FD_NUMBER}; do
			rm ${FEED_FILE}
			create_feed_file_multi ${fd_num} ${FEED_FILE}
			scp "${FEED_FILE}" "${SERVER}:${FEED_FILE}"

			for select_poll in ${VMA_SELECT_POLL_VAL}; do
				ssh $SERVER pkill -f sockperf
				sleep 1
				ssh $SERVER env VMA_RX_POLL="-1" VMA_SELECT_POLL=${select_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -f ${FEED_FILE} -F ${imoux_type} ${SERVER_FLAG} &
				sleep 5
				for pps_num in ${PPS}; do
					for j in ${M_SIZE}; do
						echo -n "${select_poll} ${imoux_type} ${fd_num} $j ${pps_num} " >> ${OUT_FILE}
						run_latancy_test "pp -m ${j} --mps ${pps_num} -t ${DURATION} -f ${FEED_FILE} -F ${imoux_type}" "VMA_SELECT_POLL=${select_poll} VMA_RX_POLL=-1 ${VMA_ENV_FLAGS}"
					done
				done
			done
		done
		rm ${FEED_FILE}
	done
	echo " " >> ${OUT_FILE}
}

#--------------------------------------PP---------------------
function pp_test()
{
	echo "Latency Ping-pong measurement UDP" >> ${OUT_FILE}
	echo "VMA_RX_POLL Message-size PPS std-dev dropped-messages duplicated-messages out-of-order-messages Average_Latency Total_observations Max_Latency 99%_percentile 50%_percentile Min_Latency" >> ${OUT_FILE}

	for rx_poll in ${VMA_RX_POLL_VAL}; do
		ssh $SERVER pkill -f sockperf
		sleep 1
		ssh $SERVER env VMA_SELECT_POLL="-1" VMA_RX_POLL=${rx_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -i ${SERVER_ADD} ${SERVER_FLAG} &
		sleep 5
		for pps_num in ${PPS}; do
			for j in ${M_SIZE}; do
				echo -n "${rx_poll} $j ${pps_num} " >> ${OUT_FILE}
				run_latancy_test "pp -m ${j} --mps ${pps_num} -t ${DURATION} -i ${SERVER_ADD}" "VMA_SELECT_POLL=-1 VMA_RX_POLL=${rx_poll} ${VMA_ENV_FLAGS}"
			done
		done
	done
	echo " " >> ${OUT_FILE}
}


#--------------------------------------PP-TCP-IMUX-------------------
function pp_tcp_imux_test()
{
	echo "Latency Ping-pong measurement TCP FEED_FILE" >> ${OUT_FILE}
	echo "VMA_SELECT_POLL Imoux_type Fd_number Message-size PPS std-dev dropped-messages duplicated-messages out-of-order-messages Average_Latency Total_observations Max_Latency 99%_percentile 50%_percentile Min_Latency" >> ${OUT_FILE}

	for imoux_type in ${IOMUX_TYPE}; do
		for fd_num in ${FD_NUMBER}; do
			rm ${FEED_FILE}
			create_feed_file_tcp ${fd_num} ${SERVER_ADD} 10005 ${FEED_FILE}
			scp "${FEED_FILE}" "${SERVER}:${FEED_FILE}"

			for select_poll in ${VMA_SELECT_POLL_VAL}; do
				ssh $SERVER pkill -f sockperf
				sleep 1
				ssh $SERVER env VMA_RX_POLL="-1" VMA_SELECT_POLL=${select_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -f ${FEED_FILE} -F ${imoux_type} ${SERVER_FLAG} &
				sleep 5
				for pps_num in ${PPS}; do
					for j in ${M_SIZE}; do
						echo -n "${select_poll} ${imoux_type} ${fd_num} $j ${pps_num} " >> ${OUT_FILE}
						run_latancy_test "pp -m ${j} --mps ${pps_num} -t ${DURATION} -f ${FEED_FILE} -F ${imoux_type}" "VMA_SELECT_POLL=${select_poll} VMA_RX_POLL=-1 ${VMA_ENV_FLAGS}"
					done
				done
			done
		done
		rm ${FEED_FILE}
	done
	echo " " >> ${OUT_FILE}
}


#--------------------------------------PP-UDP-UC-IMUX-------------------
function pp_udp_uc_imux_test()
{
	echo "Latency Ping-pong measurement UDP UC FEED_FILE" >> ${OUT_FILE}
	echo "VMA_SELECT_POLL Imoux_type Fd_number Message-size PPS std-dev dropped-messages duplicated-messages out-of-order-messages Average_Latency Total_observations Max_Latency 99%_percentile 50%_percentile Min_Latency" >> ${OUT_FILE}

	for imoux_type in ${IOMUX_TYPE}; do
		for fd_num in ${FD_NUMBER}; do
			rm ${FEED_FILE}
			create_feed_file_uni ${fd_num} ${SERVER_ADD} 10005 ${FEED_FILE}
			scp "${FEED_FILE}" "${SERVER}:${FEED_FILE}"

			for select_poll in ${VMA_SELECT_POLL_VAL}; do
				ssh $SERVER pkill -f sockperf
				sleep 1
				ssh $SERVER env VMA_RX_POLL="-1" VMA_SELECT_POLL=${select_poll} ${VMA_ENV_FLAGS} ${SOCKPERF} server -f ${FEED_FILE} -F ${imoux_type} ${SERVER_FLAG} &
				sleep 5
				for pps_num in ${PPS}; do
					for j in ${M_SIZE}; do
						echo -n "${select_poll} ${imoux_type} ${fd_num} $j ${pps_num} " >> ${OUT_FILE}
						run_latancy_test "pp -m ${j} --mps ${pps_num} -t ${DURATION} -f ${FEED_FILE} -F ${imoux_type}" "VMA_SELECT_POLL=${select_poll} VMA_RX_POLL=-1 ${VMA_ENV_FLAGS}"
					done
				done
			done
		done
		rm ${FEED_FILE}
	done
	echo " " >> ${OUT_FILE}
}

#-----------------------------------main-----------------------------------------------

echo ""
echo "Usahge: $0 <name of remote host> <ip of remote host> <output_file.csv>"
echo ""
echo "to change script parameter write: >> PARAMETER_NAME=VALUE $0"
echo ""
echo "chopse test - TEST=test_name $0 ..."
for start_test in ${TEST}; do
	echo $start_test
done
echo ""
echo "script parameter:"
echo "PPS - value:              	${PPS}"
echo "M_SIZE - value:               ${M_SIZE}"
echo "FD_NUMBER - value:            ${FD_NUMBER}"
echo "LOOP - value:                 ${LOOP}"
echo "SOCKPERF - value:             ${SOCKPERF}"
echo "DURATION - value:             ${DURATION}"
echo "VMA_SELECT_POLL_VAL - value:  ${VMA_SELECT_POLL_VAL}"
echo "SERVER_FLAG - value:			${SERVER_FLAG}"
echo "CLIENT_FLAG - value:			${CLIENT_FLAG}"
echo "VMA_RX_POLL_VAL - value:      ${VMA_RX_POLL_VAL}"
echo "VMA_ENV_FLAGS - value:        ${VMA_ENV_FLAGS}"
echo "IOMUX_TYPE - value:			${IOMUX_TYPE}"

if [ $# -ne 3 ]; then
	exit 
else
	#echo "config	print all configurable parameters"
	echo "output will be print to ${3}"
fi

SERVER=${1}
SERVER_ADD=${2}
OUT_FILE=${3}
FEED_FILE="/tmp/feed_file"

for start_test in ${TEST}; do
	$start_test
done

exit
