#!/bin/bash

# Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of Mellanox Technologies Ltd.
# (the "Company") and all right, title, and interest in and to the software product,
# including all associated intellectual property rights, are and shall
# remain exclusively with the Company.
#
# This software is made available under either the GPL v2 license or a commercial license.
# If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.

#configurable parameters
#---------------------------------------------------
MC_GROUP=224.18.7.81
PORT=5001
DURATION=10    #in seconds
BW=10G
OUTPUT_FILES_PATH="./"
INTERFACE="ib0"
OVER_VMA="yes" #[yes | not]
UDP_LAT_MSG_SIZE=(2 8 20 60 100 200 400 800 1470 2000 3000 4000 8000 16000 32000 65000)                        #Bytes
UDP_LAT_BURST_SIZE=(2 5 10 25 50 100 250 500 1000 2500 5000 10000 16000 25000 50000 100000 250000 500000)      #Bytes
IPERF_MSG_SIZE=(12 20 60 100 200 400 800 1470 2000 3000 4000 8000 16000 32000 65000)                            #Bytes
MC_GROUP_SIZES=(1 10 20 30 50 60 64 65 70 80 90 100 150 200)

#path
#----------------------------------------------------
UDP_LAT_APP=${UDP_LAT_PATH:-udp_lat}
VMA_LIB=${VMA_PATH:-libvma.so}

#####################################################
#vma default values
#---------------------------------------------------
DEFAULT_VMA_IGMP_ENABLE=1
DEFAULT_VMA_RX_POLL_OS_RATIO=10
DEFAULT_VMA_RX_SKIP_OS=100
DEFAULT_VMA_SELECT_POLL=0
DEFAULT_VMA_RX_BUFS=200000
DEFAULT_VMA_THREAD_MODE=1
DEFAULT_VMA_RX_WRE=16000
DEFAULT_VMA_SELECT_POLL=0
DEFAULT_VMA_SELECT_SKIP_OS=4
DEFAULT_VMA_HUGETLB=1
#####################################################
#initial vma values in test  
#---------------------------------------------------
VMA_IGMP_ENABLE=0
VMA_RX_POLL_OS_RATIO=$DEFAULT_VMA_RX_POLL_OS_RATIO
VMA_RX_SKIP_OS=$DEFAULT_VMA_RX_SKIP_OS
VMA_RX_BUFS=$DEFAULT_VMA_RX_BUFS
VMA_RX_WRE=$DEFAULT_VMA_RX_WRE
VMA_SELECT_POLL=$DEFAULT_VMA_SELECT_POLL
VMA_SELECT_SKIP_OS=$DEFAULT_VMA_SELECT_SKIP_OS
VMA_THREAD_MODE=$DEFAULT_VMA_THREAD_MODE
VMA_HUGETLB=$DEFAULT_VMA_HUGETLB
###########################################################################
#other								Optimal Val		
#--------------------------------------------------------------------------
VMA_SELECT_POLL_MAX_VAL=1000000		
VMA_RX_BUFS_MAX_VAL=200000
VMA_IOMUX_RX_WRE=$DEFAULT_VMA_RX_WRE				#3200
VMA_IOMUX_RX_SKIP_OS=$DEFAULT_VMA_RX_SKIP_OS			#1000
VMA_IOMUX_SELECT_SKIP_OS=$DEFAULT_VMA_SELECT_SKIP_OS		#500
VMA_IOMUX_HUGETLB=$DEFAULT_VMA_HUGETLB				#1
MAX_UDP_LAT_MSG_SIZE=65000
ACTIVITY=100000
RX_FRAMES_4_UDP_LAT=1
RX_FRAMES_4_IPERF=16
RX_USEC_4_LAT_TEST=0
RX_USEC_4_BW_TEST=10
UMCAST_VAL=1
DST_NET="224.0.0.0"
DST_MASK="240.0.0.0"
VMA="vma"
TMP_DIR=/tmp
TMP_FILE="$TMP_DIR/perf_tmp"
ERROR_MESSAGE="!!! Test Failed !!!"
ERORR_PROMT="vma_perf_envelope:"
ERROR_RESULT="null"
PREFIX=""
REM_HOST_IP=$1
COMMAND_REDIRECT="1>$TMP_FILE 2>$TMP_FILE.err"
TRUE=1
FALSE=0
SUCCSESS=1
BLOCK_FILE="$TMP_DIR/vma_tests_block_file"
script_name=$(basename $0)
user_name=`whoami`
user_id=`who -am | tr " " "\n" | tail -1 | tr -d "(|)"`
SUPER_USR=root
#####################################################

function run_iperf_with_diff_msg_len
{
        wait_time=0 
	local size_arr_len=${#IPERF_MSG_SIZE[*]}
	
 	prepare_iperf_headlines 
	save_coalesce_params
	update_coalesce_4_tr_test
	append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
	
	print_message "============================>IPERF<============================" "$log_file"    
        
	for((i=0; $i < $size_arr_len; i=$((i=$i+1)))) 
	do
		curr_msg_size=${IPERF_MSG_SIZE[$i]}
		iperf_cycle
		parse_iperf_test_results
	done
	recreate_coalesce_params
	clean_after_iperf
	tests_finish
}

function iperf_cycle
{
	print_cycle_info  $curr_msg_size  message
	killall iperf  >& /dev/null
	ssh $REM_HOST_IP killall iperf >& /dev/null
	iperf_command_line_srv=${PREFIX}"iperf -usB $MC_GROUP -p $PORT -l $curr_msg_size -i 1 -f M" 
	iperf_command_line_clt=${PREFIX}"iperf -uc $MC_GROUP -p $PORT -l $curr_msg_size -t $DURATION -b $BW -i 1 -f M"
	(echo "${SRV_CMMND_LINE_PREF}$iperf_command_line_srv" | tee -a $log_file) >& /dev/null 
	(ssh $REM_HOST_IP "echo ${CLT_CMMND_LINE_PREF}$iperf_command_line_clt|tee -a $TMP_DIR/$log_file.tmp")>& /dev/null
	(ssh $REM_HOST_IP "sleep 10;$iperf_command_line_clt 2>&1 | tee >> $TMP_DIR/$log_file.tmp " &)
	wait_time=$DURATION
        let "wait_time += 20"
        (sleep $wait_time;killall -9 iperf >& /dev/null)| (eval "$iperf_command_line_srv 2>&1 | tee >> $TMP_FILE") 		     	
}

function run_udp_lat_with_diff_msg_len
{
	prepare_udp_lat_headlines
	save_coalesce_params
	update_coalesce_4_udp_lat
	append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
	print_message "===========================>UDP_LAT<==========================" "$log_file"    
        
	local size_arr_len=${#UDP_LAT_MSG_SIZE[*]}
        upd_lat_command_line_srv=${PREFIX}"${UDP_LAT_APP} -s -i $MC_GROUP -p $PORT -m $MAX_UDP_LAT_MSG_SIZE"
        (echo ${SRV_CMMND_LINE_PREF}$upd_lat_command_line_srv | tee -a $log_file) >& /dev/null
        (eval "$upd_lat_command_line_srv 2>&1 | tee >> $log_file &") 

	for((i=0; $i < $size_arr_len; i=$((i=$i+1))))
	do
		curr_msg_size=${UDP_LAT_MSG_SIZE[$i]}
		udp_lat_cycle 
		sleep 5
		parse_udp_lat_test_results  "${UDP_LAT_MSG_SIZE[$i]}" 	              
	done
    	clean_after_udp_lat
	recreate_coalesce_params 
	tests_finish
}

function run_udp_lat_tx_bw_with_diff_msg_len
{
        prepare_udp_lat_tx_bw_headlines
        save_coalesce_params
        update_coalesce_4_tr_test
        append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
        print_message "========================>UDP_LAT TX BW<=======================" "$log_file"

        local size_arr_len=${#UDP_LAT_MSG_SIZE[*]}

        for((i=0; $i < $size_arr_len; i=$((i=$i+1))))
        do
                curr_msg_size=${UDP_LAT_MSG_SIZE[$i]}
                udp_lat_tx_bw_cycle
                sleep 5
                parse_udp_lat_tx_bw_test_results "${UDP_LAT_MSG_SIZE[$i]}"
        done
        clean_after_udp_lat
        recreate_coalesce_params
        tests_finish
}

function run_udp_lat_bw_with_diff_msg_len
{
        prepare_udp_lat_bw_headlines
        save_coalesce_params
        update_coalesce_4_tr_test
        append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
        print_message "========================>UDP_LAT BW<=========================" "$log_file"

        local size_arr_len=${#UDP_LAT_MSG_SIZE[*]}

        for((i=0; $i < $size_arr_len; i=$((i=$i+1))))
	do
                curr_msg_size=${UDP_LAT_MSG_SIZE[$i]}
                udp_lat_bw_cycle
                sleep 5
                parse_udp_lat_bw_test_results "${UDP_LAT_MSG_SIZE[$i]}"
	done
	clean_after_udp_lat
	recreate_coalesce_params
	tests_finish
}

function run_udp_lat_with_diff_burst_size
{
	prepare_udp_lat_sending_bursts_headlines
	save_coalesce_params
	update_coalesce_4_udp_lat
	append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
       	print_message "===================>UDP_LAT SENDING BURSTS<===================" "$log_file"
	local size_arr_len=${#UDP_LAT_BURST_SIZE[*]}
	local initial_rx_buffs_val=$VMA_RX_BUFS
	VMA_RX_BUFS=$VMA_RX_BUFS_MAX_VAL
	update_command_prefix
        upd_lat_command_line_srv=${PREFIX}"${UDP_LAT_APP} -s -i $MC_GROUP -p $PORT -m $MAX_UDP_LAT_MSG_SIZE"
        (echo ${SRV_CMMND_LINE_PREF}$upd_lat_command_line_srv | tee -a $log_file) >& /dev/null
        (eval "$upd_lat_command_line_srv 2>&1 | tee >> $log_file &") 

	for((i=0; $i < $size_arr_len; i=$((i=$i+1))))
	do
		curr_burst_size=${UDP_LAT_BURST_SIZE[$i]}
		udp_lat_sending_bursts_cycle 
		sleep 5
		parse_udp_lat_test_results  "${UDP_LAT_BURST_SIZE[$i]}" 	              
	done
	VMA_RX_BUFS=$initial_rx_buffs_val
	update_command_prefix
    	clean_after_udp_lat
	recreate_coalesce_params 
	tests_finish
}

function run_udp_lat_using_select_epoll_poll_with_zero_polling
{	
	local vma_select_poll_old=$VMA_SELECT_POLL
	vma_select_poll_info=""
       	save_coalesce_params
	update_coalesce_4_udp_lat
	append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
        	print_message "===============>UDP_LAT Using Select/Poll/Epoll<==============" "$log_file"
	if [[ "$OVER_VMA" = yes ]]; then
		vma_select_poll_info="With VMA_SELECT_POLL=0"
		print_message "|----------------------------------|" "$log_file"
		print_message "|VMA_SELECT_POLL=0" "$log_file"
		print_message "|----------------------------------|" "$log_file"
	fi
	run_udp_lat_using_select_epoll_poll_helper "$vma_select_poll_info"
	recreate_coalesce_params 
	tests_finish	
}

function save_shmem_prop
{
	eval "save_local_hugetlb=`cat /proc/sys/vm/nr_hugepages 2>/dev/null`;save_local_shmax=`cat /proc/sys/kernel/shmmax 2>/dev/null`"
        eval "save_remote_hugetlb=`ssh  $REM_HOST_IP 'cat /proc/sys/vm/nr_hugepages 2>/dev/null'`;save_remote_shmax=`ssh $REM_HOST_IP 'cat /proc/sys/kernel/shmmax 2>/dev/null'`"
}

function recreate_mem_prop
{
	echo "" >> "$TMP_DIR/$log_file.post"
        echo "================>Recreate number of huge pages <==============" >> "$TMP_DIR/$log_file.post"
        command="echo $save_local_hugetlb > /proc/sys/kernel/shmmax;echo $save_local_shmax > /proc/sys/vm/nr_hugepages"
        (echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
        eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.post"
	command="echo $save_remote_hugetlb > /proc/sys/kernel/shmmax;echo $save_remote_shmax > /proc/sys/vm/nr_hugepages"
        (echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
        eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $TMP_DIR/$log_file.post"
        print_huge_tlb_info "${TMP_DIR}/${log_file}.post"
	eval "cat $TMP_DIR/$log_file.post" | tee -a $log_file >& /dev/null
        clean
}

function print_huge_tlb_info 
{
	local file=$1
	echo "" >> "$file"
        echo "=======================>Huge pages info<======================" >> "$file"
        command="cat /proc/meminfo |  grep -i HugePage"
        (echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$file") >& /dev/null
        eval "$command 2>&1 | tee >> $file"
        (echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$file") >& /dev/null
        eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $file"
}

function increase_number_of_hugetlb
{
	print_huge_tlb_info "${TMP_DIR}/${log_file}.prep"
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "================>Update number of huge pages <================" >> "$TMP_DIR/$log_file.prep"
	command="echo 1000000000 > /proc/sys/kernel/shmmax;echo 400 > /proc/sys/vm/nr_hugepages;cat /proc/meminfo |  grep -i HugePage"
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
 	eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.prep"	
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $TMP_DIR/$log_file.prep"
	eval "cat $TMP_DIR/$log_file.prep" | tee -a $log_file >& /dev/null
	clean
}

function run_udp_lat_using_select_epoll_poll_with_full_polling_vma_only
{	
	if [[ "$OVER_VMA" = yes ]]; then
		local vma_select_poll_old=$VMA_SELECT_POLL
		local vma_select_skip_os_old=$VMA_SELECT_SKIP_OS
		local vma_rx_skip_os_old=$VMA_RX_SKIP_OS
		local vma_rx_wre_old=$VMA_RX_WRE
                local vma_hugetlb_old=$VMA_HUGETLB
		
		vma_select_poll_info=""
		save_coalesce_params
		update_coalesce_4_udp_lat
		append_tmp_file_and_delete "$TMP_DIR/$log_file.prep" "$log_file"
		change_command_prefix VMA_SELECT_POLL=$VMA_SELECT_POLL_MAX_VAL VMA_SELECT_SKIP_OS=$VMA_IOMUX_SELECT_SKIP_OS VMA_RX_WRE=$VMA_IOMUX_RX_WRE VMA_HUGETLB=$VMA_IOMUX_HUGETLB VMA_RX_SKIP_OS=$VMA_IOMUX_RX_SKIP_OS
		vma_select_poll_info="With VMA_SELECT_POLL=$VMA_SELECT_POLL_MAX_VAL"
		print_message "===============>UDP_LAT Using Select/Poll/Epoll<==============" "$log_file"
		print_message "|----------------------------------|" "$log_file"
		print_message "|VMA_SELECT_POLL=$VMA_SELECT_POLL_MAX_VAL" "$log_file"
		print_message "|----------------------------------|" "$log_file"
		run_udp_lat_using_select_epoll_poll_helper "$vma_select_poll_info"
		change_command_prefix VMA_SELECT_POLL=$vma_select_poll_old VMA_SELECT_SKIP_OS=$vma_select_skip_os_old VMA_RX_WRE=$vma_rx_wre_old VMA_HUGETLB=$vma_hugetlb_old VMA_RX_SKIP_OS=$vma_rx_skip_os_old
		recreate_coalesce_params 
		tests_finish	
	fi
}

function run_udp_lat_using_select_epoll_poll_helper
{	
	prepare_udp_lat_using_feed_file_headlines "Select" "$1" 
	run_udp_lat_with_diff_mc_feed_files "s" "Select"
	prepare_udp_lat_using_feed_file_headlines "Epoll" "$1"
	run_udp_lat_with_diff_mc_feed_files "e" "Epoll " 
	prepare_udp_lat_using_feed_file_headlines "Poll" "$1"
	run_udp_lat_with_diff_mc_feed_files "p"	"Poll  " 
}

function run_udp_lat_with_diff_mc_feed_files
{
	local size_arr_len=${#MC_GROUP_SIZES[*]}
	print_udp_lat_with_feed_files_header "$2"
	for((i=0; $i < $size_arr_len; i=$((i=$i+1))))
	do
        	curr_feed_file_size=${MC_GROUP_SIZES[$i]}
		feed_file_name="$TMP_DIR/feed_file_$curr_feed_file_size"
		print_cycle_info "$curr_feed_file_size" "mc group"
		create_mc_feed_files "$curr_feed_file_size" "$feed_file_name"
		run_udp_lat_with_feed_file "$feed_file_name" "$1"
		parse_udp_lat_test_results "${MC_GROUP_SIZES[$i]}"
		remove_mc_feed_files "$feed_file_name"
	done
	clean_after_udp_lat
}


function run_udp_lat_with_feed_file
{
	upd_lat_command_line_srv=${PREFIX}"${UDP_LAT_APP} -s -f $1 -F $2"
	upd_lat_command_line_clt=${PREFIX}"${UDP_LAT_APP} -c -f $1 -F $2 -t $DURATION"
	
        (echo ${SRV_CMMND_LINE_PREF}$upd_lat_command_line_srv | tee -a $log_file) >& /dev/null
	(eval "$upd_lat_command_line_srv 2>&1 | tee >> $log_file &")
	sleep 15
	(ssh $REM_HOST_IP "killall udp_lat") >& /dev/null
	(echo "${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt" | tee -a "$TMP_DIR/$log_file.tmp") >& /dev/null
	(ssh $REM_HOST_IP "sleep 10;$upd_lat_command_line_clt 2>&1 | tee >> $TMP_FILE") 
	pkill -2 -f udp_lat >& /dev/null
	sleep 5
}

function print_udp_lat_with_feed_files_header
{
	print_message "=====================>UDP_LAT With $1<====================" "$log_file" 
}

function tests_finish
{
	eval "cat $TMP_DIR/$log_file.post" | tee -a $log_file >& /dev/null
	echo "---------------------------------------------------------------" |tee -a $log_file
	clean
}

function udp_lat_cycle
{
	print_cycle_info $curr_msg_size	message	
	(ssh $REM_HOST_IP "killall udp_lat") >& /dev/null
        upd_lat_command_line_clt=${PREFIX}"${UDP_LAT_APP} -c -i $MC_GROUP -p $PORT -m $curr_msg_size -t $DURATION"
        (echo "${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt" | tee -a "$TMP_DIR/$log_file.tmp") >& /dev/null
        (ssh $REM_HOST_IP "sleep 10;$upd_lat_command_line_clt 2>&1 | tee >> $TMP_FILE")    
   
}

function udp_lat_tx_bw_cycle
{
        print_cycle_info $curr_msg_size message
        (ssh $REM_HOST_IP "killall udp_lat") >& /dev/null
        upd_lat_command_line_clt=${PREFIX}"${UDP_LAT_APP} -c -i $MC_GROUP -p $PORT -m $curr_msg_size -t $DURATION -k -A $ACTIVITY"
        (echo "${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt" | tee -a "$TMP_DIR/$log_file.tmp") >& /dev/null
        (ssh $REM_HOST_IP "sleep 10;$upd_lat_command_line_clt 2>&1 | tee >> $TMP_FILE")
}

function udp_lat_bw_cycle
{
        print_cycle_info $curr_msg_size message
        killall -9 udp_lat  >& /dev/null
        ssh $REM_HOST_IP killall -9 udp_lat >& /dev/null

        upd_lat_command_line_srv=${PREFIX}"${UDP_LAT_APP} -s -i $MC_GROUP -p $PORT -m $curr_msg_size -k -A $ACTIVITY"
        upd_lat_command_line_clt=${PREFIX}"${UDP_LAT_APP} -c -i $MC_GROUP -p $PORT -m $curr_msg_size -t $DURATION -k -A $ACTIVITY"

        (echo ${SRV_CMMND_LINE_PREF}$upd_lat_command_line_srv | tee -a $log_file) >& /dev/null
        (ssh $REM_HOST_IP "echo ${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt | tee -a $TMP_DIR/$log_file.tmp") >& /dev/null
        (eval "$upd_lat_command_line_srv 2>&1 | tee >> $log_file &")
        (ssh $REM_HOST_IP "killall udp_lat") >& /dev/null
        (echo "${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt" | tee -a "$TMP_DIR/$log_file.tmp") >& /dev/null
        (ssh $REM_HOST_IP "sleep 5;$upd_lat_command_line_clt 2>&1 | tee >> $TMP_FILE")
        local wait_time=$DURATION
        let "wait_time += 20"
        sleep $wait_time
        killall -2 udp_lat
}

function udp_lat_sending_bursts_cycle
{
	print_cycle_info $curr_burst_size burst	
	(ssh $REM_HOST_IP "killall udp_lat") >& /dev/null
        upd_lat_command_line_clt=${PREFIX}"${UDP_LAT_APP} -c -i $MC_GROUP -p $PORT -t $DURATION -b $curr_burst_size"
        (echo "${CLT_CMMND_LINE_PREF} $upd_lat_command_line_clt" | tee -a "$TMP_DIR/$log_file.tmp") >& /dev/null
        (ssh $REM_HOST_IP "sleep 10;$upd_lat_command_line_clt 2>&1 | tee >> $TMP_FILE")    
   
}

function print_cycle_info
{
	let "cycle_num=$i+1"
 	echo "##################### cycle $cycle_num of $size_arr_len #####################"
	echo "#$2 size is $1"
}

function parse_iperf_test_results 
{
	local start_time=0
	local end_time=0
	local warning_msg=""
        check_iperf_succss
	if [[ $success -eq $TRUE ]]; then

        	loss=`cat $TMP_FILE | grep % | tail -1 | tr " " "\n" | tail -1 | tr  -d '(-)'`
		avg_pps=`cat $TMP_FILE | grep % | tail -1 | tr "-" " " | tr  -s " " | tr '/' '\n' | tail -1 | tr  " " '\n' | tail -2 | head -1`
                #avg_pps=`cat $TMP_FILE | grep % | tail -1 | tr "-" " " | tr  -s " " | cut --d=" " -f 12 | cut -d "/" -f 2`
		start_time=`cat $TMP_FILE|grep %|tail -1|tr "-" " "|tr -s " " | cut --d=" " -f 3 | cut --d="." -f 1`
		end_time=`cat $TMP_FILE|grep %|tail -1|tr "-" " "|tr -s " " | cut --d=" " -f 4 | cut --d="." -f 1`
		let "actual_duration=$end_time-$start_time"
		let "avg_pps=avg_pps/$actual_duration"	
	 	avg_bw=`cat $TMP_FILE | grep % | tail -1 | tr "-" " " | tr -s " " | cut --d=" " -f 8`
        	echo "#average loss is $loss"
       		echo "#average BW is $avg_bw MBps"
		echo "#average packet rate is $avg_pps pps"
		if [[ "$actual_duration" -ne $DURATION ]]; then
			warning_msg="#vma_perf_envelope:WARNING:missing summarize in iperf"
			echo "$warning_msg"
			warning_msg=",$warning_msg"
		fi

	     	echo "${IPERF_MSG_SIZE[$i]},$avg_bw,$loss,${avg_pps}${warning_msg}" >> $res_file        	      	 			
        else
		echo "#$ERROR_MESSAGE"
		echo "${IPERF_MSG_SIZE[$i]},${ERROR_RESULT},${ERROR_RESULT},${ERROR_RESULT}" >> $res_file
	fi

	cat $TMP_FILE | tee -a $log_file >& /dev/null  			
       	rm -rf $TMP_FILE >& /dev/null
}

function parse_udp_lat_test_results 
{ 
	check_udp_lat_succss latency $TMP_FILE
	if [[ $success -eq $TRUE ]]; then
  
	        latency=`ssh $REM_HOST_IP cat $TMP_FILE |tr A-Z a-z|grep latency|tr [="="=] " " |tr -s " "|tr " " "\n"|tail -2|head -1`
		echo "#average latency is $latency usec"
        	echo $1,$latency >> $res_file           		
	else
		echo "#$ERROR_MESSAGE"
		echo "$1,${ERROR_RESULT}" >> $res_file    	
        		
	fi

	ssh $REM_HOST_IP "cat $TMP_FILE" | tee -a "$TMP_DIR/$log_file.tmp" >& /dev/null 		
       	ssh $REM_HOST_IP "rm -rf $TMP_FILE" >& /dev/null	
}

function parse_udp_lat_tx_bw_test_results
{
        check_udp_lat_succss rate $TMP_FILE
        if [[ $success -eq $TRUE ]]; then

                local pps=`ssh $REM_HOST_IP cat $TMP_FILE |tr A-Z a-z|tail -2|grep "rate"| tr -s " " |cut -d " " -f 6`
                local bw=`ssh $REM_HOST_IP cat $TMP_FILE |tr A-Z a-z|tail -2|grep "bandwidth"| tr -s " " |cut -d " " -f 5`
                echo "#average message rate is $pps [msg/sec]"
                echo "#average bw is $bw MBps"
                echo $1,$pps,$bw >> $res_file
        else
                echo "#$ERROR_MESSAGE"
                echo "$1,${ERROR_RESULT}" >> $res_file

        fi

        ssh $REM_HOST_IP "cat $TMP_FILE" | tee -a "$TMP_DIR/$log_file.tmp" >& /dev/null
        ssh $REM_HOST_IP "rm -rf $TMP_FILE" >& /dev/null
}

function parse_udp_lat_bw_test_results
{
        check_udp_lat_succss total $log_file
        if [[ $success -eq $TRUE ]]; then

		local pps=`ssh $REM_HOST_IP cat $TMP_FILE |tr A-Z a-z|tail -2|grep "rate"| tr -s " " |cut -d " " -f 6`
		local bw=`ssh $REM_HOST_IP cat $TMP_FILE |tr A-Z a-z|tail -2|grep "bandwidth"| tr -s " " |cut -d " " -f 5`
		local rx_recived=`cat $log_file| grep received  |tail -1|tr -s " "|cut -d " " -f 4`
		local tx_send=`ssh $REM_HOST_IP cat $TMP_FILE| grep sent| tail -1 |tr -s " "| cut -d " " -f 4`
		local diff=$(($tx_send-$rx_recived))
		
		if [ $diff -lt 0 ]; then
			diff=0
		fi
		
		local loss=$(echo "scale=5;($diff/$tx_send)*100"| bc)

		if [[ $loss =~ "^\." ]];
			then loss="0${loss}"
		fi

		local d_point=`expr index $loss "\."`
		d_point=$(($d_point+3))
		loss=`expr substr $loss 1 $d_point`
		
		echo "#message rate is $pps [msg/sec]"
		echo "#bw is $bw MBps"
		echo "#packet loss is ${loss}%"
		echo $1,$pps,$bw,$loss >> $res_file
        else
		echo "#$ERROR_MESSAGE"
		echo "$1,${ERROR_RESULT}" >> $res_file

        fi

        ssh $REM_HOST_IP "cat $TMP_FILE" | tee -a "$TMP_DIR/$log_file.tmp" >& /dev/null
        ssh $REM_HOST_IP "rm -rf $TMP_FILE" >& /dev/null
}

function check_udp_lat_succss
{
	local res=0
	local look_for=$1
	local res_file=$2

	if [ $res_file = $log_file ]; then
		res=`cat $res_file |tr A-Z a-z |grep $look_for | wc -l`
	else
		res=`ssh $REM_HOST_IP "cat $res_file |tr A-Z a-z |grep $look_for | wc -l"`
	fi

	if [[ $res -gt 0 ]]; then
		success=$TRUE
	else
		success=$FALSE
	fi
}

function check_iperf_succss
{
	local res=0
	
	res=`cat $TMP_FILE | grep % | wc -l`

	if [ $res -gt 0 ]; then
		success=$TRUE
	else
		success=$FALSE		
	fi	 
}

function prepare_output_files
{
        date=`date +%Y_%m_%d_%H_%M_%S`        
        log_file="${OUTPUT_FILES_PATH}vma_perf_${date}_logs.txt"
        res_file="${OUTPUT_FILES_PATH}vma_perf_${date}_results.csv"
     
        touch  $log_file
        touch  $res_file       
}

function prepare_iperf_headlines
{
	echo "" >> $res_file
        echo Iperf Test Results >> $res_file 
        echo Msg size,Averag RX BW,Average Loss,Packet Rate >> $res_file	
}

function prepare_udp_lat_headlines
{
	echo "" >> $res_file
	echo Udp_lat Test Results >> $res_file 
        echo Message size,Latency >> $res_file
}

function prepare_udp_lat_tx_bw_headlines
{
        echo "" >> $res_file
        echo Udp_lat TX BW Test Results >> $res_file
        echo Msg size,TX Packet Rate,TX BW >> $res_file
}

function prepare_udp_lat_bw_headlines
{
        echo "" >> $res_file
        echo Udp_lat BW Test Results >> $res_file
        echo Msg size,TX Packet Rate,TX BW,RX Average Loss %>> $res_file
}

function prepare_udp_lat_sending_bursts_headlines
{
	echo "" >> $res_file
	echo Udp_lat Sending Bursts Test Results >> $res_file 
        echo Burst size,Latency >> $res_file
}

function prepare_udp_lat_using_feed_file_headlines
{
	echo "" >> $res_file
	echo Udp_lat Using $1 $2 Test Results >> $res_file 
        echo MC Group Num,Latency >> $res_file
}

function update_command_line_pref_in_log_file
{
	SRV_CMMND_LINE_PREF="[$srv_hostname "`pwd`"]"
        CLT_CMMND_LINE_PREF="[$clt_hostname "`ssh $REM_HOST_IP pwd`"]"
}

function get_hostnames
{
	clt_hostname=`ssh $REM_HOST_IP hostname`
	srv_hostname=`hostname`

	update_command_line_pref_in_log_file

}

function update_vma_igmp_flag
{
	check_if_infbnd_iface	
	if [[ $is_infiniband -eq $FALSE ]]; then
		VMA_IGMP_ENABLE=1	
	fi
}

function update_command_prefix
{
	PREFIX=""
	
	update_vma_igmp_flag	
	
	if [[ "$OVER_VMA" = yes ]] ; then
	
		if [[ $VMA_IGMP_ENABLE -ne $DEFAULT_VMA_IGMP_ENABLE ]] ; then
			PREFIX="$PREFIX VMA_IGMP=$VMA_IGMP_ENABLE "	
		fi

		if [[ $VMA_SELECT_POLL -ne $DEFAULT_VMA_SELECT_POLL ]] ; then
			PREFIX="$PREFIX VMA_SELECT_POLL=$VMA_SELECT_POLL "	
		fi

		if [[ $VMA_RX_SKIP_OS -ne $DEFAULT_VMA_RX_SKIP_OS ]] ; then
                        PREFIX="$PREFIX VMA_RX_SKIP_OS=$VMA_RX_SKIP_OS "
                fi
		
		if [[ $VMA_RX_BUFS -ne $DEFAULT_VMA_RX_BUFS ]] ; then
			PREFIX="$PREFIX VMA_RX_BUFS=$VMA_RX_BUFS "	
		fi			
	
		if [[ $VMA_THREAD_MODE  -ne $DEFAULT_VMA_THREAD_MODE ]] ; then
			PREFIX="$PREFIX VMA_THREAD_MODE=$VMA_THREAD_MODE "		
		fi
	
                if [[ $VMA_RX_WRE  -ne $DEFAULT_VMA_RX_WRE ]] ; then
                        PREFIX="$PREFIX VMA_RX_WRE=$VMA_RX_WRE "
                fi
	
		if [[ $VMA_SELECT_SKIP_OS  -ne $DEFAULT_VMA_SELECT_SKIP_OS ]] ; then
                        PREFIX="$PREFIX VMA_SELECT_SKIP_OS=$VMA_SELECT_SKIP_OS "
                fi

		if [[ $VMA_HUGETLB  -ne $DEFAULT_VMA_HUGETLB ]] ; then
                        PREFIX="$PREFIX VMA_HUGETLB=$VMA_HUGETLB "
                fi
	
		PREFIX=${PREFIX}"LD_PRELOAD=$VMA_LIB "	
	fi	
}

function change_command_prefix
{
	for curr in $*;
        do
       		eval "$curr"
        done;
	update_command_prefix	
}

function remove_ifaces
{
	add_curr_route_table_2_log
	iface_arr_local=`route | grep 2[24][40].0.0.0 | tr -s ' ' | cut -d ' ' -f 8`
	iface_arr_remote=`ssh $REM_HOST_IP "route | grep 2[24][40].0.0.0 | tr -s ' ' | cut -d ' ' -f 8"`	
 	
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "============>Remove interfaces from route table <=============" >> "$TMP_DIR/$log_file.prep"	

	for iface in $iface_arr_local 
	do
		command="route del -net $DST_NET netmask $DST_MASK dev $iface"
		(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a $TMP_DIR/$log_file.prep) >& /dev/null
		eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.prep"	
	done	

	for iface in $iface_arr_remote 
	do
		command="route del -net $DST_NET netmask $DST_MASK dev $iface" 
		(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
		eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $TMP_DIR/$log_file.prep" 
	done	
}

function add_curr_route_table_2_log
{
	(echo "${SRV_CMMND_LINE_PREF} route" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "route 2>&1 | tee >>  $TMP_DIR/$log_file.prep"
	
	(echo "${CLT_CMMND_LINE_PREF} route" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "ssh $REM_HOST_IP "route" 2>&1 | tee >>  $TMP_DIR/$log_file.prep"		
}

function recreate_route_table
{
	echo "" >> "$TMP_DIR/$log_file.post"
	echo "===================>Recreate route table <====================" >> "$TMP_DIR/$log_file.post"
	command="route del -net $DST_NET netmask $DST_MASK dev $INTERFACE"
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
	eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.post"
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
 	ssh  $REM_HOST_IP "$command" 2>&1 | tee >> "$TMP_DIR/$log_file.post"
		
	for iface in $iface_arr_local 
	do
		command="route add -net $DST_NET netmask $DST_MASK dev $iface"
		(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
		eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.post"	
	done

	for iface in $iface_arr_remote 
	do
		command="route add -net $DST_NET netmask $DST_MASK dev $iface"
 		(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
		(eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $TMP_DIR/$log_file.post") >& /dev/null 
	done
	eval "cat $TMP_DIR/$log_file.post" | tee -a $log_file >& /dev/null
	clean
}

function prepare_route_table
{	
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "=====================>Route table info <======================" >> "$TMP_DIR/$log_file.prep"
	remove_ifaces
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "============>Add work interface to route table <==============" >> "$TMP_DIR/$log_file.prep"
	command="route add -net $DST_NET netmask $DST_MASK dev $INTERFACE"
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "$command 2>&1 | tee >> $TMP_DIR/$log_file.prep"
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
 	eval "ssh  $REM_HOST_IP "$command" 2>&1 | tee >>  $TMP_DIR/$log_file.prep"  
	eval "cat $TMP_DIR/$log_file.prep" | tee -a $log_file >& /dev/null
	clean
}

function save_coalesce_params
{
	local_coalesce_params_saved=$TRUE
	remote_coalesce_params_saved=$TRUE
	command1="ethtool -c $INTERFACE"
	
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "===================>Coalesce params info<=====================" >> "$TMP_DIR/$log_file.prep"

	save_local_coalesce_params "$command1" rx-frames: initial_rx_frames_local 
	save_remote_coalesce_params "$command1" rx-frames: initial_rx_frames_remote 
	save_local_coalesce_params "$command1" rx-usecs: initial_rx_usecs_local 
	save_remote_coalesce_params "$command1" rx-usecs: initial_rx_usecs_remote 
	rm -f $TMP_FILE >& /dev/null
	rm -f $TMP_FILE.err >& /dev/null

}

function save_local_coalesce_params
{
	(echo "${SRV_CMMND_LINE_PREF} $1" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "$1 $COMMAND_REDIRECT"
	check_succsess_and_save_param $2 get_coalesce_param
	eval "$3=$?"
	if [[ $SUCCSESS -eq $FALSE ]] ;then
		local_coalesce_params_saved=$FALSE		
	fi
	
}

function save_remote_coalesce_params
{
	(echo "${CLT_CMMND_LINE_PREF} $1" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "(ssh $REM_HOST_IP "$1") $COMMAND_REDIRECT"
	check_succsess_and_save_param $2 get_coalesce_param
	eval "$3=$?" 
	if [[ $SUCCSESS -eq $FALSE ]]; then
		remote_coalesce_params_saved=$FALSE
	fi
}

function get_coalesce_param
{
	ret_val=`cat $TMP_FILE | grep $1 | cut -d " " -f 2 2>/dev/null` 
}

function get_umcast_val
{
	umcast_val=`cat $TMP_FILE | tr -d "\n" 2>/dev/null` 
}

function update_coalesce_4_udp_lat
{
	local_coalesce_params_changed=$FALSE
	remote_coalesce_params_changed=$FALSE
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "============>Prepare coalesce params for udp_lat<=============" >> "$TMP_DIR/$log_file.prep"
	update_coalesce_params $RX_FRAMES_4_UDP_LAT $RX_USEC_4_LAT_TEST	
}

function update_coalesce_4_tr_test
{	
	local_coalesce_params_changed=$FALSE
	remote_coalesce_params_changed=$FALSE
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "========>Prepare coalesce params for throughput test<=========" >> "$TMP_DIR/$log_file.prep"
	update_coalesce_params $RX_FRAMES_4_IPERF $RX_USEC_4_BW_TEST
}

function update_coalesce_params
{
	local rx_frames_val=$1
	local rx_usecs_val=$2

	update_coalesce_param rx-frames $rx_frames_val
	update_coalesce_param rx-usecs $rx_usecs_val
}

function update_coalesce_param
{
	local param_name=$1
	local param_val=$2
	command="ethtool -C $INTERFACE $param_name $param_val"

	if [[ $local_coalesce_params_saved -eq $TRUE ]]; then
		if [[ $initial_rx_frames_local -ne $1 ]]; then
			update_local_coalesce_params
		fi
	fi

	if [[ $remote_coalesce_params_saved -eq $TRUE ]]; then
		if [[ $initial_rx_frames_remote -ne $1 ]]; then
			update_remote_coalesce_params
		fi
	fi
}

function update_local_coalesce_params
{
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
 	eval "$command $COMMAND_REDIRECT"
	check_command_succss
	
	if [[ $SUCCSESS -eq $TRUE ]]; then
		local_coalesce_params_changed=$TRUE
	else
		local_coalesce_params_changed=$FALSE
	fi
	
}

function update_remote_coalesce_params
{
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "(ssh  $REM_HOST_IP "$command") $COMMAND_REDIRECT"
	check_command_succss
	if [[ $SUCCSESS -eq $TRUE ]]; then
		remote_coalesce_params_changed=$TRUE
	else
		remote_coalesce_params_changed=$FALSE
	fi
}

function recreate_coalesce_params
{
	echo "" >> "$TMP_DIR/$log_file.post"
	echo "==================>Recreate coalesce params<==================" >> "$TMP_DIR/$log_file.post"

	if [[ $local_coalesce_params_changed -eq $TRUE ]]; then
		recreate_local_coalesce_params
	fi

	if [[ $remote_coalesce_params_changed -eq $TRUE ]]; then
		recreate_remote_coalesce_params	
	fi	
}

function recreate_local_coalesce_params
{
	local command="ethtool -C $INTERFACE rx-frames $initial_rx_frames_local rx-usecs $initial_rx_usecs_local"

	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
	eval $command >& /dev/null	
}

function recreate_remote_coalesce_params
{
	local command="ethtool -C $INTERFACE rx-frames $initial_rx_frames_remote rx-usecs $initial_rx_usecs_remote"

	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
	ssh  $REM_HOST_IP "$command" >& /dev/null
}

function save_umcast
{
	local_umcast_saved=$FALSE
	remote_umcast_saved=$FALSE
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "========================>Umcast info<=========================" >> "$TMP_DIR/$log_file.prep"
	check_if_infbnd_iface

	if [[ "$OVER_VMA" = not ]]; then
		UMCAST_VAL=0
	fi

	if [[ $is_infiniband -eq $TRUE ]]; then
		save_local_umcast_val
		save_remote_umcast_val				
	fi
	eval "cat $TMP_DIR/$log_file.prep" | tee -a $log_file >& /dev/null
	clean
}

function save_local_umcast_val
{
	local command="cat /sys/class/net/$INTERFACE/umcast"
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	eval "cat /sys/class/net/$INTERFACE/umcast 1>$TMP_FILE 2>$TMP_FILE.err "
	check_succsess_and_save_param initial_local_umcast_val get_umcast_val
	if [[ $SUCCSESS -eq $FALSE ]]; then
		local_umcast_saved=$FALSE
	else
		initial_local_umcast_val=$umcast_val
		local_umcast_saved=$TRUE
	fi 
}

function save_remote_umcast_val
{
	local command="cat /sys/class/net/$INTERFACE/umcast"
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
	(eval "ssh $REM_HOST_IP cat /sys/class/net/$INTERFACE/umcast") 1>$TMP_FILE 2>$TMP_FILE.err  	
	check_succsess_and_save_param initial_remote_umcast_val get_umcast_val
	if [[ $SUCCSESS -eq $FALSE ]]; then
		remote_umcast_saved=$FALSE
	else
		initial_remote_umcast_val=$umcast_val
		remote_umcast_saved=$TRUE
	fi	
}


function update_umcast
{
	echo "" >> "$TMP_DIR/$log_file.prep"
	echo "===================>Prepare umcast param<====================" >> "$TMP_DIR/$log_file.prep"
	local_umcast_changed=$FALSE
	remote_umcast_changed=$FALSE
	
	if [[ $initial_local_umcast_val -ne $UMCAST_VAL ]]; then
		update_local_umcast
	fi
	
	if [[ $initial_remote_umcast_val -ne $UMCAST_VAL ]]; then
		update_remote_umcast
	fi

	eval "cat $TMP_DIR/$log_file.prep" | tee -a $log_file >& /dev/null
	clean
}

function update_local_umcast
{
	local command="echo $UMCAST_VAL 1>&/sys/class/net/$INTERFACE/umcast"
	if [[ $local_umcast_saved -eq $TRUE ]]; then
		(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
		eval "$command 1>$TMP_FILE 2>$TMP_FILE.err" 
		check_command_succss
		if [[ $SUCCSESS -eq $TRUE ]]; then
			local_umcast_changed=$TRUE
		else
			local_umcast_changed=$FALSE
		fi
	fi
}

function update_remote_umcast
{
	local command="echo $UMCAST_VAL 1>&/sys/class/net/$INTERFACE/umcast"
	if [[ $local_umcast_saved -eq $TRUE ]]; then
		(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.prep") >& /dev/null
		ssh $REM_HOST_IP "$command" | eval "1>$TMP_FILE 2>$TMP_FILE.err "	
		check_command_succss
		if [[ $SUCCSESS -eq $TRUE ]]; then
			remote_umcast_changed=$TRUE
		else
			remote_umcast_changed=$FALSE
		fi
	fi
}

function recreate_umcast
{
	echo "" >> "$TMP_DIR/$log_file.post"
	echo "====================>Recreate umcast value<===================" >> "$TMP_DIR/$log_file.post"
		
	if [[ $local_umcast_changed -eq $TRUE ]]; then
		recreate_local_umcast_val
	fi

	if [[ $remote_umcast_changed -eq $TRUE ]]; then
		recreate_remote_umcast_val	
	fi

	eval "cat $TMP_DIR/$log_file.post" | tee -a $log_file >& /dev/null	
}

function recreate_local_umcast_val
{
	local command="echo $initial_local_umcast_val 1>&/sys/class/net/$INTERFACE/umcast"
	(echo "${SRV_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
	eval "$command" >& /dev/null	
}

function recreate_remote_umcast_val
{
	local command="echo $initial_remote_umcast_val 1>&/sys/class/net/$INTERFACE/umcast"
	(echo "${CLT_CMMND_LINE_PREF} $command" | tee -a "$TMP_DIR/$log_file.post") >& /dev/null
	ssh  $REM_HOST_IP $command >& /dev/null
}

function clean_after_iperf
{
	killall iperf >& /dev/null
	ssh $REM_HOST_IP killall iperf >& /dev/null
	ssh $REM_HOST_IP "cat $TMP_DIR/$log_file.tmp" | tee -a $log_file >& /dev/null 
	ssh $REM_HOST_IP rm -f "$TMP_DIR/$log_file.tmp" >& /dev/null
	rm -f $TMP_FILE.err >& /dev/null 
	rm -f "$TMP_DIR/$log_file.prep" >& /dev/null
}

function clean_after_udp_lat
{	
	ssh $REM_HOST_IP killall udp_lat >& /dev/null
       	pkill -2 -f udp_lat >& /dev/null
        sleep 10
        cat "$TMP_DIR/$log_file.tmp" | tee -a $log_file >& /dev/null
        rm -f "$TMP_DIR/$log_file.tmp" >& /dev/null
}

function collect_nodes_info_to_file
{
	collect_local_node_info_to_file "$1"
	collect_remote_node_info_to_file "$1"
}

function collect_local_node_info_to_file
{
	(echo "======================>Local node info<======================" | tee -a $1) >& /dev/null
	(echo "--------------------" | tee -a $1) >& /dev/null
	(hostname | tee -a $1) >& /dev/null
	(echo -n "OS: " >> $1;cat /etc/issue | grep We | tee -a $1) >& /dev/null
	(echo -n "CPU: " >> $1;cat /proc/cpuinfo | grep 'model name' | sort -u | awk '{print $4, $5, $6, $7, $9}' | tee -a $1) >& /dev/null
	(echo -n "Number of CPUs: " >> $1;cat /proc/cpuinfo |grep proce |wc |awk '{print $1}' | tee -a $1) >& /dev/null
	(echo -n "CPU Type: " >> $1;uname -a | awk '{print $12}' | tee -a $1) >& /dev/null
	(cat /proc/meminfo |grep [M,m]em | tee -a $1) >& /dev/null
	(echo -n "Kernel: " >> $1;uname -a | awk '{print $3}' | tee -a $1) >& /dev/null
	(cat /usr/voltaire/version | tee -a $1) >& /dev/null
	(ibstat | grep -e "CA type" -e "Firmware version" | tee -a $1) >& /dev/null
	(ibstatus | grep -e rate -e state | grep -v 'phys state' | tee -a $1) >& /dev/null
	check_if_infbnd_iface
	if [[ $is_infiniband -eq $TRUE ]]; then
		(echo -n "IPoIB mode: " >> $1 ; cat "/sys/class/net/$INTERFACE/mode" | tee -a $1) >& /dev/null
	fi
	(ifconfig $INTERFACE | grep MTU | awk '{print $5}' | tee -a $1) >& /dev/null
	(echo -n "OFED:" >> $1;ofed_info | head -6 | grep OFED | tee -a $1) >& /dev/null
	(echo -n "VMA:" >> $1;rpm -qa | grep $VMA | tee -a $1) >& /dev/null	

}

function collect_remote_node_info_to_file
{
	(echo "=====================>Remote node info<======================" | tee -a $1) >& /dev/null
	(echo "--------------------" | tee -a $1) >& /dev/null
	(ssh $REM_HOST_IP "hostname" | tee -a $1) >& /dev/null
	(echo -n "OS: " >> $1;ssh $REM_HOST_IP cat /etc/issue | grep We | tee -a $1) >& /dev/null
	(echo -n "CPU: " >> $1;ssh $REM_HOST_IP cat /proc/cpuinfo | grep 'model name' | sort -u | awk '{print $4, $5, $6, $7, $9}' | tee -a $1) >& /dev/null
	(echo -n "Number of CPUs: " >> $1;ssh $REM_HOST_IP cat /proc/cpuinfo |grep proce |wc |awk '{print $1}' | tee -a $1) >& /dev/null
	(echo -n "CPU Type: " >> $1;ssh $REM_HOST_IP uname -a | awk '{print $12}' | tee -a $1) >& /dev/null
	(ssh $REM_HOST_IP cat /proc/meminfo |grep [M,m]em | tee -a $1) >& /dev/null
	(echo -n "Kernel: " >> $1;ssh $REM_HOST_IP uname -a | awk '{print $3}' | tee -a $1) >& /dev/null
	(ssh $REM_HOST_IP "cat /usr/voltaire/version" | tee -a $1) >& /dev/null
	(ssh $REM_HOST_IP "ibstat | grep -e "CA type" -e 'Firmware version'" | tee -a $1) >& /dev/null
	(ssh $REM_HOST_IP "ibstatus | grep -e rate -e state | grep -v 'phys state'" | tee -a $1) >& /dev/null
	to_print="/sys/class/net/$INTERFACE/mode"
	check_if_infbnd_iface
	if [[ $is_infiniband -eq $TRUE ]]; then
		(echo -n "IPoIB mode: " >> $1 ;ssh $REM_HOST_IP "cat $to_print" | tee -a $1) >& /dev/null
	fi
	(ssh $REM_HOST_IP ifconfig $INTERFACE | grep MTU | awk '{print $5}' | tee -a $1) >& /dev/null
	(echo -n "OFED:" >> $1;ssh $REM_HOST_IP ofed_info | head -6 | grep OFED | tee -a $1) >& /dev/null
	(echo -n "VMA:" >> $1;ssh $REM_HOST_IP rpm -qa | grep $VMA | tee -a $1) >& /dev/null
}

function print_message
{
	echo $1 | tee -a $2
        echo ""| tee -a $2 
}

function append_tmp_file_and_delete
{
	cat $1 | tee -a $2 >& /dev/null
	rm -f  $1	
}

function check_command_succss
{	
	if [ -s  $TMP_FILE.err ]; then
		eval "cat $TMP_FILE.err 2>&1 | tee >> $TMP_DIR/$log_file.prep"
		LAST_ERROR=`cat $TMP_FILE.err`
		SUCCSESS=$FALSE		
	else
		if [ -s $TMP_FILE ]; then
			eval "cat $TMP_FILE 2>&1 | tee >> $TMP_DIR/$log_file.prep"
		fi
		SUCCSESS=$TRUE	
	fi

	rm -f $TMP_FILE.err >& /dev/null	
}

function check_succsess_and_save_param
{
	local ret_val=0

	check_command_succss

	if [[ $SUCCSESS -eq $TRUE ]]; then
		$2 $1			
	fi

	return $ret_val 
} 

function check_if_infbnd_iface
{
	is_infiniband=$FALSE
	
	if [[ $INTERFACE  =~ "ib*" ]]; then
		is_infiniband=$TRUE		
	fi
}

function discover_local_work_if_ip
{
	LOCAL_IP=`ifconfig  $INTERFACE | grep inet |grep -v inet6 | cut -d ':' -f 2| cut -d " " -f 1`  >& /dev/null
}

function calc_file_age
{
	creation_time=`stat -c %Z /tmp/vma_utils_block_file` 
	now=`date +%s`
	block_file_age=$(($now-$creation_time)) 		
}

function get_operator_pid
{
	pid=$$
}

function write_to_file_operator_details
{
	operating_machine_hostname=`hostname`
        get_operator_pid
	rm -f  "$2" >& /dev/null
	touch "$2" >& /dev/null
	echo -n "$1 " >> "$2" 2>/dev/null 
	echo -n "$pid " >> "$2" 2>/dev/null 
	echo -n "$script_name " >> "$2" 2>/dev/null
        echo -n "$user_name " >> "$2" 2>/dev/null
        echo -n "$user_id " >> "$2" 2>/dev/null
	echo -n "$operating_machine_hostname " >> "$2" 2>/dev/null

	if [[ $1 == "local" ]]; then
		st_timestamp=`date`
	else
		st_timestamp=`ssh $REM_HOST_IP "date" `
	fi
	
	echo "$st_timestamp" | tr " " "_" >> "$2" 2>/dev/null 	
}

function read_block_file
{
	blocking_pid=`awk -F " " '{print $2}' "$1"`
	blocking_app=`awk -F " " '{print $3}' "$1"`
        blocking_username=`awk -F " " '{print $4}' "$1"`
        blocking_id=`awk -F " " '{print $5}' "$1"`
	blocking_hostname=`awk -F " " '{print $6}' "$1"`
        blocking_st_time=`awk -F " " '{print $7}' "$1"`
}

function print_block_files_details
{
	echo "Blocked Host:$blocked_host"
	echo "You blocked by:"
	echo "-	application: ${blocking_app} "
        echo "-	user: ${blocking_username} "
	echo "-	users local host ip:${blocking_id} "
	echo "-	blocking proccess with pid: ${blocking_pid} running on host ${blocking_hostname} "
        echo "-	starting time:${blocking_st_time} "
	echo "-	blocking file:${BLOCK_FILE}"		
}

function update_remote_block_file
{
	write_to_file_operator_details "$LOCAL_IP" "${BLOCK_FILE}.rem"
	scp "${BLOCK_FILE}.rem" "${REM_HOST_IP}:${BLOCK_FILE}" >& /dev/null
	rm -f  "${BLOCK_FILE}.rem" >& /dev/null
}

function update_local_block_file
{
	write_to_file_operator_details "local" "$BLOCK_FILE"
}

function update_block_files
{
	discover_local_work_if_ip
	if [ "$LOCAL_IP" == "" ]; then
		echo "WARNING: Will be executed without blocking..."
	else
		update_local_block_file
		update_remote_block_file
	fi	
}

function unblock_local_host
{
	rm -f $BLOCK_FILE >& /dev/null
	rm -f "${BLOCK_FILE}.rem" >& /dev/null
}

function unblock_remote_host
{
	ssh $REM_HOST_IP "rm -f $BLOCK_FILE >& /dev/null" >& /dev/null
	rm -f "${BLOCK_FILE}.rem" >& /dev/null
}

function unblock
{
	unblock_local_host
	unblock_remote_host
}

function check_connection_to_remote_host
{
	ping -w 3 "$1" >& /dev/null
	test $? -eq 0 && RES=OK || RES=NOT 
}

function check_if_another_proccess_running_on_local_host
{
	eval "ps -eF| grep '$blocking_pid'|grep -v grep|wc -l" > $TMP_FILE
	RES=`cat $TMP_FILE`
}

function check_if_another_proccess_running_on_remote_host
{
	RES=0
	check_connection_to_remote_host "$1"
	if [ $RES == "OK" ]; then
		RES=`sudo ssh ${SUPER_USR}@${1} "ps -eF| grep ${blocking_pid}|grep -v grep|wc -l"`
	else
		RES=1
	fi
}

function get_operating_host_ip_or_hostname
{
	RES=0
	operating_host_ip=`awk -F " " '{print $1}' "$1"`
	if [[ $operating_host_ip != "local" ]]; then
		check_connection_to_remote_host "$operating_host_ip"
		if [ $RES != "OK" ]; then
			operating_host_ip=`awk -F " " '{print $6}' "$1"`
		fi	
	fi
}	

function check_if_operating_host_running_another_proccess 
{
	if [ $1 == "local" ]; then
		check_if_another_proccess_running_on_local_host	
	else
		check_if_another_proccess_running_on_remote_host "$1"
	fi
}

function adjust_operating_host_ip_of_remote_machine
{
	local tmp=""
	
	if [ "$1" == "local" ]; then
		operating_host_ip=$REM_HOST_IP
	else
		tmp=`ifconfig|grep $1`
		if [ "$tmp" != "" ]; then
			operating_host_ip="local"		
		fi	
	fi
}

function check_if_remote_host_is_blocked
{	
	RES=0
	ssh $REM_HOST_IP "cat  ${BLOCK_FILE} 2>/dev/null" > "${BLOCK_FILE}.rem"

	if [ -s "${BLOCK_FILE}.rem" ]; then
		read_block_file "${BLOCK_FILE}.rem"
		get_operating_host_ip_or_hostname "${BLOCK_FILE}.rem"
		adjust_operating_host_ip_of_remote_machine "$operating_host_ip"
		check_if_operating_host_running_another_proccess "$operating_host_ip"
		
		if [[ $RES -le 0 ]]; then
			unblock_remote_host 
		else
			read_block_file "$BLOCK_FILE.rem"
			blocked_host=$REM_HOST_IP
			print_block_files_details
			rm -f "${BLOCK_FILE}.rem" >& /dev/null
			clean
			exit 1
		fi	
	fi
}

function check_if_local_host_is_blocked
{	
	RES=0
	if [[ -e $BLOCK_FILE ]]; then
		read_block_file "$BLOCK_FILE"
		get_operating_host_ip_or_hostname "${BLOCK_FILE}"
		check_if_operating_host_running_another_proccess "$operating_host_ip"
		if [[ $RES -le 0 ]]; then
			unblock_local_host 
		else
			blocked_host=`hostname`
			print_block_files_details
			clean
			exit 1
		fi	
	fi	
}

function block 
{
	check_if_local_host_is_blocked	
	check_if_remote_host_is_blocked
	update_block_files
}


function pre_test_checks
{
	check_connection_2_remote_ip
	check_if_iperf_avaibale	
	clean
}

function check_connection_2_remote_ip
{
	ssh -o "BatchMode yes" $REM_HOST_IP exit 2>$TMP_FILE.err
	check_command_succss	
	if [[ $SUCCSESS -ne $TRUE ]]; then
		echo "vma_perf_envelope error:$LAST_ERROR"
		clean
		unblock
		exit 1	
	fi		
}

function write_mc_feed_file
{
	local mc_grp_ctr=0  	# num of mc groups
	local mc_addr_part_3=1  # the third number of the mc group
	local port=10005
	local mc_addr_part_4=3  # the last number of the mc group
	local mc_grp_num=$1
	local file_name=$2
	
	if [ -e $file_name ]; then
		rm -f $file_name >& /dev/null
	fi

	while [ $mc_grp_ctr -lt $mc_grp_num ]
	do
		if [ $mc_addr_part_4 -ge 254 ]; then
			mc_addr_part_3=$(($mc_addr_part_3+1)) 
			mc_addr_part_4=3
		fi
		
		echo 224.4.$mc_addr_part_3.$mc_addr_part_4:$port >> $file_name
		mc_grp_ctr=$(($mc_grp_ctr+1))
		port=$(($port+1))
		mc_addr_part_4=$(($mc_addr_part_4+1))
	done
}

function create_mc_feed_files
{
	write_mc_feed_file $1 $2
	copy_feed_file_2_remote_machine	$2 >& /dev/null	
}

function copy_feed_file_2_remote_machine
{
	scp $1 	"$REM_HOST_IP:/$TMP_DIR"
}

function remove_mc_feed_files
{
	rm -f $1 >& /dev/null 
	ssh $REM_HOST_IP "rm -f $1" >& /dev/null
}

function run_iperf
{
	if [[ $iperf_is_installed -ne $TRUE ]]; then
		echo "$ERORR_PROMT iperf tool not found on one of the machines, skipping iperf test"
	else
		run_iperf_with_diff_msg_len
	fi	
}


function check_if_iperf_avaibale
{
	local_iperf_is_installed=$FALSE	
	remote_iperf_is_installed=$FALSE
	iperf_is_installed=$FALSE	
	which iperf 2>$TMP_FILE.err 1>/dev/null
	check_command_succss
	if [[ $SUCCSESS -ne $FALSE ]]; then
		local_iperf_is_installed=$TRUE
	else
		echo "$ERORR_PROMT iperf not found on local machine "			
	fi

	ssh $REM_HOST_IP "which iperf" 2>$TMP_FILE.err 1>/dev/null
	check_command_succss					
	if [[ $SUCCSESS -ne $FALSE ]]; then
		remote_iperf_is_installed=$TRUE
	else
		echo "$ERORR_PROMT iperf not found on remote machine "		
	fi
	
	if [[ $local_iperf_is_installed -eq $TRUE ]]; then
		if [[ $remote_iperf_is_installed -eq $TRUE ]]; then
			iperf_is_installed=$TRUE
		fi	
	fi
}

function clean
{
	rm -f $TMP_FILE.err >& /dev/null 
	rm -f "$TMP_DIR/$log_file.prep" >& /dev/null 
	rm -f "$TMP_DIR/$log_file.post" >& /dev/null	
	ssh $REM_HOST_IP rm -f "$TMP_DIR/$log_file.tmp" >& /dev/null
	rm -rf $TMP_FILE >& /dev/null
}

function write_date_2_log_file
{
	echo "=============================>Date<===========================" >> "$log_file"
	(echo "${SRV_CMMND_LINE_PREF} date" | tee -a "$log_file") >& /dev/null
	(date | tee -a $log_file) >& /dev/null
}

function pre_vma_perf
{	
	pre_test_checks
	get_hostnames
	prepare_output_files
	write_date_2_log_file
	collect_nodes_info_to_file "$log_file"	
	prepare_route_table
	save_shmem_prop
	increase_number_of_hugetlb
	save_umcast
	update_umcast
	clean			
	update_command_prefix		
}

function final_test_message
{
	echo "####################### Generated files #######################"
	echo "#Test results	:	$res_file"
	echo "#Test logs	:	$log_file"
	echo "---------------------------------------------------------------"
}

function post_vma_perf
{
	collect_nodes_info_to_file "$res_file"	
	recreate_route_table
	recreate_mem_prop
	recreate_umcast
	final_test_message
	write_date_2_log_file
	clean	
}

function vma_perf
{
	run_udp_lat_with_diff_msg_len
	run_udp_lat_tx_bw_with_diff_msg_len
	run_udp_lat_bw_with_diff_msg_len
	run_udp_lat_with_diff_burst_size
	run_iperf
	run_udp_lat_using_select_epoll_poll_with_zero_polling
	run_udp_lat_using_select_epoll_poll_with_full_polling_vma_only
}	

#main

if [ $# = 1 ]; then
	block      
        pre_vma_perf
	vma_perf
	post_vma_perf
	unblock
else
      echo "Usage: perf <ip of remote host>"
      exit
fi
