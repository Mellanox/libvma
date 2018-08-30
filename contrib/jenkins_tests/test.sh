#!/bin/bash -eExl

source $(dirname $0)/globals.sh

do_check_filter "Checking for test ..." "on"

if [ $(command -v ibdev2netdev >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] ibdev2netdev tool does not exist"
	exit 0
fi

cd $WORKSPACE

rm -rf $test_dir
mkdir -p $test_dir
cd $test_dir

do_cmd "wget -O sockperf_v2.zip https://github.com/Mellanox/sockperf/archive/sockperf_v2.zip && unzip sockperf_v2.zip && mv sockperf-sockperf_v2 sockperf"
cd sockperf

./autogen.sh
./configure --prefix=$PWD/install CPPFLAGS="-I${install_dir}/include"
make install
test_app="$PWD/install/bin/sockperf"

if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
	echo can not find $test_app
	exit 1
fi

test_ip_list=""
test_list="tcp-pp tcp-tp tcp-ul"
test_lib=$install_dir/lib/libvma.so

if [ ! -z "${test_remote_ip}" ] ; then
	[[ "${test_remote_ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {\
		echo ">> FAIL wrong ip address ${test_remote_ip}"
		exit 1
	}
	test_ip_list="eth:${test_remote_ip}"
	[ -z "${NODE_NAME}" ] && NODE_NAME=$(hostname)
	sperf_exec_dir="/tmp/sockperf_exec_${NODE_NAME}"
	rmt_user=root
 
	rmt_os=$(sudo ssh ${rmt_user}@${test_remote_ip} ". /etc/os-release ; echo \${NAME,,} | awk '{print \$1}'")
	[ ! -z "${test_remote_rebuild}" ] && rmt_os="rebuld"
	local_os=$(. /etc/os-release ; echo ${NAME,,} | awk '{print $1}')

	#skip_remote_prep=1
	if [ -z "${skip_remote_prep}" ] ; then
		sudo ssh ${rmt_user}@${test_remote_ip} "rm -rf ${sperf_exec_dir} && mkdir ${sperf_exec_dir}"

		if [[ "${rmt_os}" =~ .*"${local_os}".* ]] ; then
			sudo scp -q ${test_app} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			sudo scp -q ${test_lib} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			eval "pid=$(sudo ssh ${rmt_user}@${test_remote_ip} pidof vmad)"
			if [ ! -z "${pid}" ] ;  then 
				echo "vmad pid=${pid}"
				eval "sudo ssh ${rmt_user}@${test_remote_ip} kill -9 ${pid}"
			fi
			sudo scp -q ${install_dir}/sbin/vmad ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			eval "sudo ssh ${rmt_user}@${test_remote_ip} sudo ${sperf_exec_dir}/vmad &"
		else
			sudo -E rsync -q -I -a -r --exclude jenkins --exclude '*.o' --exclude '.deps' --exclude '*.l*' \
			-e ssh ${WORKSPACE} ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			sudo scp -q ${test_dir}/sockperf_v2.zip ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			if [ $? -eq 0 ] ; then
				subdir=${WORKSPACE##*/}
				cmd="cd ${sperf_exec_dir}/${subdir} && "
				cmd+="./autogen.sh && ./configure && make ${make_opt} && "
				cmd+="cp src/vma/.libs/*.so ${sperf_exec_dir} &&"
				cmd+="cd ${sperf_exec_dir} && "
				cmd+="unzip sockperf_v2.zip && cd sockperf-sockperf_v2 && "
				cmd+="./autogen.sh && ./configure && make ${make_opt} && cp sockperf ${sperf_exec_dir}"
				sudo ssh ${rmt_user}@${test_remote_ip} "${cmd}"
			else
				exit 1
			fi
		fi
	fi
else
	if [ ! -z $(do_get_ip 'ib') ]; then
		test_ip_list="${test_ip_list} ib:$(do_get_ip 'ib')"
	fi
	if [ ! -z $(do_get_ip 'eth') ]; then
		test_ip_list="${test_ip_list} eth:$(do_get_ip 'eth')"
	fi
fi

nerrors=0

for test_link in $test_ip_list; do
	for test in $test_list; do
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test}
		test_tap=${WORKSPACE}/${prefix}/test-${test_name}.tap

		if [ ! -z "${test_remote_ip}" ] ; then

			eval "pid=$(sudo pidof vmad)"
			[ ! -z "${pid}" ] && eval "sudo kill -9 ${pid}" 
			eval "sudo ${install_dir}/sbin/vmad --console -v5 & "

			echo "BUILD_NUMBER=${BUILD_NUMBER}"
			eval "pid=$(sudo ssh ${rmt_user}@${test_remote_ip} pidof vmad)"
			if [ ! -z "${pid}" ] ;  then
				echo "vmad pid=${pid}"
				eval "sudo ssh ${rmt_user}@${test_remote_ip} kill -9 ${pid}"
			fi
			sudo scp -q ${install_dir}/sbin/vmad ${rmt_user}@${test_remote_ip}:${sperf_exec_dir}
			eval "sudo ssh ${rmt_user}@${test_remote_ip} sudo ${sperf_exec_dir}/vmad &"

			vutil="$(dirname $0)/vutil.sh"
			[ ! -e "${vutil}" ] && { echo "error vutil not found" ; exit 1 ; }

			sudo $timeout_exe ${vutil}  -a "${test_app}" -x "--load-vma=${test_lib} " -t "${test}:tc[1-9]$" \
					-s "${test_remote_ip}" -p "${test_remote_port}" -l "${test_dir}/${test_name}.log" \
					-e "VMA_TX_BUFS=20000 VMA_RX_BUFS=20000"
	
		else
			$timeout_exe $PWD/tests/verifier/verifier.pl -a ${test_app} -x " --load-vma=$test_lib " \
				-t ${test}:tc[1-9]$ -s ${test_ip} -l ${test_dir}/${test_name}.log \
				-e " VMA_TX_BUFS=20000 VMA_RX_BUFS=20000 " \
				--progress=0
		fi

		cp $PWD/${test_name}.dump ${test_dir}/${test_name}.dump
		grep -e 'PASS' -e 'FAIL' ${test_dir}/${test_name}.dump > ${test_dir}/${test_name}.tmp

		do_archive "${test_dir}/${test_name}.dump" "${test_dir}/${test_name}.log"

		echo "1..$(wc -l < ${test_dir}/${test_name}.tmp)" > $test_tap

		v1=1
		while read line; do
		    if [[ $(echo $line | cut -f1 -d' ') =~ 'PASS' ]]; then
		        v0='ok'
		        v2=$(echo $line | sed 's/PASS //')
		    else
		        v0='not ok'
		        v2=$(echo $line | sed 's/FAIL //')
	            nerrors=$((nerrors+1))
		    fi

		    echo -e "$v0 ${test_in}: $v2" >> $test_tap
		    v1=$(($v1+1))
		done < ${test_dir}/${test_name}.tmp
		rm -f ${test_dir}/${test_name}.tmp
	done
done

rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
