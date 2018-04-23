#!/bin/bash -eExl

source $(dirname $0)/globals.sh

do_check_filter "Checking for valgrind ..." "on"

do_module "tools/valgrind-3.12.0"

set +eE

cd $WORKSPACE
rm -rf $vg_dir
mkdir -p $vg_dir
cd $vg_dir

${WORKSPACE}/configure --prefix=${vg_dir}/install --with-valgrind $jenkins_test_custom_configure

make $make_opt all
make install
rc=$?


test_ip_list=""
#if [ ! -z $(do_get_ip 'ib' 'mlx5') ]; then
#	test_ip_list="${test_ip_list} ib:$(do_get_ip 'ib' 'mlx5')"
#fi
if [ ! -z "$(do_get_ip 'eth' 'mlx5')" ]; then
	test_ip_list="${test_ip_list} eth:$(do_get_ip 'eth' 'mlx5')"
fi
test_list="tcp:--tcp udp:"
test_lib=${vg_dir}/install/lib/libvma.so
test_app=sockperf
test_app_path=${test_dir}/sockperf/install/bin/sockperf

if [ $(command -v $test_app_path >/dev/null 2>&1 || echo $?) ]; then
	test_app_path=sockperf
	if [ $(command -v $test_app_path >/dev/null 2>&1 || echo $?) ]; then
		echo can not find $test_app_path
		exit 1
	fi
fi

vg_tap=${WORKSPACE}/${prefix}/vg.tap
v1=$(echo $test_list | wc -w)
v1=$(($v1*$(echo $test_ip_list | wc -w)))
echo "1..$v1" > $vg_tap

nerrors=0

for test_link in $test_ip_list; do
	for test in $test_list; do
		IFS=':' read test_n test_opt <<< "$test"
		IFS=':' read test_in test_ip <<< "$test_link"
		test_name=${test_in}-${test_n}

		vg_args="-v \
			--memcheck:leak-check=full --track-origins=yes --read-var-info=yes \
			--errors-for-leak-kinds=definite --show-leak-kinds=definite,possible \
			--undef-value-errors=yes --track-fds=yes --num-callers=32 \
			--fullpath-after=${WORKSPACE} --gen-suppressions=all \
			--suppressions=${WORKSPACE}/contrib/valgrind/valgrind_vma.supp \
			"
		eval "LD_PRELOAD=$test_lib \
			valgrind --log-file=${vg_dir}/${test_name}-valgrind-sr.log $vg_args \
			$test_app_path sr ${test_opt} -i ${test_ip} > /dev/null 2>&1 &"
		sleep 20
		eval "LD_PRELOAD=$test_lib \
			valgrind --log-file=${vg_dir}/${test_name}-valgrind-cl.log $vg_args \
			$test_app_path pp ${test_opt} -i ${test_ip} -t 10"

		if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
		then
			sudo pkill -SIGINT -f $test_app 2>/dev/null || true
			sleep 10
			# in case SIGINT didn't work
			if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
			then
				sudo pkill -SIGTERM -f $test_app 2>/dev/null || true
				sleep 3
			fi
			if [ `ps -ef | grep $test_app | wc -l` -gt 1 ];
			then
				sudo pkill -SIGKILL -f $test_app 2>/dev/null || true
			fi
		fi

		ret=$(cat ${vg_dir}/${test_name}-valgrind*.log | awk '/ERROR SUMMARY: [0-9]+ errors?/ { sum += $4 } END { print sum }')

		do_archive "${vg_dir}/${test_name}-valgrind*.log"

		if [ $ret -gt 0 ]; then
			echo "not ok ${test_name}: valgrind Detected $ret failures # ${vg_dir}/${test_name}-valgrind*.log" >> $vg_tap
			grep -A 10 'LEAK SUMMARY' ${vg_dir}/${test_name}-valgrind*.log >> ${vg_dir}/${test_name}-valgrind.err
			cat ${vg_dir}/${test_name}-valgrind*.log
			do_err "valgrind" "${vg_dir}/${test_name}-valgrind.err"
		else
			echo ok ${test_name}: Valgrind found no issues >> $vg_tap
		fi
		nerrors=$(($ret+$nerrors))
	done
done

if [ $nerrors -gt 0 ]; then
	info="Valgrind found $nerrors errors"
	status="error"
else
	info="Valgrind found no issues"
	status="success"
fi

vg_url="$BUILD_URL/valgrindResult/"

if [ -n "$ghprbGhRepository" ]; then
	context="MellanoxLab/valgrind"
	do_github_status "repo='$ghprbGhRepository' sha1='$ghprbActualCommit' target_url='$vg_url' state='$status' info='$info' context='$context'"
fi

module unload tools/valgrind-3.12.0

rc=$(($rc+$nerrors))
set -eE
echo "[${0##*/}]..................exit code = $rc"
exit $rc
