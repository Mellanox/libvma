#!/bin/bash -eEx

source $(dirname $0)/globals.sh

check_filter "Checking for test ..." "on"

cd $WORKSPACE

rm -rf $test_dir
mkdir -p $test_dir
cd $test_dir

git clone https://github.com/Mellanox/sockperf.git sockperf
cd sockperf
./autogen.sh
./configure --prefix=$PWD/install
make install
test_app="$PWD/install/bin/sockperf"

if [ $(command -v $test_app >/dev/null 2>&1 || echo $?) ]; then
    echo can not find $test_app
    exit 1
fi

test_ip_list="$(get_ip 'ib') $(get_ip 'eth')"
test_list="tcp-pp tcp-tp tcp-ul udp-pp udp-tp udp-ul"
test_lib=$install_dir/lib/libvma.so

nerrors=0

for test_ip in $test_ip_list; do
	for test in $test_list; do
		test_name=${test_ip}-${test}
		test_tap=${WORKSPACE}/${prefix}/test-${test_name}.tap
		
		$timeout_exe $PWD/tests/verifier/verifier.pl -a ${test_app} -x " --load-vma=$test_lib " \
			-t ${test}:tc[1-9]$ -s ${test_ip} -l ${test_dir}/${test_name}.log \
			-e " VMA_TX_BUFS=20000 VMA_RX_BUFS=20000 " \
			--progress=0
		
		cp $PWD/${test_name}.dump ${test_dir}/${test_name}.dump
		grep -e 'PASS' -e 'FAIL' ${test_dir}/${test_name}.dump > ${test_dir}/${test_name}.tmp
		
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
		
		    echo -e "$v0 $v1 - $v2" >> $test_tap
		    v1=$(($v1+1))
		done < ${test_dir}/${test_name}.tmp
		rm -f ${test_dir}/${test_name}.tmp
	done
done

rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
