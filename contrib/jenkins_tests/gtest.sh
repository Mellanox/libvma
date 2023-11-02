#!/bin/bash -eExl

source $(dirname $0)/globals.sh

echo "Checking for gtest ..."

# Check dependencies
if [ $(test -d ${install_dir} >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] Not found ${install_dir} : build should be done before this stage"
	exit 1
fi

if [ $(command -v ibdev2netdev >/dev/null 2>&1 || echo $?) ]; then
	echo "[SKIP] ibdev2netdev tool does not exist"
	exit 1
fi

cd $WORKSPACE

rm -rf $gtest_dir
mkdir -p $gtest_dir
cd $gtest_dir

gtest_app="$PWD/tests/gtest/gtest"
gtest_lib=$install_dir/lib/${prj_lib}

gtest_ip_list=""
if [ ! -z $(do_get_ip 'eth') ]; then
	gtest_ip_list="$(do_get_ip 'eth')"
fi
if [ ! -z $(do_get_ip 'eth' '' $gtest_ip_list) ]; then
	gtest_ip_list="${gtest_ip_list}:$(do_get_ip 'eth' '' $gtest_ip_list)"
else
	echo "[SKIP] two eth interfaces are required. found: ${gtest_ip_list}"
	exit 0
fi
gtest_opt="--addr=${gtest_ip_list}"

set +eE

${WORKSPACE}/configure --prefix=$install_dir
make -C tests/gtest
rc=$(($rc+$?))

eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"
eval "${sudo_cmd} ${install_dir}/sbin/${prj_service} --console -v5 &"

# Exclude VMA EXTRA API tests
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=-vma_*:tcp_send_zc* --gtest_output=xml:${WORKSPACE}/${prefix}/test-basic.xml"
rc=$(($rc+$?))
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=keep_alive* --gtest_output=xml:${WORKSPACE}/${prefix}/test-keepalive.xml"
rc=$(($rc+$?))

make -C tests/gtest clean
make -C tests/gtest CPPFLAGS="-DEXTRA_API_ENABLED=1"
rc=$(($rc+$?))

# Verify VMA EXTRA API tests
eval "${sudo_cmd} $timeout_exe env GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=vma_*:-vma_poll.*:vma_ring.*:vma_send_zc.* --gtest_output=xml:${WORKSPACE}/${prefix}/test-extra.xml"
rc=$(($rc+$?))

# Verify VMA EXTRA API socketxtreme mode tests
eval "${sudo_cmd} $timeout_exe env VMA_SOCKETXTREME=1 GTEST_TAP=2 LD_PRELOAD=$gtest_lib $gtest_app $gtest_opt --gtest_filter=vma_poll.*:vma_ring.* --gtest_output=xml:${WORKSPACE}/${prefix}/test-socketxtreme.xml"
rc=$(($rc+$?))

eval "${sudo_cmd} pkill -9 ${prj_service} 2>/dev/null || true"

set -eE

for f in $(find $gtest_dir -name '*.tap')
do
    cp $f ${WORKSPACE}/${prefix}/gtest-$(basename $f .tap).tap
done

echo "[${0##*/}]..................exit code = $rc"
exit $rc
