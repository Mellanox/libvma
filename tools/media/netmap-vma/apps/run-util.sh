#!/bin/bash

IF="ens4f0"

VMA_TOP_DIR=../../../..

PRELOAD="LD_PRELOAD=${VMA_TOP_DIR}/src/vma/.libs/libvma.so"

LD_PATH="LD_LIBRARY_PATH=.."

APP=nm-ex1
PORT=""

run_test()
{
	sh -c "${PRELOAD} ${LD_PATH} ./${APP} netmap:${IF}-1/R${PORT}"
}

usage()
{
cat << eOm
	usage:$0 -r -rvma
eOm
}

case "$1" in
	-r)
		PRELOAD=""; LD_PATH=""
		run_test
		;;
	-rvma)
		APP+="-vma"; PORT=":2000"
		run_test
		;;
	*)
		usage
		exit 0
		;;
esac

# </run-util.sh>
