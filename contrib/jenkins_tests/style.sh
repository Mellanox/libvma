#!/bin/bash -xeEl

source $(dirname $0)/globals.sh

echo "Checking for codying style ..."

cd $WORKSPACE

rm -rf $style_dir
mkdir -p $style_dir
cd $style_dir

stoplist_pattern=${stoplist_pattern:="WARNING"}

checkpatch=/hpc/local/scripts/checkpatch/checkpatch.pl
if [ ! -e $checkpatch ]; then
    set +e
    eval wget  --no-check-certificate https://raw.githubusercontent.com/torvalds/linux/master/scripts/checkpatch.pl
    ret=$?
    if [ $ret -gt 0 ]; then break; fi
    eval wget  --no-check-certificate https://github.com/torvalds/linux/blob/master/scripts/spelling.txt
    ret=$?
    if [ $ret -gt 0 ]; then break; fi
    chmod +x checkpatch.pl
    set -e
    checkpatch=$style_dir/checkpatch.pl
fi

if [ -e $checkpatch ]; then

    style_tap=${WORKSPACE}/${prefix}/style_test.tap
    rm -rf $style_tap
    check_files=$(find $WORKSPACE/src/state_machine/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/stats/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vlogger/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/dev/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/event/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/infra/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/iomux/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/netlink/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/proto/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma/sock/ -name '*.c' -o -name '*.cpp' -o -name '*.h')
    check_files+=" "
    check_files+=$(find $WORKSPACE/src/vma -name '*.c' -o -name '*.cpp' -o -name '*.h')

    echo "1..$(echo $check_files | wc -w)" > $style_tap
    i=0
    status="success"
    nerrors=0

    for file in $check_files; do
        set +e
        ret=$(perl -X $checkpatch --file --terse --no-tree $file | grep -v -w $stoplist_pattern| wc -l)
        nerrors=$((nerrors+ret))
        set -e
        i=$((i+1))

        fix_file=$(echo $file|sed -e s,$WORKSPACE/,,g)

        if [ $ret -gt 0 ]; then
            echo "not ok $i $fix_file # TODO" >> $style_tap
            #status="error"
            info="checkpatch.pl detected $nerrors style errors"
        else
            echo "ok $i $fix_file" >> $style_tap
        fi
    done

    rc=$(($rc+$nerrors))

fi

echo "[${0##*/}]..................exit code = $rc"
exit $rc
