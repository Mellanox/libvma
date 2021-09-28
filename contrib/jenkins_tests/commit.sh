#!/bin/bash -xeEl

source $(dirname $0)/globals.sh

echo "Checking for commit message ..."

cd $WORKSPACE

rm -rf $commit_dir
mkdir -p $commit_dir
cd $commit_dir

commit_tap=${WORKSPACE}/${prefix}/commit_test.tap
rm -rf $commit_tap
out_log=${commit_dir}/output.log

function current_head()
{
     echo ${ghprbActualCommit:=HEAD}
}

function current_ancestor()
{
    git merge-base origin/master HEAD
}

function current_commits()
{
    git log --pretty=%H $(current_ancestor)..$(current_head)
}

function check_commit()
{
    echo "1..$(echo $(current_commits) | tr " " "\n" | wc -l)" > $commit_tap
    nerrors=0
    test_id=1

    for sha in $(current_commits); do
        ret=0
        test_name=$(echo ${sha:0:7})

        echo "#${test_id} commit: ${test_name}" >>${out_log} 2>&1

        commit_subject=$(git log --format=%B -n 1 "${sha}" | head -n2)
        commit_body=$(git log --format=%B -n 1 "${sha}" | awk '{if(NR>2)print}')

        if [ 0 -eq "${#commit_subject}" -o "${#commit_subject}" -gt 72 ]; then
            echo "Commit message subject should be less than 72 characters" >>${out_log} 2>&1
            ret=$((ret+1))
        fi

        if [[ "${commit_subject}" == *. ]]; then
            echo "Commit message subject should not have period at the end" >>${out_log} 2>&1
            ret=$((ret+1))
        fi

        if [ -z "$(echo ${commit_body} | grep 'Signed-off-by')" ]; then
            echo "Commit message body should have 'Signed-off-by'" >>${out_log} 2>&1
            ret=$((ret+1))
        fi

        if [ $ret -eq 0 ]; then
            echo -e "ok ${test_name}" >> $commit_tap
        else
            echo -e "not ok ${test_name}: error ${ret} see ${out_log}" >> $commit_tap
            nerrors=$(($ret+$nerrors))
            ret=0
        fi

        test_id=$((test_id+1))
    done
}

check_commit

do_archive "${out_log}"
rc=$(($rc+$nerrors))

echo "[${0##*/}]..................exit code = $rc"
exit $rc
