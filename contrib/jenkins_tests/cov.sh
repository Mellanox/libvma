#!/bin/bash -eE

source $(dirname $0)/globals.sh

check_filter "Checking for coverity ..." "off"

cd $WORKSPACE

rm -rf $cov_dir
mkdir -p $cov_dir
cd $cov_dir

cov_exclude_file_list="test"

module load tools/cov

cov_build_id="cov_build_${BUILD_NUMBER}"
cov_build="$cov_dir/$cov_build_id"

set +eE

${WORKSPACE}/configure --prefix=$install_dir $jenkins_test_custom_configure -C
cov-build --dir $cov_build make $make_opt

set +eE
for excl in $cov_exclude_file_list; do
    cov-manage-emit --dir $cov_build --tu-pattern "file('$excl')" delete
done
set -eE

cov-analyze --dir $cov_build --config ${WORKSPACE}/coverity_vma_config.xml

set -eE

cov_web_path="$(echo $cov_build | sed -e s,$WORKSPACE,,g)"
nerrors=$(cov-format-errors --dir $cov_build | awk '/Processing [0-9]+ errors?/ { print $2 }')
rc=$(($rc+$nerrors))

index_html=$(cd $cov_build && find . -name index.html | cut -c 3-)
cov_url="$WS_URL/$cov_web_path/${index_html}"
cov_file="$cov_build/${index_html}"

filtered_nerrors=0
rm -f jenkins_sidelinks.txt

coverity_tap=${WORKSPACE}/${prefix}/coverity.tap
echo 1..1 > $coverity_tap
if [ $nerrors -gt 0 ]; then

    cat $cov_file  | grep -i -e '</\?TABLE\|</\?TD\|</\?TR\|</\?TH' | \
                     sed 's/^[\ \t]*//g' | tr -d '\n' | \
                     sed 's/<\/TR[^>]*>/\n/Ig'  | \
                     sed 's/<\/\?\(TABLE\|TR\)[^>]*>//Ig' | \
                     sed 's/^<T[DH][^>]*>\|<\/\?T[DH][^>]*>$//Ig' | \
                     sed 's/<\/T[DH][^>]*><T[DH][^>]*>/%/Ig' | \
                     cut -d"%" -f2,4 > $cov_build/index.csv

    filter_csv="$WORKSPACE/contrib/jenkins_tests/filter.csv"

    FILTER="grep -F -x -v -f $filter_csv $cov_build/index.csv"
    filtered_nerrors=`$FILTER | wc -l`

fi

if [ $filtered_nerrors -gt 0 ]; then
    echo "not ok 1 Coverity Detected $filtered_nerrors failures # $cov_url" >> $coverity_tap
    info="Coverity found $filtered_nerrors errors"
    status="error"
else
    echo ok 1 Coverity found no issues >> $coverity_tap
    info="Coverity found no issues"
    status="success"
fi

if [ -n "$ghprbGhRepository" ]; then
    context="MellanoxLab/coverity"
    do_github_status "repo='$ghprbGhRepository' sha1='$ghprbActualCommit' target_url='$cov_url' state='$status' info='$info' context='$context'"
fi

echo Coverity report: $cov_url
printf "%s\t%s\n" Coverity $cov_url >> jenkins_sidelinks.txt

module unload tools/cov
