#!/bin/sh

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(dirname $0)
SCRIPT_DIR=$(cd $SCRIPT_DIR;pwd)
APP_NAME=vma
VMA_DIR=$APP_NAME
cd $SCRIPT_DIR

REVISION=`svn info $VMA_DIR|grep "Last Changed Rev"|awk -F ": "  '{print $2}'`
DATE=`svn info $VMA_DIR|grep "Last Changed Date"|awk -F " "  '{print $4}'`
TIME=`svn info $VMA_DIR|grep "Last Changed Date"|awk -F " "  '{print $5}'`

grep -e "VMA_LIBRARY_MAJOR=" -e "VMA_LIBRARY_MINOR=" -e "VMA_LIBRARY_REVISION=" -e "VMA_LIBRARY_RELEASE=" $VMA_DIR/configure.ac |head -4 > temp
. ./temp
VERSION=$VMA_LIBRARY_MAJOR.$VMA_LIBRARY_MINOR.$VMA_LIBRARY_REVISION

#VERSION=`grep "VMA_VERSION" $VMA_DIR/version.h |awk -F "\""  '{print $2'}`
#RELEASE=`grep "VMA_RELEASE" $VMA_DIR/version.h |awk -F "\""  '{print $2'}`

VMA_DIR_NAME=libvma-$VERSION

if [ $# -lt 1 ]; then
  RPM_DIR=$(rpm --eval '%{_topdir}');
else
  RPM_DIR=$1;
fi

sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g' -e 's/__REVISION/'$REVISION'/g' -e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' -e 's/__MAJOR/'$VMA_LIBRARY_MAJOR'/g' $APP_NAME.spec > $APP_NAME-$VERSION.spec

sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g' -e 's/__REVISION/'$REVISION'/g' -e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' $VMA_DIR/vma_version_template > $VMA_DIR/VMA_VERSION

rm -f libvma*.tar.gz  > /dev/null > /dev/null 2>&1
rm -f $RPM_DIR/SRPMS/libvma*  > /dev/null > /dev/null 2>&1
rm -rf $VMA_DIR_NAME  > /dev/null > /dev/null 2>&1


mkdir $VMA_DIR_NAME
mkdir $VMA_DIR_NAME/build
cp -r build_vma_udp_rpm.sh $APP_NAME.spec $VMA_DIR_NAME/build
cp -r $VMA_DIR  $VMA_DIR_NAME/build/   # copy vma & udp_test
tar zcvf $VMA_DIR_NAME.tar.gz --exclude .svn $VMA_DIR_NAME > /dev/null > /dev/null 2>&1

sudo cp *.gz $APP_NAME-$VERSION.spec $RPM_DIR/SOURCES/ > /dev/null > /dev/null 2>&1
sudo rpmbuild --define "_topdir $RPM_DIR" -bs $APP_NAME-$VERSION.spec
 
rm -f $VMA_DIR_NAME.tar.gz temp > /dev/null > /dev/null 2>&1
rm -rf $VMA_DIR_NAME > /dev/null > /dev/null 2>&1
rm -rf $APP_NAME-$VERSION.spec > /dev/null > /dev/null 2>&1

if [  ! -f $RPM_DIR/SRPMS/libvma* ]; then
	exit 1
fi
echo $RPM_DIR/SRPMS/libvma*



