#!/bin/sh

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(dirname $0)
SCRIPT_DIR=$(cd $SCRIPT_DIR;pwd)
VMA_DIR=vma
REV=HEAD
URL=`svn info|grep URL|awk -F " "  '{print $2'}|rev|cut -d '/' -f2-|rev`

function print_usage_and_exit
{
	echo "" 
	echo "#################### get_src ####################"
      	echo ""
	echo "Usage:"
       	echo "		./get_src [OPTIONS]"
       	echo "		./get_src [-r revision] [-u url] [-h help]"
       	echo "Options:"
       	echo "		-r=<NUM>	checkout to NUM revision"
       	echo "		-u=<URL>	checkout from URL"
       	echo "		-h		print this help and exit"
       	echo ""
	exit "$1"

}

while getopts ":r:u:h" options; do
	case $options in
    		r ) 	REV=$OPTARG;;
    		u ) 	URL=$OPTARG;;
    		h ) 	print_usage_and_exit 0;;
    		\? )	print_usage_and_exit 0;;
    		* ) 	print_usage_and_exit 1;;
	esac
done

if [[ $URL != *'/' ]]; then
	URL="${URL}/"
fi

SVN_DIR=`echo $URL|rev|cut -d '/' -f2 |rev`
rm -rf $VMA_DIR > /dev/null > /dev/null 2>&1
#mkdir $MCE_DIR
#cd $MCE_DIR
svn co  $URL -r $REV
mv $SVN_DIR $VMA_DIR
