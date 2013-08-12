#!/bin/bash

function usage {

cat << EOF

The building environment works on 4 possible modes:
	* Release
	* Daily
	* Local
	* Wrapper

usage: $0 options

GENERAL OPTIONS:
----------------
   -h      Show this message
   -r -R   Release mode 
   -w -W   Wrapper mode
   -d -D   Daily mode 
   -l -L   Local mode 

RELEASE MODE OPTIONS:
---------------------
   -r <svn folder> 
   
   Optional:
   -e -E   Check out specified revision <svn revision>
   -b -B   Build 2 rpms if 64 bit OS and is 32bit compatible
   -o -O   Override existing release
   -c -C   Make coverity

WRAPPER MODE OPTIONS:
---------------------
   -w <svn branches...> -f <machines' names...> ...
   
    can run this format "-w <svn branches...> -f <machines' names...>" several times in order to
    build different branches on several machines in the same run
    Example: ./build_vma_rpm.sh -w vma_6.1 -f alf1 alf2 -w vma_6.2 vma_6.3 -f alf3
           ==> will build vma_6.1 on alf1, alf2 and vma_6.2,vma_6.3 on alf3

DAILY MODE OPTIONS:
-------------------
   -d <svn folder>

   Optional:
   -e -E   Check out specified revision <svn revision>
   -s -S   Secure copy the rpms created to bgate
   -c -C   Make coverity
           
LOCAL MODE OPTIONS:
-------------------
   -l <target folder> 

   run the script from the HEAD of the workspace folder

   Optional:
   -n -N   Add a name to rpm <rpm's title>
   -b -B   Build 2 rpms if 64 bit OS and is 32bit compatible

EOF

exit 1

}

####################### NOT IN USE #######################
function sendErrorMailToUser { # NOT IN USE

user=`eval whoami`
EMAIL=""$user"@mellanox.com"
SUBJECT="ERROR IN BUILD VMA-RPM"
EMAILMESSAGE="/tmp/emailmessage.txt"
echo "An error occured while running vma_build_rpm.sh" >> $EMAILMESSAGE
echo "failed on step: $1" >> $EMAILMESSAGE
echo "see /tmp/build_vma_rpm.log for more information" >> $EMAILMESSAGE
/bin/mail -s "$SUBJECT" "$EMAIL" < $EMAILMESSAGE
rm -rf $EMAILMESSAGE
rm -rf $workspace_folder

}

function noRpmMail { # NOT IN USE

user=`eval whoami`
EMAIL=""$user"@mellanox.com"
SUBJECT="VMA Daily Build- no new rpm"
EMAILMESSAGE="/tmp/emailmessage.txt"
machine=`uname -n`
echo "Branch: $branch_folder, Machine: $machine" > $EMAILMESSAGE
echo "No changes from last daily rpm" >> $EMAILMESSAGE
/bin/mail -s "$SUBJECT" "$EMAIL" < $EMAILMESSAGE
rm -rf $EMAILMESSAGE

}

function rpmCreatedMail { # NOT IN USE

user=`eval whoami`
EMAIL=""$user"@mellanox.com"
SUBJECT="VMA Build- successful build"
EMAILMESSAGE="/tmp/emailmessage.txt"
echo "New rpm was created successfuly" > $EMAILMESSAGE
/bin/mail -s "$SUBJECT" "$EMAIL" < $EMAILMESSAGE
rm -rf $EMAILMESSAGE

}
####################### NOT IN USE #######################

function echoStep {

echo -e "\e[00;32m $1 \e[0m"

}

function echoMsgToUser {

echo -e "\e[00;34m $1 \e[0m"

}

function echoErr {

echo -e "\e[00;31m $1 \e[00m"

}

function echoDebug {

echo -e "\e[00;35m $1 \e[00m"

}

function isValidSvnBranch {

svn list $svn_branches > /tmp/svn_list.tmp
folder=$1
grep "^$folder\/$" /tmp/svn_list.tmp > /dev/null
if [[ $? != 0 ]]; then
	rm -f /tmp/svn_list.tmp
	return 1;
fi
rm -f /tmp/svn_list.tmp
return 0

}

function parseArguments {

RELEASE_MODE=0
DAILY_MODE=0
LOCAL_MODE=0
WRAPPER_MODE=0

BRANCH_INITIALIZED=0
branch_folder=
svn_branches="https://sirius.voltaire.com/repos/enterprise/mce/branches/"

mswg_vma_folder="/.autodirect/mswg/release/vma"
mswg_daily_folder="/.autodirect/mswg/release/vma/daily"

#MAIL_ALERT=0
LOG_SCRIPT_STATUS=0
log_file=
rpm_name=
co_svn_revision=
OVERRIDE=0
build_32=0
make_cov=0
copy_to_bgate=0

while getopts wWd:D:r:R:l:L:n:N:e:E:f:F:oObBsScCh OPTION
do
	case $OPTION in
		h) # help
			usage
		;;
		d|D|r|R) # daily \ release mode
			branch_folder=$OPTARG
			
			#### branch folder arg- checks that the requested branch folder exists under https://sirius.voltaire.com/repos/enterprise/mce/branches/
			isValidSvnBranch $branch_folder
			if [[ $? != 0 ]]; then
				echoErr "\"$branch_folder\" is illegal branch folder"
				echoErr "run \"svn list $svn_branches\" for the complete list"
				usage; 
			fi
			svn_folder="https://sirius.voltaire.com/repos/enterprise/mce/branches/$branch_folder"
			BRANCH_INITIALIZED=1

			#### sign which mode is selected
			if [[ $OPTION == "d" ]] || [[ $OPTION == "D" ]]; then
				DAILY_MODE=1;
			fi
			if [[ $OPTION == "r" ]] || [[ $OPTION == "R" ]]; then
				RELEASE_MODE=1;
			fi
		;;
		w|W)
			WRAPPER_MODE=1;
			checkLegalWrapperModeParams $@
			runWrapper $@;
		;;
		l|L) # local mode
			LOCAL_MODE=1
			target_dir=$OPTARG
			if [ ! -d $target_dir ]; then
				echoErr "folder $target_dir does not exist"
				usage; 
			fi
		;;
		c|C) # make coverity
			make_cov=1
		;;
		n|N) # rpm's name
			rpm_name="-$OPTARG"
		;;
		e|E) # check out specified revision
			co_svn_revision="-r $OPTARG"
		;;
		
                f|F) # log the status of the script (success/failiure) to a log file
		        LOG_SCRIPT_STATUS=1
			log_file=$OPTARG
               ;;
		b|B) # build 2 rpms if 64 bit OS and is 32bit compatible
                        build_32=1;
                ;;
#		m|M) # mail errors to user
#			MAIL_ALERT=1
#		;;
		o|O) # override existing release
			OVERRIDE=1
		;;
		s|S) # copy rpms to bgate, if on daily mode
			copy_to_bgate=1
		;;
		?)
			usage
		;;
	esac
done

#### on daily mode- build_32 if possible
if [ $DAILY_MODE == 1 ]; then 
	build_32=1;
fi

#### check if arguments are valid ####
total_modes=$(( $DAILY_MODE + $RELEASE_MODE + $LOCAL_MODE + $WRAPPER_MODE )) # exactly one mode can be chosen
if [ $total_modes != 1 ]; then
	echoErr "Please choose exactly one mode- daily/release/local/wrapper"
	usage
fi

if [ ! -x $rpm_name ] && [ $LOCAL_MODE != 1 ]; then # costumer's name argument was added but not on local mode
	echoErr "-n flag is available only when using -l (local mode)"
	usage
fi

if [ $OVERRIDE == 1 ] && [ $RELEASE_MODE != 1 ]; then # override argument was added but not on release mode
        echoErr "-o flag is available only when using -r (release mode)"
        usage
fi

if [ ! -x "$co_svn_revision" ] && [ $LOCAL_MODE == 1 ]; then # costumer's name argument was added but not on local mode
        echoErr "-e flag is available only when using -r (release mode) or -d (daily mode)"
        usage
fi

if [ $LOG_SCRIPT_STATUS == 1 ] && [ $LOCAL_MODE == 1 ]; then
	echoErr "-f flag is available only when using -r (release mode) or -d (daily mode)"
	usage
fi

if [ $copy_to_bgate == 1 ] && [ $DAILY_MODE != 1 ]; then # copy to bgate available only on daily mode
	echoErr "-s flag is available only when using -d (daily mode)"
        usage
fi

if [ $make_cov == 1 ] && [ $LOCAL_MODE == 1 ]; then
	echoErr "-c flag is available only when using -r (release mode) or -d (daily mode)"
	usage
fi

if [ "$branch_folder" != "vma_6.3" ]; then #only vma_6.3 can be build with coverity
	make_cov=0
fi

}


function cleanFilesAndExit {

#### clear the workspace folder (svn_co_tmp) if the script is on daily/release mode
if [ ! $LOCAL_MODE == 1 ]; then
        rm -rf $workspace_folder;
fi

exit 1
}

function errorOccured {

#### clear the workspace folder (svn_co_tmp) if the script is on daily/release mode
if [ ! $LOCAL_MODE == 1 ]; then
	rm -rf $workspace_folder;
fi

echoErr "failed on step: $1"
echoErr "see /tmp/build_vma_rpm.log for more information"
#if [ $MAIL_ALERT == 1 ]; then
#	sendErrorMailToUser $1;
#fi

if [ -x $2 ]; then
	build32=
else
	build32=", BUILD_32="$2""
fi

if [ "$LOG_SCRIPT_STATUS" == 1 ]; then
	machine=`uname -n`
        echo "Machine: $machine $build32- failed on step: $1" >> $log_file
fi

}

function mailScriptStatus {

EMAIL="sw-dev-vma@mellanox.com mellanox-CSA-team@asaltech.com"
#EMAIL="oritm@mellanox.com" # for debug
SUBJECT="VMA Daily Build"

# Left in case we want to add the logs as attachments
#ls ~/*_$DATE.log
#if [ $? == 0 ]; then
#	mutt -s "$SUBJECT" `for file in ~/*_$DATE.log; do echo -n "-a ${file} "; done` "$EMAIL" < ~/script_status
#	rm -f ~/*_$DATE.log
#else
#	/bin/mail -s "$SUBJECT" "$EMAIL" < ~/script_status
#fi

/bin/mail -s "$SUBJECT" "$EMAIL" < ~/script_status

rm -f ~/script_status

}

function svn_co {

mkdir $workspace_folder
chmod 777 $workspace_folder
cd $workspace_folder

#### check out last revision from the requested branch or the revision specified
echoStep "svn co $co_svn_revision $svn_folder"

svn co $co_svn_revision $svn_folder clean 2>&1 | tee -a /tmp/build_vma_rpm.log
if [[ $? != 0 ]]; then 
	errorOccured "svn co $svn_folder"
	finishScript; 
fi

cd clean
svn_revision=`svn info |grep Revision: |cut -c11-`

}

function set_topdir {

#check _topdir folder
redhatFlag=0
suseFlag=0
distribution=$(cat /etc/issue | grep "Red Hat")
if [ "$distribution" != "" ]; then
	topdir="/usr/src/redhat"
	redhatFlag=1
else
	topdir="/usr/src/packages"
	suseFlag=1
fi

}

function getVmaParamsFromConfigure.ac {

#grep_line=$(grep 'define(\[vma_ver_major\]' configure.ac)
#vma_ver_major=$(echo $grep_line | egrep "[0-9]{1,}" -o)

#grep_line=$(grep 'define(\[vma_ver_minor\]' configure.ac)
#vma_ver_minor=$(echo $grep_line | egrep "[0-9]{1,}" -o)

#grep_line=$(grep 'define(\[vma_ver_revision\]' configure.ac)
#vma_ver_revision=$(echo $grep_line | egrep "[0-9]{1,}" -o)

#grep_line=$(grep 'define(\[vma_ver_release\]' configure.ac)
#vma_ver_release=$(echo $grep_line | egrep "[0-9]{1,}" -o)

grep_line=$(egrep "VMA_LIBRARY_MAJOR=[0-9]{1,}" configure.ac)
vma_ver_major=$(echo $grep_line | awk -F '=' '{print $2}')

grep_line=$(egrep "VMA_LIBRARY_MINOR=[0-9]{1,}" configure.ac)
vma_ver_minor=$(echo $grep_line | awk -F '=' '{print $2}')

grep_line=$(egrep "VMA_LIBRARY_REVISION=[0-9]{1,}" configure.ac)
vma_ver_revision=$(echo $grep_line | awk -F '=' '{print $2}')

grep_line=$(egrep "VMA_LIBRARY_RELEASE=[0-9]{1,}" configure.ac)
vma_ver_release=$(echo $grep_line | awk -F '=' '{print $2}')

}

function areFilesUpdated {

jurnal_version=`cat journal.txt | head -1 | cut -d' ' -f2-`
configure_version=`echo "Version $vma_ver_major.$vma_ver_minor.$vma_ver_revision-$vma_ver_release" | cut -d' ' -f2-`
if [[ $jurnal_version != $configure_version ]]; then
	echoMsgToUser "Configure.ac or journal.ac are not updated"
	echoMsgToUser "version defined in configure.ac = $configure_version"
	echoMsgToUser "version defined in journal.txt = $jurnal_version"
	echoMsgToUser "Do you want to continue anyway?"
	while true; do
                        read yn
                        case $yn in
                        y|Y ) break;;
                        n|N ) cleanFilesAndExit;;
                        * ) echo "Please answer y or n";;
                    	esac
                done
fi

}

function isReleaseExists {

mswg_vma_version_folder="vma_v_"$vma_ver_major"."$vma_ver_minor"."$vma_ver_revision"-"$vma_ver_release"_r_"$svn_revision""
if [[ $OVERRIDE == 0 ]]; then
	ls $mswg_vma_folder | grep $mswg_vma_version_folder
	if [[ $? == 0 ]]; then
		echoMsgToUser "This version already exist: $mswg_vma_folder/$mswg_vma_version_folder"
		echoMsgToUser "Do you want to continue (a new svn revision will be created instead)? y/n"
		while true; do
			read yn
			case $yn in
			y|Y ) 
				rm -rf $mswg_vma_folder/$mswg_vma_version_folder
				break;;
			n|N ) cleanFilesAndExit;;
			* ) echo "Please answer y or n";;
			esac
		done
	fi
fi
cd $mswg_vma_folder
rm -rf "$mswg_vma_version_folder"
cd -

}

function build_vma_src_rpm {

APP_NAME=vma
VMA_DIR=$APP_NAME

cd ..
echoStep `pwd`
REVISION=`svn info |grep "Last Changed Rev"|awk -F ": "  '{print $2}'`
DATE=`svn info |grep "Last Changed Date"|awk -F " "  '{print $4}'`
TIME=`svn info |grep "Last Changed Date"|awk -F " "  '{print $5}'`
cd build

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
#sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g' -e 's/__REVISION/'$REVISION'/g' -e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' -e 's/__MAJOR/'$VMA_LIBRARY_MAJOR'/g' $APP_NAME.spec > $APP_NAME-$VERSION.spec

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

}

function checkLegalWrapperModeParams {

if [ $# -eq 0 ]; then
        usage;
fi
machines=0
firstFlag=1
numOfBranches=0
numOfMachines=0
i=0
j=0

for PARAM in $@; do
        if [ $PARAM == "-w" ]; then
                if [ $firstFlag == 1 ]; then
                        firstFlag=0;
                        continue
                fi
                if [ "$numOfBranches" == "0" ]; then
                        usage;
                fi
                if [ "$numOfMachines" == "0" ]; then
                        usage;
                fi

                numOfBranches=0
                numOfMachines=0
                i=0
                j=0
                machines=0
                continue
        fi
        if [ $PARAM == "-f" ]; then
                machines=1;
                continue
        fi
        if [ $machines == 1 ]; then
                eval machine_$i=$PARAM
                curr_machine=$(eval echo \$machine_$i)
                ping -c 1 $curr_machine
                if [ $? != 0 ]; then
                        echoErr "\"$curr_machine\" is illegal machine"
                        usage;
                fi
                i=`expr $i + 1`
                numOfMachines=`expr $i`
        else
                eval build_branch_$j=$PARAM
                curr_build_branch=$(eval echo \$build_branch_$j)
                isValidSvnBranch $curr_build_branch
                if [[ $? != 0 ]]; then
                        echoErr "\"$curr_build_branch\" is illegal branch folder"
                        echoErr "run \"svn list $svn_branches\" for the complete list"
                        usage;
                fi
                j=`expr $j + 1`
                numOfBranches=`expr $j`
        fi
done

if [[ "$numOfBranches" == "0"  ||  "$numOfMachines" == "0" ]]; then
        usage;
fi

}

#if there is no new commit for the input branch argument, no need to build new rpm
function needToBuildDaily {

branch_folder=$1
last_daily=`ls -Atr /.autodirect/mswg/release/vma/daily/"$branch_folder"/ | tail -1` #last daily rpm created
if [[ $? != 0 ]]; then # folder doesn't exist
        return 0;
fi
commitDate=`svn log -r 'COMMITTED' | grep ^r | grep -Po '\d{4}[\-]\d{2}[\-]\d{2}'` #date of last commit
DATE=`date +""%Y"-"%m"-"%d""` #today's date

#if last commit is not from today, and rpm was created since last commit- no need to build new rpm
if [ "$commitDate" != "$DATE" ]; then
        if [ "$last_daily" \> "$commitDate" ] || [ "$last_daily" == "$commitDate" ]; then
                echoMsgToUser "revision did not change- no need to build again"
                echo "revision did not change- no new rpm" >> ~/script_status
                return 1; #nothing changed
        fi
fi

return 0

}

function runWrapper {

script=`basename $0`
script_dir=`dirname $0`
if [[ $script_dir == /* ]]; then # absolute path
	full_path_script="$script_dir/$script"
else
	if [ "$script_dir" == "." ]; then # current dir
	        full_path_script=`pwd`"/$script"
	else
	        if [[ $script_dir == .* ]]; then
	                script_dir=`echo $script_dir | sed 's/^..//'`
	        fi
	        full_path_script=`pwd`"/$script_dir/$script"
	fi
fi

SCRIPT_STATUS_FILE="~/script_status"
rm -f ~/script_status
touch ~/script_status
echo "BUILD VMA RPM- DAILY STATUS" > ~/script_status

if [ $# -eq 0 ]; then
        usage;
fi
machines=0
firstFlag=1
numOfBranches=0
numOfMachines=0
i=0
j=0

for PARAM in $@; do
        if [ $PARAM == "-w" ]; then
		if [ $firstFlag == 1 ]; then
			firstFlag=0;
			continue
		fi
		
		startBuild $numOfBranches $numOfMachines
		
		numOfBranches=0
		numOfMachines=0
		i=0
		j=0	
		machines=0
                continue
        fi
        if [ $PARAM == "-f" ]; then
                machines=1;
                continue
        fi
        if [ $machines == 1 ]; then
		eval machine_$i=$PARAM
		i=`expr $i + 1`
		numOfMachines=`expr $i`
        else
		eval build_branch_$j=$PARAM
                j=`expr $j + 1`
		numOfBranches=`expr $j`
        fi
done

startBuild $numOfBranches $numOfMachines

mailScriptStatus

exit

}

function startBuild {

numOfBranches=$1
numOfMachines=$2

for (( i=0; i<$numOfBranches; i++ )); do
	curr_branch=$(eval echo \$build_branch_$i)
	echo "============================================" >> ~/script_status
	echo "Branch: $curr_branch" >> ~/script_status
	echo "===============" >> ~/script_status
	cd /tmp
	svn co $svn_branches$curr_branch
	cd $curr_branch
	needToBuildDaily $curr_branch
	if [[ $? == 0 ]]; then
		for (( j=0; j<$numOfMachines; j++ )); do
			working_machine=$(eval echo \$machine_$j)
			ssh $working_machine rm -f /tmp/$script
			scp $full_path_script $working_machine:/tmp/$script
			ssh $working_machine chmod 777 /tmp/$script
			ssh $working_machine /tmp/$script -d $curr_branch -f $SCRIPT_STATUS_FILE
			ssh $working_machine rm -f /tmp/$script
			echoStep "$working_machine is finished"
		done


		DATE=`date +""%Y"-"%m"-"%d""` #today's date
		if [ $WRAPPER_MODE == 1 ]; then
		        echo " " >> ~/script_status
			svn log -r HEAD:{"$last_daily 18:00:00"} >> ~/script_status
		        echo " " >> ~/script_status
		fi

		cd /.autodirect/mswg/release/vma/
		folderName=$(readlink -f "latest_daily-"$curr_branch""/ | grep -o "20.*")
		if [ "$folderName" == "$DATE" ]; then
		       cd latest_daily-"$curr_branch"
		       ssh oritm@bgate.mellanox.com mkdir -p /vma/daily/"$curr_branch"/"$folderName"
		       scp -r . oritm@bgate.mellanox.com:/vma/daily/"$curr_branch"/"$folderName"
		fi
		cd -
	fi
	cd ..
	rm -rf $curr_branch
done

}

function finishScript {

if [ ! $LOCAL_MODE == 1 ]; then
        #remove svn_co folder
        rm -rf $workspace_folder;
fi

if [ "$1" == "s" ]; then
	#create TAG- if release mode
	if [ "$RELEASE_MODE" == 1 ]; then
        	DATE=$(date +%Y%m%d)
		echoMsgToUser "To create a tag, run:"
	  	echoMsgToUser "svn cp https://web.voltaire.com/repos/enterprise/mce/branches/$branch_folder/ https://web.voltaire.com/repos/enterprise/mce/tags/vma_$fullVersion_rev_$svn_revision_from_$DATE"
		finalRpm="$mswg_vma_folder/vma_v_"$fullVersion"_r_"$svn_revision""
		echoStep "rpm was created successfuly under $finalRpm"
	else
		echoStep "rpm was created successfuly under $target_dir"
	        rm -rf /tmp/build_vma_rpm.log
	fi
#	if [ "$MAIL_ALERT" == 1 ]; then
#	        rpmCreatedMail;
#	fi
fi

exit

}

function handleError {

retVal=$1
command=$2
if [[ $retVal != 0 ]]; then
	touch /tmp/build_vma_rpm.log
        $command 2>&1 /tmp/build_vma_rpm.log
        errorOccured "$command"
        finishScript;
fi

}

function runStep {

currStep=$1
echoStep "$currStep"
$currStep
handleError $? "$currStep"

}
######################### main #########################

parseArguments $@
all_flags=$@
#mswg_vma_folder="/tmp/mswg/release/vma" # for debug

if [ $LOCAL_MODE == 1 ]; then
	#### local mode- no need to check out from svn, current folder contains the code
	workspace_folder=`pwd`;
else
	#### daily/release mode- check out the requested revision from the branch
	workspace_folder="/tmp/svn_co_tmp"
	target_dir=$mswg_vma_folder
	rm -rf "$workspace_folder"
	svn_co;
fi

if [ ! -f ./autogen.sh ] && [ $LOCAL_MODE == 1 ]; then
        echoErr "please run the script from the HEAD of the workspace folder"
        script=`basename $0`
        echoErr "i.e. ./build/$script $all_flags"
        usage
fi

getVmaParamsFromConfigure.ac
if [ $RELEASE_MODE == 1 ]; then
	#### release mode- check if configure.ac and jurnal.txt are updated
	areFilesUpdated

	#### release mode- check if a release already exists for this version
	isReleaseExists
fi

echoStep "clean project"
make clean
make distclean
chmod -R 777 build/
rm -rf /tmp/build_vma_rpm.log

#### create build/vma dir instead of running script ./get_src.sh
mkdir -p /tmp/vma
cp -r ./* /tmp/vma
mkdir -p build/vma
cp -r /tmp/vma/* build/vma/
rm -rf /tmp/vma

runStep "./autogen.sh"

runStep "./configure"

if [ "$make_cov" == 1 ]; then
	runStep "make cov"
else
	runStep "make"
fi

chmod -R 777 build/
cd build/

set_topdir

echoStep "./build_vma_udp_rpm.sh"
if [ "$(rpm --eval '%{_topdir}')" == "$topdir" ]; then
	build_vma_src_rpm > /tmp/tmp_file
else
	for d in SRPMS SPECS SOURCES RPMS BUILD; do sudo mkdir -p "$topdir"/"$d"; done
	build_vma_src_rpm $topdir > /tmp/tmp_file
fi
handleError $? "build_vma_src_rpm $topdir"

#move to source package folder
srcRpm=$(cat /tmp/tmp_file | grep Wrote: | grep -o '/.*')
srcRpmPath=$(cat /tmp/tmp_file | grep Wrote: | grep -o '/.*/')
rm -rf /tmp/tmp_file
cd $srcRpmPath

#check if 64bit architecture, and if so- check if Ofed 32bit is supported
numOfRPMs=1;
machine=$(uname -m)
name=`uname -n`
if [ "$build_32" == 1 ] && [ "$machine" == "x86_64" ]; then
	lib64_path=$(rpm -ql libibverbs | grep "\/usr\/lib64\/")
	lib32_path=$(rpm -ql libibverbs | grep "\/usr\/lib\/")
	if [ "$lib32_path" != "" -a "$lib64_path" != "" ]; then numOfRPMs=2; fi #ofed 32bit supported
fi

fullVersion="$vma_ver_major"."$vma_ver_minor"."$vma_ver_revision"-"$vma_ver_release"

finalRpm=
machine=`uname -n`
i=0
while [ $i -lt $numOfRPMs ]; do
	err=0

	#make rpm and output errors
	echoStep "sudo BUILD_32=$i rpmbuild --rebuild --define "_topdir $topdir"  libvma-"$fullVersion".src.rpm"
	sudo BUILD_32=$i rpmbuild --rebuild --define "_topdir $topdir"  libvma-"$fullVersion".src.rpm > /tmp/build_vma_rpm.log
	if [[ $? != 0 ]]; then 
		errorOccured "sudo BUILD_32=$i rpmbuild --rebuild libvma-$fullVersion.src.rpm" $i
		i=`expr $i + 1`
		continue
	fi

	#find path to rpm
	path=$(cat /tmp/build_vma_rpm.log | grep Wrote: | head -1 | grep -o '/.*')
	pattern=" |'"
	if [[ $path =~ $pattern ]]; then # in case $path contains space
		path=`echo $path | awk '{print $1}'`
	fi

	#copy the rpm to src dir
	if [ $i == 0 ]; then
		if [ "$DAILY_MODE" == 1 ]; then #daily
			cd $mswg_vma_folder
			date=$(date +%Y-%m-%d)
			mkdir -p daily/"$branch_folder"/"$date"
			#create symbolic link
			rm -rf latest_daily-"$branch_folder"
			ln -s daily/"$branch_folder"/"$date" latest_daily-"$branch_folder"
			cp $path* daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".rpm
			if [[ $? != 0 ]]; then
				err=1;
				echo "Machine: $machine $build32- failed on step: cp $path daily/$branch_folder/$date/" >> $log_file
			fi
			finalRpm=$mswg_vma_folder/daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".rpm
			if [ "$make_cov" == 1 ]; then
				cp -r $workspace_folder/clean/cov-build daily/"$branch_folder"/"$date"
			fi
			if [ "$copy_to_bgate" == 1 ]; then
	                       ssh oritm@bgate.mellanox.com mkdir -p /vma/daily/"$branch_folder"/"$date"
	                       scp -r daily/"$branch_folder"/"$date"/ oritm@bgate.mellanox.com:/vma/daily/"$branch_folder"/"$date"
			fi
		fi
    		if [ "$RELEASE_MODE" == 1 ]; then #release
			cd $mswg_vma_folder
			mkdir -p "vma_v_"$fullVersion"_r_"$svn_revision""/src/
			#create symbolic link
			rm -rf latest_release
			ln -s "vma_v_"$fullVersion"_r_"$svn_revision"" latest_release
			cd "vma_v_"$fullVersion"_r_"$svn_revision""
			#copy src rpm
			cp $srcRpm src/
                        if [[ $? != 0 ]]; then
                                err=1;
                                echo "Machine: $machine $build32- failed on step: cp $srcRpm src/" >> $log_file
                        fi
			cp $path* src/
			#copy the rpm (short name) to vma dir
			ln -s src/*"$(uname -n)".rpm libvma-""$fullVersion"-"$machine"".rpm
			cp "$workspace_folder"/clean/README.txt .
			cp "$workspace_folder"/clean/journal.txt .
			if [ "$make_cov" == 1 ]; then
                                cp -r $workspace_folder/clean/cov-build .
                        fi
		fi
		if [ "$LOCAL_MODE" == 1 ]; then #local
			cp $path* "$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name"".rpm
			if [[ $? != 0 ]]; then
                                err=1;
                                echo "Machine: $machine $build32-  failed on step: cp $path $target_dir/" >> $log_file
                        fi
			finalRpm="$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name"".rpm;
		fi
	
	else # BUILD_32=1
		if [ "$DAILY_MODE" == 1 ]; then #daily
			cd $mswg_vma_folder
			cd daily/"$branch_folder"/"$date"
			cp $path* ./libvma-""$fullVersion"-"$machine""-"$name"-combined."$date".rpm
			if [[ $? != 0 ]]; then
                                err=1;
                                echo "Machine: $machine $build32- failed on step: cp $path daily/"$branch_folder"/"$date"/" >> $log_file
                        fi
			finalRpm=$mswg_vma_folder/daily/"$branch_folder"/"$date"/libvma-""$fullVersion"-"$machine""-"$name"-combined."$date".rpm
                        if [ "$copy_to_bgate" == 1 ]; then
                               scp -r $finalRpm oritm@bgate.mellanox.com:/vma/daily/"$branch_folder"/"$date"/
                        fi
			if [ "$make_cov" == 1 ]; then
                                cp -r $workspace_folder/clean/cov-build daily/"$branch_folder"/"$date"/cov-combined
                        fi
		fi
		if [ "$RELEASE_MODE" == 1 ]; then #release
			cd $mswg_vma_folder
			mkdir -p "vma_v_"$fullVersion"_r_"$svn_revision""/src-combined/
			cd "vma_v_"$fullVersion"_r_"$svn_revision""
			cp $path* src-combined/
			if [[ $? != 0 ]]; then
                                err=1;1
                                echo "Machine: $machine $build32- failed on step: cp $path src/-combined/" >> $log_file
                        fi
			#copy the rpm (short name) to vma dir
			ln -s src-combined/*"$(uname -n)".rpm libvma-""$fullVersion"-"$machine""-combined.rpm
			if [ "$make_cov" == 1 ]; then
                                cp -r $workspace_folder/clean/cov-build ./cov-combined
                        fi
		fi
		if [ "$LOCAL_MODE" == 1 ]; then #local
                	cp $path* "$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name""-combined.rpm
			if [[ $? != 0 ]]; then
                                err=1;
                                echo "Machine: $machine $build32- failed on step: cp $path $target_dir/" >> $log_file
                        fi
			finalRpm="$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name""-combined.rpm
		fi
	fi
	cd $srcRpmPath

	if [ "$LOG_SCRIPT_STATUS" == 1 ]; then
		if [ $err == 0 ]; then
		        machine=`uname -n`
	        	echo "Machine: $machine, BUILD_32="$i" - rpm was created successfuly, location: $finalRpm" >> $log_file
		fi
	fi
	i=`expr $i + 1`
done

finishScript "s" #finish script successfuly

