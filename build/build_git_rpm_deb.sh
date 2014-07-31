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
   -r <branch>

   Optional:
   -o -O   Override existing release
   -c -C   Make coverity
   -b -B   Make Bullseye

WRAPPER MODE OPTIONS:
---------------------
   -w <branches...> -f <machines' names...> ...

    can run this format "-w <branches...> -f <machines' names...>" several times in order to
    build different branches on several machines in the same run
    Example: ./build_vma_rpm.sh -w vma_6.1 -f alf1 alf2 -w vma_6.2 vma_6.3 -f alf3
           ==> will build vma_6.1 on alf1, alf2 and vma_6.2,vma_6.3 on alf3

DAILY MODE OPTIONS:
-------------------
   -d <branch>

   Optional:
   -s -S   Secure copy the rpms created to bgate
   -c -C   Make coverity
   -b -B   Make Bullseye

LOCAL MODE OPTIONS:
-------------------
   -l <target folder>

   run the script from the HEAD of the workspace folder

   Optional:
   -n -N   Add a name to rpm <rpm's title>

EOF

cleanFilesAndExit

}

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

function isValidGitBranch {

git branch -r > /tmp/git_list.tmp
folder=$1
ret=0
grep "origin/$folder$" /tmp/git_list.tmp > /dev/null
if [[ $? != 0 ]]; then
        ret=1;
fi
rm -f /tmp/git_list.tmp
return $ret

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
	if [ $PARAM == "-c" ] || [ $PARAM == "-C" ]; then
                continue
        fi
        if [ $PARAM == "-b" ] || [ $PARAM == "-B" ]; then
                continue
        fi
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
                        # mail report
                        tmp_file="/tmp/log_$RANDOM.txt"
                        echo "Script failed: ssh: connect to host \"$curr_machine\": No route to host" > $tmp_file
                        /bin/mail -s "$SUBJECT" "$EMAIL" < $tmp_file
                        usage;
                fi
                i=`expr $i + 1`
                numOfMachines=`expr $i`
        else
                eval build_branch_$j=$PARAM
                curr_build_branch=$(eval echo \$build_branch_$j)
                isValidGitBranch $curr_build_branch
                if [[ $? != 0 ]]; then
                        echoErr "\"$curr_build_branch\" is illegal branch folder"
                        echoErr "run \"git branch -r\" for the complete list"
                        # mail report
                        tmp_file="/tmp/log_$RANDOM.txt"
                        echo "Script failed: \"$curr_build_branch\" is illegal branch folder" > $tmp_file
                        /bin/mail -s "$SUBJECT" "$EMAIL" < $tmp_file
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
commitDate=`git log -1 --format="%ci" | grep -Po '\d{4}[\-]\d{2}[\-]\d{2}'` #date of last commit
commitTime=`git log -1 --format="%ci" | grep -Po '\d{2}[\:]\d{2}[\:]\d{2}'` #time of last commit
DATE=`date +""%Y"-"%m"-"%d""` #today's date

#if last commit is not from today, and rpm was created since last commit- no need to build new rpm
if [ "$commitDate" != "$DATE" ]; then
        if [ "$last_daily" \> "$commitDate" ]; then
                echoMsgToUser "Branch $branch_folder: No changes from last build- no need to build again"
                echo "No changes from last build- no new rpm" >> ~/script_status
                return 1; #nothing changed
        fi
	if [ "$last_daily" == "$commitDate" ] && [ "$commitTime" \< "$buildTime" ]; then
                echoMsgToUser "Branch $branch_folder: No changes from last build- no need to build again"
                echo "No changes from last build- no new rpm" >> ~/script_status
                return 1; #nothing changed
        fi
fi

return 0

}

function runWrapper {

SCRIPT_STATUS_FILE="~/script_status"
rm -f ~/script_status
touch ~/script_status
echo "BUILD VMA RPM- DAILY STATUS" > ~/script_status

if [ $# -eq 0 ]; then
        usage;
fi
machines=0
make_cov=0
make_bullseye=0
firstFlag=1
numOfBranches=0
numOfMachines=0
i=0
j=0

for PARAM in $@; do
	if [ $PARAM == "-c" ] || [ $PARAM == "-C" ]; then
                make_cov=1;
                continue
        fi
	if [ $PARAM == "-b" ] || [ $PARAM == "-B" ]; then
                make_bullseye=1;
                continue
        fi
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

script_flags=" "
if [ $make_cov == 1 ]; then
	script_flags=" -c $script_flags"
fi
if [ $make_bullseye == 1 ]; then
        script_flags=" -b $script_flags"
fi

for (( i=0; i<$numOfBranches; i++ )); do
        curr_branch=$(eval echo \$build_branch_$i)
        echo "============================================" >> ~/script_status
	curr_branch_name=$curr_branch
        if [ "$curr_branch" == "master" ]; then
        	curr_branch_name=$master_name
       	fi
        echo "Branch: $curr_branch_name" >> ~/script_status
        echo "===============" >> ~/script_status
	cd $vma_repos_base
	PARENT=`ps --no-heading -o %c -p $PPID`
	if [ $PARENT == bash ]; then
        	rm -rf $vma_repos_dir
        	git clone /.autodirect/mswg/git/accl/vma.git/ vma_build_repos #TODO: add rm -rf... at the end 
		#git clone /.autodirect/mtrswgwork/ork/workspace/git/vma/ vma_build_repos #debug
	fi        
	cd $vma_repos_dir
        git checkout $curr_branch
        needToBuildDaily $curr_branch
        if [[ $? == 0 ]]; then
                if [ -z "$last_daily" ]; then
                        since="yesterday"
                else
                        since="$last_daily $buildTime"
                fi
                for (( j=0; j<$numOfMachines; j++ )); do
                        working_machine=$(eval echo \$machine_$j)
                        ssh $working_machine rm -f /tmp/$script
                        scp $full_path_script $working_machine:/tmp/$script
                        ssh $working_machine chmod 777 /tmp/$script
                        ssh $working_machine bash /tmp/$script $script_flags -d $curr_branch -f $SCRIPT_STATUS_FILE 
                        ssh $working_machine rm -f /tmp/$script
                        echoStep "$working_machine is finished"
                done
		#exit #debug	
		cd $vma_repos_base
		if [ $PARENT == bash ]; then
                	rm -rf $vma_repos_dir
			#git clone /.autodirect/mtrswgwork/ork/workspace/git/vma/ vma_build_repos #debug
                	git clone /.autodirect/mswg/git/accl/vma.git/ vma_build_repos #TODO: add rm -rf... at the end
        	fi
        	cd $vma_repos_dir
        	git checkout $curr_branch

                DATE=`date +""%Y"-"%m"-"%d""` #today's date
                if [ $WRAPPER_MODE == 1 ] && [ "$curr_branch" != "vma_6.4_deliberate_failures" ]; then
                        echo " " >> ~/script_status
                        cd $vma_repos_dir
                        git checkout $curr_branch
                        git log --since="$since" >> ~/script_status
                        echo " " >> ~/script_status
                fi

                cd /.autodirect/mswg/release/vma/
                folderName=$(readlink -f "latest_daily-"$curr_branch""/ | grep -o "20.*")
                if [ "$folderName" == "$DATE" ]; then
                       cd latest_daily-"$curr_branch"
			bgate_curr_branch=$curr_branch
			if [ "$curr_branch" == "master" ]; then
				bgate_curr_branch=$master_name
			fi
                       ssh ork@bgate.mellanox.com mkdir -p /hpc/home/vma/daily/"$bgate_curr_branch"/"$folderName"
                       scp -r . ork@bgate.mellanox.com:/hpc/home/vma/daily/"$bgate_curr_branch"/"$folderName"
                fi
                cd -
        fi
done

}

function parseArguments {

EMAIL="sw-dev-vma@mellanox.com mellanox-CSA-team@asaltech.com"
#EMAIL="ork@mellanox.com" # for debug
SUBJECT="VMA Daily Build"

RELEASE_MODE=0
DAILY_MODE=0
LOCAL_MODE=0
WRAPPER_MODE=0

BRANCH_INITIALIZED=0
branch_folder=

mswg_vma_folder="/.autodirect/mswg/release/vma"
mswg_daily_folder="/.autodirect/mswg/release/vma/daily"

#MAIL_ALERT=0
rpm_name=
OVERRIDE=0
make_cov=0
make_bullseye=0
copy_to_bgate=0

master_name="vma_6.6"
buildTime="18:00:00"

LOG_SCRIPT_STATUS=0
log_file=

if [ "$1" == "-h" ]; then
        usage;
fi

pwd_dir=`pwd`
cd $vma_repos_base
PARENT=`ps --no-heading -o %c -p $PPID`
if [ $PARENT == bash ]; then
        rm -rf $vma_repos_dir
	#git clone /.autodirect/mtrswgwork/ork/workspace/git/vma vma_build_repos #debug
        git clone /.autodirect/mswg/git/accl/vma.git/ vma_build_repos #TODO: add rm -rf... at the end 
fi
cd $vma_repos_dir 

while getopts wWd:D:r:R:l:L:n:N:f:F:oOsScCbBh OPTION
do
        case $OPTION in
                h) # help
                        usage
                ;;
                d|D|r|R) # daily \ release mode
                        branch_folder=$OPTARG

                        #### branch folder arg- checks that the requested branch folder exists under https://sirius.voltaire.com/repos/enterprise/mce/branches/
                        isValidGitBranch $branch_folder
                        if [[ $? != 0 ]]; then
                                echoErr "\"$branch_folder\" is illegal branch folder"
                                echoErr "run \"git branch -r\" for the complete list"
                                usage;
                        fi
                        BRANCH_INITIALIZED=1

                        #### sign which mode is selected
                        if [[ $OPTION == "d" ]] || [[ $OPTION == "D" ]]; then
                                DAILY_MODE=1;
                        fi
                        if [[ $OPTION == "r" ]] || [[ $OPTION == "R" ]]; then
                                RELEASE_MODE=1;
                        fi
                ;;
		c|C) # make coverity
                        make_cov=1
                ;;
                b|B) # make coverity
                        make_bullseye=1
                ;;
                w|W)
                        WRAPPER_MODE=1;
                        checkLegalWrapperModeParams $@
                        runWrapper $@;
                ;;
                l|L) # local mode
                        LOCAL_MODE=1
                        rm -rf $vma_repos_dir
                        cd $pwd_dir
                        target_dir=$OPTARG
                        if [ ! -d $target_dir ]; then
                                echoErr "folder $target_dir does not exist"
                                usage;
                        fi
                ;;
                n|N) # rpm's name
                        rpm_name="-$OPTARG"
                ;;
                f|F) # log the status of the script (success/failiure) to a log file
                        LOG_SCRIPT_STATUS=1
                        log_file=$OPTARG
                ;;
#               m|M) # mail errors to user
#                       MAIL_ALERT=1
#               ;;
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

if [ $copy_to_bgate == 1 ] && [ $DAILY_MODE != 1 ]; then # copy to bgate available only on daily mode
        echoErr "-s flag is available only when using -d (daily mode)"
        usage
fi

if [ $LOG_SCRIPT_STATUS == 1 ] && [ $LOCAL_MODE == 1 ]; then
        echoErr "-f flag is available only when using -r (release mode) or -d (daily mode)"
        usage
fi

if [ $make_cov == 1 ] && [ $LOCAL_MODE == 1 ]; then
        echoErr "-c flag is available only when using -r (release mode) or -d (daily mode)"
        usage
fi

if [ "$branch_folder" != "vma_6.3" ] && [ "$branch_folder" != "master" ]; then #only vma_6.3 can be build with coverity
        make_cov=0
fi

}

function build_vma_src_rpm {

APP_NAME=vma
VMA_DIR=$APP_NAME

cd ..
echoStep `pwd`
DATE=`git log -1 --format="%ci" | grep -Po '\d{4}[\-]\d{2}[\-]\d{2}'`
TIME=`git log -1 --format="%ci" | grep -Po '\d{2}[\:]\d{2}[\:]\d{2}'`
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

sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g' -e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' -e 's/__MAJOR/'$VMA_LIBRARY_MAJOR'/g' $APP_NAME.spec > $APP_NAME-$VERSION.spec
#sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g'-e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' -e 's/__MAJOR/'$VMA_LIBRARY_MAJOR'/g' $APP_NAME.spec > $APP_NAME-$VERSION.spec
sed  -e 's/__VERSION/'$VERSION'/g' -e 's/__RELEASE/'$VMA_LIBRARY_RELEASE'/g' -e 's/__DATE/'$DATE'/g' -e 's/__TIME/'$TIME'/g' $VMA_DIR/vma_version_template > $VMA_DIR/VMA_VERSION

rm -f libvma*.tar.gz  > /dev/null > /dev/null 2>&1
rm -f $RPM_DIR/SRPMS/libvma*  > /dev/null > /dev/null 2>&1
rm -rf $VMA_DIR_NAME  > /dev/null > /dev/null 2>&1

mkdir $VMA_DIR_NAME
mkdir $VMA_DIR_NAME/build
cp -r build_vma_udp_rpm.sh $APP_NAME.spec $VMA_DIR_NAME/build
cp -r $VMA_DIR  $VMA_DIR_NAME/build/$VMA_DIR_NAME/   # copy vma & udp_test
cd $VMA_DIR_NAME
cd build
cd $VMA_DIR_NAME
#./autogen.sh
autogenWrap
prepare_debian_files "debian"
cd ..
tar zcvf ../../$VMA_DIR_NAME.tar.gz --exclude .git $VMA_DIR_NAME > /dev/null > /dev/null 2>&1
cd ..
cd ..

sudo cp *.gz $APP_NAME-$VERSION.spec $RPM_DIR/SOURCES/ > /dev/null > /dev/null 2>&1
sudo rpmbuild --define "_topdir $RPM_DIR" -bs $APP_NAME-$VERSION.spec

rm -f $VMA_DIR_NAME.tar.gz temp > /dev/null > /dev/null 2>&1
rm -rf $VMA_DIR_NAME > /dev/null > /dev/null 2>&1
rm -rf $APP_NAME-$VERSION.spec > /dev/null > /dev/null 2>&1

#if [  ! -f $RPM_DIR/SRPMS/libvma* ]; then
#        exit 1
#fi
echo $RPM_DIR/SRPMS/libvma*

}

function cleanFilesAndExit {

#### clear the workspace folder if the script is on daily/release mode
PARENT=`ps --no-heading -o %c -p $PPID`
if [ ! $LOCAL_MODE == 1 ] && [ $PARENT == bash ]; then
        rm -rf $vma_repos_dir;
fi

exit 1
}

function errorOccured {

#### clear the workspace folder if the script is on daily/release mode
if [ ! $LOCAL_MODE == 1 ] && [ $PARENT == bash ]; then
        rm -rf $vma_repos_dir;
fi

echoErr "failed on step: $1"
#if [ $MAIL_ALERT == 1 ]; then
#       sendErrorMailToUser $1;
#fi

if [ "$LOG_SCRIPT_STATUS" == 1 ]; then
        name=`uname -n`
        echo "Machine: $name - failed on step: $1" >> $log_file
fi

}

function mailScriptStatus {

# Left in case we want to add the logs as attachments
#ls ~/*_$DATE.log
#if [ $? == 0 ]; then
#       mutt -s "$SUBJECT" `for file in ~/*_$DATE.log; do echo -n "-a ${file} "; done` "$EMAIL" < ~/script_status
#       rm -f ~/*_$DATE.log
#else
#       /bin/mail -s "$SUBJECT" "$EMAIL" < ~/script_status
#fi

/bin/mail -s "$SUBJECT" "$EMAIL" < ~/script_status

rm -f ~/script_status

}

function git_co {

#### check out the requested branch 
echoStep "git checkout $branch_folder"

git checkout $branch_folder
if [[ $? != 0 ]]; then
        errorOccured "git checkout $branch_folder"
        finishScript;
fi

}

function getVmaParamsFromConfigure.ac {

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

jurnal_version=`cat journal.txt | head -1` 
configure_version=`echo "Version $vma_ver_major.$vma_ver_minor.$vma_ver_revision-$vma_ver_release":` # configure.ac version in same format as journal.txt (i.e. Version 6.3.22-0:) 
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

mswg_vma_version_folder="vma_v_"$vma_ver_major"."$vma_ver_minor"."$vma_ver_revision"-"$vma_ver_release""
if [[ $OVERRIDE == 0 ]]; then
        ls $mswg_vma_folder | grep $mswg_vma_version_folder
        if [[ $? == 0 ]]; then
                echoMsgToUser "This version already exist: $mswg_vma_folder/$mswg_vma_version_folder"
                echoMsgToUser "Do you want to continue (a new rpm will be created instead)? y/n"
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

function finishScript {

PARENT=`ps --no-heading -o %c -p $PPID`
if [ ! $LOCAL_MODE == 1 ] && [ $PARENT == bash ]; then
        rm -rf $workspace_folder;
fi

cd $vma_repos_base
rm -rf $vma_repos_dir

if [ "$1" == "s" ]; then
        #create TAG- if release mode
        if [ "$RELEASE_MODE" == 1 ]; then
                finalRpm="$mswg_vma_folder/vma_v_"$fullVersion"" #TODO:replace svn_revision with???????
                echoStep "rpm was created successfuly under $finalRpm"
        else
                echoStep "rpm was created successfuly under $target_dir"
        fi
fi

exit

}

function handleError {

retVal=$1
command=$2
if [[ $retVal != 0 ]]; then
        errorOccured "$command"
        PARENT=`ps --no-heading -o %c -p $PPID`
        if [ $PARENT == bash ]; then
                finishScript;
        else
                exit
        fi
fi

}

function prepare_deb_tarball {
	pathToWorkspace=$1

	debBuildDir="/tmp"
        debBuildContainer="deb_build"
        debBuildDirFinal="$debBuildDir/$debBuildContainer/"

	cd $debBuildDir
	sudo rm -rf $debBuildContainer
	mkdir $debBuildContainer
	cd $debBuildContainer

        DEB_VMA_VERSION="$vma_ver_major.$vma_ver_minor.$vma_ver_revision"
        DEB_VMA_RELEASE="$vma_ver_release"

	cp -rf $pathToWorkspace libvma-$DEB_VMA_VERSION.$DEB_VMA_RELEASE
	rm -rf libvma-$DEB_VMA_VERSION.$DEB_VMA_RELEASE/.git

	cd libvma-$DEB_VMA_VERSION.$DEB_VMA_RELEASE
	#./autogen.sh
	autogenWrap
	cd ..

	prepare_debian_files "libvma-$DEB_VMA_VERSION.$DEB_VMA_RELEASE/debian"

        srcDebTarName=libvma_$DEB_VMA_VERSION.$DEB_VMA_RELEASE.orig.tar.gz
        currpwd=`pwd`
        srcDebTarPath="$currpwd/$srcDebTarName"

        tar czvf $srcDebTarName libvma-$DEB_VMA_VERSION.$DEB_VMA_RELEASE

}


function prepare_debian_files {

	pathToDebianDir=$1 
	debUserName="Or Kehati"
        debUserEmail="ork@mellanox.com"
        localArch="`eval arch`"
        debArch="any"
	#debArch="$localArch"
        #if [[ "$localArch" == "x86_64" ]]; then
        #        debArch="amd64";
        #elif [[ "$localArch" == "x86" ]]; then
        #        debArch="i386";
        #fi
        debDate=`date -R`

        DEB_VMA_VERSION="$vma_ver_major.$vma_ver_minor.$vma_ver_revision"
        DEB_VMA_RELEASE="$vma_ver_release"
        DEB_VMA_DATE="$debDate"
        DEB_VMA_ARCH="$debArch"
        DEB_VMA_USERNAME="$debUserName"
        DEB_VMA_USER_EMAIL="$debUserEmail"
	
        mv $pathToDebianDir/postinst $pathToDebianDir/postinst.template
        mv $pathToDebianDir/postrm $pathToDebianDir/postrm.template
        mv $pathToDebianDir/changelog $pathToDebianDir/changelog.template
        mv $pathToDebianDir/control $pathToDebianDir/control.template
        mv $pathToDebianDir/copyright $pathToDebianDir/copyright.template
	mv $pathToDebianDir/rules $pathToDebianDir/rules.template
        sed  -e "s/__DEB_VMA_VERSION/$DEB_VMA_VERSION/g" -e "s/__DEB_VMA_RELEASE/$DEB_VMA_RELEASE/g" $pathToDebianDir/postinst.template > $pathToDebianDir/postinst
        sed  -e "s/__DEB_VMA_VERSION/$DEB_VMA_VERSION/g" -e "s/__DEB_VMA_RELEASE/$DEB_VMA_RELEASE/g" $pathToDebianDir/postrm.template > $pathToDebianDir/postrm

        sed  -e "s/__DEB_VMA_VERSION/$DEB_VMA_VERSION/g" -e "s/__DEB_VMA_RELEASE/$DEB_VMA_RELEASE/g" -e "s/__DEB_VMA_DATE/$DEB_VMA_DATE/g" -e "s/__DEB_VMA_USERNAME/$DEB_VMA_USERNAME/g" -e "s/__DEB_VMA_USER_EMAIL/$DEB_VMA_USER_EMAIL/g" $pathToDebianDir/changelog.template > $pathToDebianDir/changelog

        sed  -e "s/__DEB_VMA_ARCH/$DEB_VMA_ARCH/g" -e "s/__DEB_VMA_USERNAME/$DEB_VMA_USERNAME/g" -e "s/__DEB_VMA_USER_EMAIL/$DEB_VMA_USER_EMAIL/g" $pathToDebianDir/control.template > $pathToDebianDir/control

        sed  -e "s/__DEB_VMA_VERSION/$DEB_VMA_VERSION/g" -e "s/__DEB_VMA_RELEASE/$DEB_VMA_RELEASE/g" -e "s/__DEB_VMA_DATE/$DEB_VMA_DATE/g" -e "s/__DEB_VMA_ARCH/$DEB_VMA_ARCH/g" $pathToDebianDir/copyright.template > $pathToDebianDir/copyright

	sed  -e "s/__VMA_DEB_DATE/$DATE/g" -e "s/__VMA_DEB_TIME/$TIME/g" $pathToDebianDir/rules.template > $pathToDebianDir/rules

        rm -f $pathToDebianDir/postinst.template
        rm -f $pathToDebianDir/postrm.template
        rm -f $pathToDebianDir/changelog.template
        rm -f $pathToDebianDir/control.template
        rm -f $pathToDebianDir/copyright.template
	rm -f $pathToDebianDir/rules.template

}

function build_deb {
        srcRpmFile=$1
        pathToFinalDir=$2
	debFinalFile=$pathToFinalDir
        ubuntuMachine="hail14-vm03-ub12-x64-ofed20"
        debBuildDir="/tmp"
        debBuildContainer="deb_build"
        debBuildDirFinal="$debBuildDir/$debBuildContainer/"
        libvmaDir="libvma"-"$vma_ver_major"."$vma_ver_minor"."$vma_ver_revision"
	ssh $ubuntuMachine "cd $debBuildDir; sudo rm -rf $debBuildContainer"
        ssh $ubuntuMachine "cd $debBuildDir; mkdir $debBuildContainer"
        ssh $ubuntuMachine "cp $srcRpmFile $debBuildDirFinal"
        ssh $ubuntuMachine "cd $debBuildDirFinal; rpm2cpio *.rpm | cpio -idmv > /dev/null 2>&1"
        ssh $ubuntuMachine "cd $debBuildDirFinal; tar xzvf *.tar.gz > /dev/null 2>&1"
        ssh $ubuntuMachine "cd $debBuildDirFinal$libvmaDir; sudo dpkg-buildpackage -us -uc 2>&1"
        ssh $ubuntuMachine "cd $debBuildDirFinal; cp *.deb "$pathToFinalDir""
        ssh $ubuntuMachine "cd $debBuildDir; sudo rm -rf $debBuildContainer"

	#sudo rm -rf $debBuildDirFinal
}

function runStep {

currStep=$1
echoStep "$currStep"
$currStep
handleError $? "$currStep"

}

# from http://superuser.com/questions/39751/add-directory-to-path-if-its-not-already-there
function pathadd {
    export PATH="$1:$PATH"
    #if [ -d "$1" ] && [[ ":$PATH:" != *":$1:"* ]]; then
    #    PATH="${PATH:+"$PATH:"}$1"
    #fi
}

function autogenWrap {
	mv ./config/config.guess ./config/config.guess.override
	mv ./config/config.sub ./config/config.sub.override
	./autogen.sh
	rm ./config/config.guess
	rm ./config/config.sub
	mv ./config/config.guess.override ./config/config.guess
	mv ./config/config.sub.override ./config/config.sub
}
################################## main ##################################
script=`basename $0`
script_dir=`dirname $(readlink -f $0)`
full_path_script=$script_dir/$script

#vma_repos_base=/.autodirect/mtrswgwork/ork/ # for debug
vma_repos_base=/.autodirect/mswg/projects/vma/vma_git
vma_repos_dir=$vma_repos_base/vma_build_repos

path_to_bullseye=/.autodirect/mswg/release/vma/bullseye/bin

parseArguments $@
all_flags=$@
#mswg_vma_folder="/.autodirect/mtrswgwork/ork/tmp/vma" # for debug

if [ $LOCAL_MODE == 1 ]; then
        #### local mode- no need to checkout, current folder contains the code
        workspace_folder=`pwd`;
else
        #### daily/release mode- check out the requested revision from the branch
        cd $vma_repos_dir
        workspace_folder=$vma_repos_dir
        target_dir=$mswg_vma_folder
        git_co;
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

#currPwd=`pwd`
#prepare_deb_tarball "$currPwd"
#cd $currPwd

echoStep "clean project"
make clean
make distclean
chmod -R 777 build/

#### create build/vma dir instead of running script ./get_src.sh
mkdir -p /tmp/vma
cp -r ./* /tmp/vma
mkdir -p build/vma
cp -r /tmp/vma/* build/vma/
rm -rf /tmp/vma

#runStep "./autogen.sh"
autogenWrap

runStep "./configure --enable-debug"

if [ "$make_cov" == 1 ]; then
        runStep "make cov"
#else
       #runStep "make"
fi

curr_pwd=$PWD

chmod -R 777 build/
cd build/

set_topdir

#if [ "$make_bullseye" == 1 ]; then
#	pathadd "$path_to_bullseye"
#	export COVFILE="$curr_pwd/test.cov"
#	#export COVFILE="/tmp/test.cov"
#	cov01 -1
#	cov01 -s
#fi

echoStep "./build_vma_udp_rpm.sh"
if [ "$(rpm --eval '%{_topdir}')" == "$topdir" ]; then
        build_vma_src_rpm > /tmp/tmp_file
#        build_vma_src_rpm
else
        for d in SRPMS SPECS SOURCES RPMS BUILD; do sudo mkdir -p "$topdir"/"$d"; done
        build_vma_src_rpm $topdir > /tmp/tmp_file
#        build_vma_src_rpm $topdir
fi
handleError $? "build_vma_src_rpm $topdir"

# move to source package folder
srcRpm=$(cat /tmp/tmp_file | grep Wrote: | grep -o '/.*')
srcRpmPath=$(cat /tmp/tmp_file | grep Wrote: | grep -o '/.*/')
rm -rf /tmp/tmp_file
cd $srcRpmPath

machine=`uname -m`
name=`uname -n`
fullVersion="$vma_ver_major"."$vma_ver_minor"."$vma_ver_revision"-"$vma_ver_release"
finalRpm=
finalCoverity=
finalBullseye=
err=0
# make rpm and output errors
echoStep "sudo BUILD_32=$i BUILD_BULLSEYE=$make_bullseye rpmbuild --rebuild --define "_topdir $topdir"  libvma-"$fullVersion".src.rpm"
sudo BUILD_32=$i BUILD_BULLSEYE=$make_bullseye rpmbuild --rebuild --define "_topdir $topdir" libvma-"$fullVersion".src.rpm > /tmp/build_vma_rpm.log
if [[ $? != 0 ]]; then
        errorOccured "sudo BUILD_32=$i BUILD_BULLSEYE=$make_bullseye rpmbuild --rebuild libvma-$fullVersion.src.rpm" $i
        i=`expr $i + 1`
fi

#if [ "$make_bullseye" == 1 ]; then
        #cov01 -0
#fi

# find path to rpm
path=$(cat /tmp/build_vma_rpm.log | grep Wrote: | head -1 | grep -o '/.*')
pattern=" |'"
if [[ $path =~ $pattern ]]; then # in case $path contains space
        path=`echo $path | awk '{print $1}'`
fi
echo "path=$path"
rm -f /tmp/build_vma_rpm.log

# copy to correct location
if [ "$DAILY_MODE" == 1 ]; then #daily
        cd $mswg_vma_folder
        date=$(date +%Y-%m-%d)
        mkdir -p daily/"$branch_folder"/"$date"
        #create symbolic link
        rm -rf latest_daily-"$branch_folder"
        ln -s daily/"$branch_folder"/"$date" latest_daily-"$branch_folder"
	if [ "$make_bullseye" == 1 ]; then
        	cp $path* daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".bullseye.rpm
        else
		cp $path* daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".rpm
		cp $srcRpm daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".src.rpm
	fi
	#cp $path* daily/"$branch_folder"/"$date"/
	if [[ $? != 0 ]]; then
                err=1;
                echo "Machine: $name - failed on step: cp $path daily/$branch_folder/$date/" >> $log_file
        fi
        finalRpm=$mswg_vma_folder/daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".rpm
        if [ "$make_cov" == 1 ]; then
                cp -r $workspace_folder/cov-build daily/"$branch_folder"/"$date"
		finalCoverity=$mswg_vma_folder/daily/"$branch_folder"/"$date"/cov-build
        fi
	if [ "$make_bullseye" == 1 ]; then
		finalRpm=$mswg_vma_folder/daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".bullseye.rpm
        	cp "/tmp/test.cov" daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".cov
		finalBullseye=$mswg_vma_folder/daily/"$branch_folder"/"$date"/libvma-"$fullVersion"-"$machine"-"$name"."$date".bullseye.cov
	fi
	build_deb "$mswg_vma_folder/daily/$branch_folder/$date/libvma-$fullVersion-$machine-$name.$date.src.rpm" "$mswg_vma_folder/daily/$branch_folder/$date/libvma-$fullVersion-$machine-$name.$date.deb"

        if [ "$copy_to_bgate" == 1 ]; then
		bgate_branch_folder=$branch_folder
                if [ "$branch_folder" == "master" ]; then
                	bgate_branch_folder=$master_name
                fi
                ssh ork@bgate.mellanox.com mkdir -p /hpc/home/vma/daily/"$bgate_branch_folder"/"$date"
                scp -r daily/"$branch_folder"/"$date"/* ork@bgate.mellanox.com:/hpc/home/vma/daily/"$bgate_branch_folder"/"$date"
	fi
fi
if [ "$RELEASE_MODE" == 1 ]; then #release
        cd $mswg_vma_folder
        mkdir -p "vma_v_"$fullVersion""/src/
        #create symbolic link
        rm -rf latest_release
        ln -s "vma_v_"$fullVersion"" latest_release
        cd "vma_v_"$fullVersion""
        #copy src rpm
        cp $srcRpm src/
        if [[ $? != 0 ]]; then
                err=1;
                echo "Machine: $name - failed on step: cp $srcRpm src/" >> $log_file
        fi
        cp $path* src/
        #copy the rpm (short name) to vma dir
        ln -s src/*x86_64.rpm libvma-""$fullVersion"-"$machine"".rpm
        
	cp "$workspace_folder"/README.txt .
        cp "$workspace_folder"/journal.txt .
        if [ "$make_cov" == 1 ]; then
                cp -r $workspace_folder/cov-build .
        fi
	if [ "$make_bullseye" == 1 ]; then
                cp "/tmp/test.cov" libvma-""$fullVersion"-"$machine"".cov
        fi
	localPath=`pwd`
	finalRpm="$localPath/libvma-""$fullVersion"-"$machine"".rpm"

	build_deb "$localPath/src/libvma-$fullVersion.src.rpm" "$localPath/libvma-$fullVersion-$machine.deb"

	echo "libvma-$fullVersion.src.rpm" > $localPath/src/latest.txt

	echo "libvma-$fullVersion.src.rpm" > $mswg_vma_folder/source_rpms/latest.txt
	ln -s $localPath/src/libvma-$fullVersion.src.rpm $mswg_vma_folder/source_rpms/libvma-$fullVersion.src.rpm

fi
if [ "$LOCAL_MODE" == 1 ]; then #local
        cp $path* "$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name"".rpm
        if [[ $? != 0 ]]; then
                err=1;
                echo "Machine: $name -  failed on step: cp $path $target_dir/" >> $log_file
        fi
        finalRpm="$target_dir"/libvma-""$fullVersion"-"$machine""$rpm_name"".rpm;
fi

if [ "$LOG_SCRIPT_STATUS" == 1 ]; then
        if [ $err == 0 ]; then
                echo "Machine: $name - rpm was created successfuly, location: $finalRpm" >> $log_file
		echo "Machine: $name - deb was created successfuly, location: $debFinalFile" >> $log_file
		if [ "$make_cov" == 1 ]; then
                        echo "Coverity was created successfuly, location: $finalCoverity" >> $log_file
                fi
		if [ "$make_bullseye" == 1 ]; then
			echo "Bullseye .cov file was created successfuly, location: $finalBullseye" >> $log_file
		fi
        fi
fi

if [ $LOCAL_MODE != 1 ]; then
        cd $vma_repos_dir
        rm -rf vma_repos
fi

finishScript "s" #finish script successfuly
