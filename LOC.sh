#!/bin/sh

TEAM="Acceleration"
PROJECT="VMA"
VERSION="6.4"
EXCLUDES="`pwd`/LOC_exclude_VMA.txt"

REPO_GIT="git:///.autodirect/mswg/git/accl/vma.git"
BRANCH="master"

# Run from remote git url (clean from build objects)
python /.autodirect/mtrswgwork/accounter_lines_of_code/bin/loc_count.py -T $TEAM -P $PROJECT -V $VERSION -E $EXCLUDES -R $REPO_GIT -B $BRANCH

# Run from local path
#python /.autodirect/mtrswgwork/accounter_lines_of_code/bin/loc_count.py -T $TEAM -P $PROJECT -V $VERSION -E $EXCLUDES -p `pwd`

