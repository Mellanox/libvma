# func.m4 - Collection of functions
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2019.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Configure functions
#
# Some helper script functions
#
AC_DEFUN([FUNC_CONFIGURE_INIT],
[
show_section_title()
{
    cat <<EOF

============================================================================
== ${1}
============================================================================
EOF
}

show_summary_title()
{
    cat <<EOF

Mellanox VMA library
============================================================================
Version: ${VMA_LIBRARY_MAJOR}.${VMA_LIBRARY_MINOR}.${VMA_LIBRARY_REVISION}.${VMA_LIBRARY_RELEASE}
Git: ${GIT_VER}

EOF
}

])
