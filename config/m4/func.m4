# func.m4 - Collection of functions
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2020.  ALL RIGHTS RESERVED.
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

# FUNC_CHECK_WITHDIR(name, direcory, file)
# ----------------------------------------------------
AC_DEFUN([FUNC_CHECK_WITHDIR],[
    AC_MSG_CHECKING([for $1 location])
    AS_IF([test "$2" = "yes" || test "$2" = "no" || test "x$2" = "x"],
          [AC_MSG_RESULT([(system default)])],
          [AS_IF([test ! -d "$2"],
                 [AC_MSG_RESULT([not found])
                  AC_MSG_WARN([Directory $2 not found])
                  AC_MSG_ERROR([Cannot continue])],
                 [AS_IF([test "x`ls $2/$3 2> /dev/null`" = "x"],
                        [AC_MSG_RESULT([not found])
                         AC_MSG_WARN([Expected file $2/$3 not found])
                         AC_MSG_ERROR([Cannot continue])],
                        [AC_MSG_RESULT([($2)])]
                       )
                 ]
                )
          ]
         )
])
