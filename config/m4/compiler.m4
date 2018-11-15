# compiler.m4 - Parsing compiler capabilities
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#


# Check compiler specific attributes
# Usage: CHECK_COMPILER_ATTRIBUTE([attribute], [program], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_COMPILER_ATTRIBUTE], [
    AC_CACHE_VAL(vma_cv_attribute_[$1], [
        #
        # Try to compile using the C compiler
        #
        AC_TRY_COMPILE([$2],[],
                       [vma_cv_attribute_$1=yes],
                       [vma_cv_attribute_$1=no])
        AS_IF([test "x$vma_cv_attribute_$1" = "xyes"], [
            AC_LANG_PUSH(C++)
            AC_TRY_COMPILE([extern "C" {
                           $2
                           }],[],
                           [vma_cv_attribute_$1=yes],
                           [vma_cv_attribute_$1=no])
            AC_LANG_POP(C++)
        ])
    ])

    AC_MSG_CHECKING([for attribute $1])
    AC_MSG_RESULT([$vma_cv_attribute_$1])
    AS_IF([test "x$vma_cv_attribute_$1" = "xyes"], [
        AS_IF([test "x$3" = "x"],
            [AC_DEFINE_UNQUOTED([DEFINED_$1], [1], [Define to 1 if attribute $1 is supported])],
            [AC_DEFINE_UNQUOTED([DEFINED_$3], [1], [Define to 1 if attribute $1 is supported])]
        )
    ])
])



##########################
# Set compiler capabilities
#
AC_DEFUN([COMPILER_CAPABILITY_SETUP],
[

CHECK_COMPILER_ATTRIBUTE([optimize],
                         [int foo (int arg) __attribute__ ((optimize("O0")));],
                         [ATTRIBUTE_OPTIMIZE])
])
