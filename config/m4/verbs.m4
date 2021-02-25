# verbs.m4 - Parsing verbs capabilities
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2021. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#


# Check attributes
# Usage: CHECK_VERBS_ATTRIBUTE([attribute], [header file], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_VERBS_ATTRIBUTE], [
    AC_LINK_IFELSE([AC_LANG_PROGRAM([
        [#include <$2>]],
        [[int attr = (int)$1; attr = attr;]])],
        [vma_cv_attribute_$1=yes],
        [vma_cv_attribute_$1=no])

    AC_MSG_CHECKING([for attribute $1])
    AC_MSG_RESULT([$vma_cv_attribute_$1])
    AS_IF([test "x$3" != "x"], [vma_cv_attribute_ex_$3=$vma_cv_attribute_$1])
    AS_IF([test "x$vma_cv_attribute_$1" = "xyes"], [
        AS_IF([test "x$3" = "x"],
            [AC_DEFINE_UNQUOTED([DEFINED_$1], [1], [Define to 1 if attribute $1 is supported])],
            [AC_DEFINE_UNQUOTED([DEFINED_$3], [1], [Define to 1 if attribute $1 is supported])]
        )
    ])
])

# Check attributes
# Usage: CHECK_VERBS_MEMBER([attribute], [header file], [definition])
#
AC_DEFUN([CHECK_VERBS_MEMBER], [
    AC_CHECK_MEMBER( $1, [AC_DEFINE_UNQUOTED([DEFINED_$3], [1], [Define to 1 if attribute $1 is supported])], [], [[#include <$2>]])
])

##########################
# Configure ofed capabilities
#
AC_DEFUN([VERBS_CAPABILITY_SETUP],
[

AC_CHECK_HEADERS([infiniband/verbs.h], ,
    [AC_MSG_ERROR([Unable to find the libibverbs-devel header files])])

AC_CHECK_HEADERS([rdma/rdma_cma.h], ,
    [AC_MSG_ERROR([Unable to find the librdmacm-devel header files])])

AC_CHECK_LIB(ibverbs,
    ibv_get_device_list, [VERBS_LIBS="$VERBS_LIBS -libverbs"],
    AC_MSG_ERROR([ibv_get_device_list() not found.]))

AC_CHECK_LIB(rdmacm,
    rdma_create_id, [VERBS_LIBS="$VERBS_LIBS -lrdmacm"],
    AC_MSG_ERROR([rdma_create_id() not found.]))

AC_SUBST([VERBS_LIBS])

# Save LIBS
verbs_saved_libs=$LIBS
LIBS="$LIBS $VERBS_LIBS"


# Check if VERBS version
#
vma_cv_verbs=0
vma_cv_verbs_str="None"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <infiniband/verbs_exp.h>
]],
[[
    int access = (int)IBV_EXP_ACCESS_ALLOCATE_MR;
    access = access;
]])],
[
    vma_cv_verbs=2
    vma_cv_verbs_str="Experimental"
],
[
    AC_CHECK_HEADER([infiniband/verbs.h],
        [AC_CHECK_MEMBERS([struct ibv_query_device_ex_input.comp_mask],
            [vma_cv_verbs=3 vma_cv_verbs_str="Upstream"],
            [vma_cv_verbs=1 vma_cv_verbs_str="Legacy"],
            [[#include <infiniband/verbs.h>]] )],
            [],
            [AC_MSG_ERROR([Can not detect VERBS version])]
    )
])
AC_MSG_CHECKING([for OFED Verbs version])
AC_MSG_RESULT([$vma_cv_verbs_str])
AC_DEFINE_UNQUOTED([DEFINED_VERBS_VERSION], [$vma_cv_verbs], [Define found Verbs version])


# Check if direct hardware operations can be used instead of VERBS API
#
vma_cv_directverbs=0
case "$vma_cv_verbs" in
    1)
        ;;
    2)
        AC_CHECK_HEADER([infiniband/mlx5_hw.h],
            [AC_CHECK_DECL([MLX5_ETH_INLINE_HEADER_SIZE],
                [vma_cv_directverbs=$vma_cv_verbs], [], [[#include <infiniband/mlx5_hw.h>]])])
        ;;
    3)
        AC_CHECK_HEADER([infiniband/mlx5dv.h],
            [AC_CHECK_LIB(mlx5,
                mlx5dv_init_obj, [VERBS_LIBS="$VERBS_LIBS -lmlx5" vma_cv_directverbs=$vma_cv_verbs])])
        ;;
    *)
        AC_MSG_ERROR([Unrecognized parameter 'vma_cv_verbs' as $vma_cv_verbs])
        ;;
esac
AC_MSG_CHECKING([for direct verbs support])
if test "$vma_cv_directverbs" -ne 0; then
    AC_DEFINE_UNQUOTED([DEFINED_DIRECT_VERBS], [$vma_cv_directverbs], [Direct VERBS support])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi


# Check <verbs.h>
#
CHECK_VERBS_ATTRIBUTE([IBV_CQ_ATTR_MODERATE], [infiniband/verbs.h], [IBV_CQ_ATTR_MODERATE])
CHECK_VERBS_ATTRIBUTE([IBV_QPT_RAW_PACKET], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_WC_WITH_VLAN], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_ACCESS_ALLOCATE_MR], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_QP_CREATE_SOURCE_QPN], [infiniband/verbs.h], [IBV_QP_INIT_SOURCE_QPN])
CHECK_VERBS_ATTRIBUTE([IBV_FLOW_SPEC_IB], [infiniband/verbs.h], [IBV_FLOW_SPEC_IB])
CHECK_VERBS_ATTRIBUTE([IBV_DEVICE_RAW_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_SEND_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_FLOW_SPEC_ACTION_TAG], [infiniband/verbs.h], [IBV_FLOW_TAG])
CHECK_VERBS_ATTRIBUTE([IBV_WC_EX_WITH_COMPLETION_TIMESTAMP], [infiniband/verbs.h], [IBV_CQ_TIMESTAMP])
CHECK_VERBS_MEMBER([struct ibv_device_attr_ex.orig_attr], [infiniband/verbs.h], [IBV_DEVICE_ATTR_EX])
CHECK_VERBS_MEMBER([struct ibv_alloc_dm_attr.length], [infiniband/verbs.h], [IBV_DM])
CHECK_VERBS_MEMBER([struct ibv_packet_pacing_caps.qp_rate_limit_min], [infiniband/verbs.h], [IBV_PACKET_PACING_CAPS])
CHECK_VERBS_MEMBER([struct ibv_qp_rate_limit_attr.max_burst_sz], [infiniband/verbs.h], [IBV_QP_SUPPORT_BURST])

# Check <verbs_exp.h>
#
if test "x$vma_cv_verbs" == x2; then
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_CQ_MODERATION], [infiniband/verbs_exp.h], [IBV_CQ_ATTR_MODERATE])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_WR_NOP], [infiniband/verbs_exp.h], [IBV_WR_NOP])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_ACCESS_ALLOCATE_MR], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN], [infiniband/verbs_exp.h], [IBV_QP_INIT_SOURCE_QPN])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_FLOW_SPEC_IB], [infiniband/verbs_exp.h], [IBV_FLOW_SPEC_IB])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_SEND_IP_CSUM], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE], [infiniband/verbs_exp.h], [IBV_DM])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_QP_RATE_LIMIT], [infiniband/verbs_exp.h], [IBV_PACKET_PACING_CAPS])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_QP_SUPPORT_BURST], [infiniband/verbs_exp.h], [IBV_QP_SUPPORT_BURST])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_WR_TSO], [infiniband/verbs_exp.h], [OPCODE_TSO])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_CROSS_CHANNEL], [infiniband/verbs_exp.h], [IBV_DEVICE_CROSS_CHANNEL])

    #
    # Experimental Verbs CQ
    #
    AC_ARG_ENABLE([exp-cq],
        AS_HELP_STRING([--disable-exp-cq],
                       [Disable experimental Verbs CQ (disables UDP RX HW Timestamp, RX CSUM verification offload and Multi Packet RQ)]),
        [enable_exp_cq=no],
        [enable_exp_cq=yes]
    )

    AS_IF([test "x$enable_exp_cq" == xyes],
        [AC_DEFINE([DEFINED_IBV_EXP_CQ], 1, [Define to 1 if Experimental Verbs CQ was enabled at configure time])]

        CHECK_VERBS_ATTRIBUTE([IBV_EXP_CQ_TIMESTAMP], [infiniband/verbs_exp.h], [IBV_CQ_TIMESTAMP])
        CHECK_VERBS_ATTRIBUTE([IBV_EXP_VALUES_CLOCK_INFO], [infiniband/verbs_exp.h], [IBV_CLOCK_INFO])
        CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_RX_CSUM_L4_PKT], [infiniband/verbs_exp.h])
        CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT], [infiniband/verbs_exp.h])
        CHECK_VERBS_ATTRIBUTE([IBV_EXP_FLOW_SPEC_ACTION_TAG], [infiniband/verbs_exp.h], [IBV_FLOW_TAG])
    )

    AC_CHECK_FUNCS([rdma_lib_reset])
    AC_CHECK_FUNCS([ibv_exp_get_device_list])
fi

# Check Upstream
#
if test "x$vma_cv_verbs" == x3; then
    CHECK_VERBS_ATTRIBUTE([IBV_WR_TSO], [infiniband/verbs.h], [OPCODE_TSO])

    if test "x$vma_cv_directverbs" == x3; then
        CHECK_VERBS_ATTRIBUTE([MLX5_OPCODE_NOP], [infiniband/mlx5dv.h], [IBV_WR_NOP])
        CHECK_VERBS_MEMBER([struct mlx5dv_clock_info.last_cycles], [infiniband/mlx5dv.h], [IBV_CLOCK_INFO])
        CHECK_VERBS_MEMBER([struct mlx5dv_context.num_lag_ports], [infiniband/mlx5dv.h], [ROCE_LAG])
    fi
fi

# Restore LIBS
LIBS=$verbs_saved_libs
])
