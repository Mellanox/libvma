# verbs.m4 - Parsing verbs capabilities
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2018.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#


# Check attributes
# Usage: CHECK_VERBS_ATTRIBUTE([attribute], [header file], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_VERBS_ATTRIBUTE], [
    AC_TRY_LINK(
        [#include <$2>],
        [int attr = (int)$1; attr = attr;],
        [vma_cv_attribute_$1=yes],
        [vma_cv_attribute_$1=no])

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


# Check if OFED verbs (2.1 and older)
#
AC_MSG_CHECKING([for Mellanox OFED verbs (2.1 and older)])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_ACCESS_ALLOCATE_MR;
  access = access;
],
[
  AC_MSG_RESULT([no])
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_OLD_VERBS_MLX_OFED, 1, [Define to 1 for ofed 2.1 and older])
])


# Check if direct hardware operations can be used instead of VERBS API
# infiniband/mlx5_hw.h should exist
#
AC_CHECK_HEADER([infiniband/mlx5_hw.h],
    [AC_CHECK_MEMBERS([struct mlx5_qp.ctrl_seg, struct mlx5_qp.gen_data],
        [AC_DEFINE([HAVE_INFINIBAND_MLX5_HW_H],1,[infiniband/mlx5_hw.h can be used])
            enable_mlx5=yes],
        [enable_mlx5=no],
        [[#include <infiniband/mlx5_hw.h>]] )],
        [],[]
)


# Enable tcp tx window availability
#
AC_ARG_ENABLE([tcp-tx-wnd-availability],
    AC_HELP_STRING([--enable-tcp-tx-wnd-availability],
                   [Enable TCP Tx window availability (TCP packets will only be sent if their size (hdr options + data) is less than or equal to the window size. Otherwise -1 is returned and errno is set to EAGAIN)]),
    [AC_DEFINE(DEFINED_TCP_TX_WND_AVAILABILITY, 1, [Define to 1 to enable TCP Tx window availability])],
    [])


#
# Experimental Verbs CQ
#
AC_ARG_ENABLE([exp-cq],
    AC_HELP_STRING([--disable-exp-cq],
                   [Disable experimental Verbs CQ (disables UDP RX HW Timestamp, RX CSUM verification offload and Multi Packet RQ)]),
    [enable_exp_cq=no],
    [enable_exp_cq=yes]
)

AS_IF([test "x$enable_exp_cq" == xyes],
    [AC_DEFINE([DEFINED_IBV_EXP_CQ], 1, [Define to 1 if Experimental Verbs CQ was enabled at configure time])]

    CHECK_VERBS_ATTRIBUTE([IBV_EXP_CQ_TIMESTAMP], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_VALUES_CLOCK_INFO], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_RX_CSUM_L4_PKT], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT], [infiniband/verbs_exp.h])
    CHECK_VERBS_ATTRIBUTE([IBV_EXP_FLOW_SPEC_ACTION_TAG], [infiniband/verbs_exp.h], [IBV_EXP_FLOW_TAG])
)

# Check <verbs.h>
#
CHECK_VERBS_ATTRIBUTE([IBV_QPT_RAW_PACKET], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_WC_WITH_VLAN], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_ACCESS_ALLOCATE_MR], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_FLOW_SPEC_IB], [infiniband/verbs.h], [IBV_FLOW_SPEC_IB])
CHECK_VERBS_ATTRIBUTE([IBV_DEVICE_RAW_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_SEND_IP_CSUM], [infiniband/verbs.h])

# Check <verbs_exp.h>
#
CHECK_VERBS_ATTRIBUTE([IBV_EXP_CQ_MODERATION], [infiniband/verbs_exp.h])
CHECK_VERBS_ATTRIBUTE([IBV_EXP_WR_NOP], [infiniband/verbs_exp.h])
CHECK_VERBS_ATTRIBUTE([IBV_EXP_ACCESS_ALLOCATE_MR], [infiniband/verbs_exp.h])
CHECK_VERBS_ATTRIBUTE([IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN], [infiniband/verbs_exp.h])
CHECK_VERBS_ATTRIBUTE([IBV_EXP_FLOW_SPEC_IB], [infiniband/verbs_exp.h], [IBV_FLOW_SPEC_IB])

# Check for <mlx5/wqe.h>
#
CHECK_VERBS_ATTRIBUTE([MLX5_ETH_WQE_L3_CSUM], [infiniband/mlx5_hw.h], [MLX5_HW_ETH_WQE_HEADER])

#
# On Device Memory
#
AC_CHECK_DECL([IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE],
    [AC_DEFINE(HAVE_IBV_DM, 1, [Define to 1 if IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE is defined])],
    [],
    [[#include <infiniband/verbs_exp.h>]])


AC_CHECK_DECLS([IBV_EXP_QP_RATE_LIMIT],
	[AC_DEFINE(DEFINED_IBV_EXP_QP_RATE_LIMIT, 1, [Define to 1 if IBV_EXP_QP_RATE_LIMIT defined])],
	[], [[#include <infiniband/verbs_exp.h>]])

AC_CHECK_DECLS([IBV_EXP_QP_SUPPORT_BURST],
	[AC_DEFINE(DEFINED_IBV_EXP_QP_SUPPORT_BURST, 1, [Define to 1 if IBV_EXP_QP_SUPPORT_BURST defined])],
	[], [[#include <infiniband/verbs_exp.h>]])

have_mp_rq=yes
AC_CHECK_DECLS([IBV_EXP_DEVICE_ATTR_VLAN_OFFLOADS,
		IBV_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN,
		IBV_EXP_CQ_RX_UDP_PACKET,
		MLX5_CQE_L3_HDR_TYPE_MASK,
		MLX5_CQE_L4_OK,
		MLX5_CQE_L4_HDR_TYPE_UDP],
		[],
		[have_mp_rq=no],
		[[#include <infiniband/verbs_exp.h>]
		 [#include <infiniband/mlx5_hw.h>]])

AC_MSG_CHECKING([for multi packet RQ support])
AS_IF([test "x$have_mp_rq" == xyes -a "x$enable_exp_cq" == xyes -a "x$enable_mlx5" == xyes],
	[AC_DEFINE([HAVE_MP_RQ], 1, [MP_RQ QP supported])] [AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])])

AC_CHECK_FUNCS([rdma_lib_reset])
AC_CHECK_FUNCS([ibv_exp_get_device_list])

# Restore LIBS
LIBS=$verbs_saved_libs
])
