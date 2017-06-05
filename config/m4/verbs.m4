# verbs.m4 - Parsing verbs capabilities
# 
# Copyright (C) Mellanox Technologies Ltd. 2016-2017.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

##########################
# Configure ofed capabilities
#
AC_DEFUN([VERBS_CAPABILITY_SETUP],
[

#
# Experimental Verbs CQ
#
AC_ARG_ENABLE([exp-cq],
    AC_HELP_STRING([--disable-exp-cq],
                   [Disable experimental Verbs CQ (required for UDP RX HW Timestamp and for RX CSUM verification offload)]),
    [],
    [enable_exp_cq=yes]
)

AS_IF([test "x$enable_exp_cq" == xyes],
        [AC_DEFINE([DEFINED_IBV_EXP_CQ], 1, [Define to 1 if Experimental Verbs CQ was enabled at configure time])]

	AC_MSG_CHECKING([if IBV_EXP_CQ_TIMESTAMP is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_CQ_TIMESTAMP;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_CQ_TIMESTAMP, 1, [Define to 1 if IBV_EXP_CQ_TIMESTAMP is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_DEVICE_RX_CSUM_L4_PKT is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_DEVICE_RX_CSUM_L4_PKT;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_DEVICE_RX_CSUM_L4_PKT, 1, [Define to 1 if IBV_EXP_DEVICE_RX_CSUM_L4_PKT is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT;
	  access = access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT, 1, [Define to 1 if IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])

	AC_MSG_CHECKING([if IBV_EXP_FLOW_SPEC_ACTION_TAG is defined])
	AC_TRY_LINK(
	#include <infiniband/verbs_exp.h>
	,
	[
	  int access = (int)IBV_EXP_FLOW_SPEC_ACTION_TAG;
	  return access;
	],
	[
	  AC_MSG_RESULT([yes])
	  AC_DEFINE(DEFINED_IBV_EXP_FLOW_TAG, 1, [Define to 1 if IBV_EXP_FLOW_SPEC_ACTION_TAG is defined])
	],
	[
	  AC_MSG_RESULT([no])
	])
)


AC_MSG_CHECKING([if IBV_QPT_RAW_PACKET is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int qp_type = (int)IBV_QPT_RAW_PACKET;
  qp_type = qp_type;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_QPT_RAW_PACKET, 1, [Define to 1 if IBV_QPT_RAW_PACKET is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_WC_WITH_VLAN is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int  vlan_flag = (int)IBV_WC_WITH_VLAN;
  vlan_flag = vlan_flag;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_WC_WITH_VLAN, 1, [Define to 1 if IBV_WC_WITH_VLAN is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_ACCESS_ALLOCATE_MR is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_ACCESS_ALLOCATE_MR;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
])

# Check if MLNX_OFED's experimental CQ moderiation API is supported
# This API allows VMA to implement the CQ manual and automatic interrupt moderation logic
# If it is not supported then VMA code will disable all of it's CQ interrupt moderation logic
AC_MSG_CHECKING([if IBV_EXP_CQ_MODERATION is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_CQ_MODERATION;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_CQ_MODERATION, 1, [Define to 1 if IBV_EXP_CQ_MODERATION is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_WR_NOP is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_WR_NOP;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_WR_NOP, 1, [Define to 1 if IBV_EXP_WR_NOP is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_ACCESS_ALLOCATE_MR;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
],
[
  AC_MSG_RESULT([no])
  AC_DEFINE(DEFINED_IBV_OLD_VERBS_MLX_OFED, 1, [Define to 1 if IBV_EXP_ACCESS_ALLOCATE_MR is defined])
])

AC_MSG_CHECKING([if IBV_DEVICE_RAW_IP_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_DEVICE_RAW_IP_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_DEVICE_RAW_IP_CSUM, 1, [Define to 1 if IBV_DEVICE_RAW_IP_CSUM is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_SEND_IP_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_SEND_IP_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_SEND_IP_CSUM, 1, [Define to 1 if IBV_SEND_IP_CSUM is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN, 1, [Define to 1 if IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_EXP_FLOW_SPEC_IB is defined])
AC_TRY_LINK(
#include <infiniband/verbs_exp.h>
,
[
  int access = (int)IBV_EXP_FLOW_SPEC_IB;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_FLOW_SPEC_IB, 1, [Define to 1 if IBV_EXP_FLOW_SPEC_IB is defined])
],
[
  AC_MSG_RESULT([no])
])

AC_MSG_CHECKING([if IBV_FLOW_SPEC_IB is defined])
AC_TRY_LINK(
#include <infiniband/verbs.h>
,
[
  int access = (int)IBV_FLOW_SPEC_IB;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_IBV_FLOW_SPEC_IB, 1, [Define to 1 if IBV_FLOW_SPEC_IB is defined])
],
[
  AC_MSG_RESULT([no])
])


AC_MSG_CHECKING([if MLX5_ETH_WQE_L3_CSUM is defined])
AC_TRY_LINK(
#include <infiniband/mlx5_hw.h>
,
[
  int access = (int)MLX5_ETH_WQE_L3_CSUM;
  access = access;
],
[
  AC_MSG_RESULT([yes])
  AC_DEFINE(DEFINED_MLX5_HW_ETH_WQE_HEADER, 1, [Define to 1 if MLX5_ETH_WQE_L3_CSUM is defined])
],
[
  AC_MSG_RESULT([no])
])


#
# On Device Memory
#
AC_MSG_CHECKING([if on device memory is enabled])
AC_CHECK_DECL([IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE],
    [AC_DEFINE(HAVE_IBV_DM, 1, [Define to 1 if IBV_EXP_DEVICE_ATTR_MAX_DM_SIZE is defined]) [AC_MSG_RESULT([yes])]],
    [AC_MSG_RESULT([no])],
    [[#include <infiniband/verbs_exp.h>]])


AC_CHECK_DECLS([IBV_EXP_QP_RATE_LIMIT],
	[AC_DEFINE(DEFINED_IBV_EXP_QP_RATE_LIMIT, 1, [Define to 1 if IBV_EXP_QP_RATE_LIMIT defined])],
	[], [[#include <infiniband/mlx5_hw.h>]])

TMP_LDFLAGS=$LDFLAGS
AC_SEARCH_LIBS([rdma_create_id],[rdmacm],
		[LDFLAGS="$LDFLAGS -lrdmacm" VERBS_LIBS="$VERBS_LIBS -lrdmacm"],
		[])
AC_CHECK_FUNCS_ONCE([rdma_lib_reset])
AC_CHECK_LIB([ibverbs], [ibv_cmd_poll_cq], [VERBS_LIBS="$VERBS_LIBS -libverbs"],
		[])
AC_SUBST([VERBS_LIBS])

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

AC_MSG_CHECKING([if multi packet RQ is enabled])
AS_IF([test "x$have_mp_rq" == xyes],
	[AC_DEFINE([HAVE_MP_RQ], 1, [MP_RQ QP supported])] [AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])])

LDFLAGS=$TMP_LDFLAGS
])
