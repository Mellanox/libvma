#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#
# verbs.m4 - Parsing verbs capabilities

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

AC_CHECK_HEADERS([infiniband/mlx5dv.h], ,
    [AC_MSG_ERROR([Unable to find the libmlx5 header files])])

AC_CHECK_LIB(ibverbs,
    ibv_get_device_list, [VERBS_LIBS="$VERBS_LIBS -libverbs"],
    AC_MSG_ERROR([ibv_get_device_list() not found.]))

AC_CHECK_LIB(rdmacm,
    rdma_create_id, [VERBS_LIBS="$VERBS_LIBS -lrdmacm"],
    AC_MSG_ERROR([rdma_create_id() not found.]))

AC_CHECK_LIB(mlx5,
    mlx5dv_init_obj, [VERBS_LIBS="$VERBS_LIBS -lmlx5"],
    AC_MSG_ERROR([mlx5dv_init_obj() not found.]))

AC_SUBST([VERBS_LIBS])

# Check <verbs.h>
#
CHECK_VERBS_ATTRIBUTE([IBV_CQ_ATTR_MODERATE], [infiniband/verbs.h], [IBV_CQ_ATTR_MODERATE])
CHECK_VERBS_ATTRIBUTE([IBV_QPT_RAW_PACKET], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_WC_WITH_VLAN], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_ACCESS_ALLOCATE_MR], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_QP_CREATE_SOURCE_QPN], [infiniband/verbs.h], [IBV_QP_INIT_SOURCE_QPN])
CHECK_VERBS_ATTRIBUTE([IBV_DEVICE_RAW_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_SEND_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_FLOW_SPEC_ACTION_TAG], [infiniband/verbs.h], [IBV_FLOW_TAG])
CHECK_VERBS_ATTRIBUTE([IBV_WC_EX_WITH_COMPLETION_TIMESTAMP], [infiniband/verbs.h], [IBV_CQ_TIMESTAMP])
CHECK_VERBS_MEMBER([struct ibv_device_attr_ex.orig_attr], [infiniband/verbs.h], [IBV_DEVICE_ATTR_EX])
CHECK_VERBS_MEMBER([struct ibv_alloc_dm_attr.length], [infiniband/verbs.h], [IBV_DM])
CHECK_VERBS_MEMBER([struct ibv_packet_pacing_caps.qp_rate_limit_min], [infiniband/verbs.h], [IBV_PACKET_PACING_CAPS])
CHECK_VERBS_MEMBER([struct ibv_qp_rate_limit_attr.max_burst_sz], [infiniband/verbs.h], [IBV_QP_SUPPORT_BURST])

CHECK_VERBS_ATTRIBUTE([MLX5_OPCODE_NOP], [infiniband/mlx5dv.h], [IBV_WR_NOP])
CHECK_VERBS_MEMBER([struct mlx5dv_clock_info.last_cycles], [infiniband/mlx5dv.h], [IBV_CLOCK_INFO])
CHECK_VERBS_MEMBER([struct mlx5dv_context.num_lag_ports], [infiniband/mlx5dv.h], [ROCE_LAG])

])
