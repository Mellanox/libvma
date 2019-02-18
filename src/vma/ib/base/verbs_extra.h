/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef VERBS_EXTRA_H
#define VERBS_EXTRA_H

#include <rdma/rdma_cma.h>
#include <config.h>
#include <infiniband/verbs.h>
#include "vma/util/vtypes.h"
#if defined(DEFINED_VERBS_VERSION) && (DEFINED_VERBS_VERSION == 2)
#include <infiniband/verbs_exp.h>
#endif
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#if defined(DEFINED_DIRECT_VERBS)
#include "vma/ib/mlx5/ib_mlx5.h"
#endif /* DEFINED_DIRECT_VERBS */

#ifndef DEFINED_IBV_WC_WITH_VLAN
//#warning probaly you are trying to compile on OFED which doesnt support VLAN for RAW QP.
//#error when you see this then you need to manually open the below comment and to comment the current and the previous lines.
//#define IBV_WC_WITH_VLAN		1 << 3
#endif

// Wrapper for all IBVERBS & RDMA_CM API to normalize the return code and errno value
// With these marco all ibverbs & rdma_cm failures are caugth and errno is updated
// Without this marco ibverbs & rdma_cm returns sometimes with -1 and sometimes with -errno
inline int _errnocheck(int rc) {
    if (rc < -1) {
        errno = -rc;
    }
    return rc;
}

#define IF_VERBS_FAILURE_EX(__func__, __err__)  { if (_errnocheck(__func__) && (errno != __err__))
#define IF_VERBS_FAILURE(__func__)  { if (_errnocheck(__func__))
#define ENDIF_VERBS_FAILURE			}


#define IF_RDMACM_FAILURE(__func__)		IF_VERBS_FAILURE(__func__)
#define ENDIF_RDMACM_FAILURE			ENDIF_VERBS_FAILURE
#define IPOIB_QKEY 0x0b1b

// See - IB Arch Spec - 11.6.2 COMPLETION RETURN STATUS
const char* priv_ibv_wc_status_str(enum ibv_wc_status status);

// See - IB Arch Spec - 11.6.3 ASYNCHRONOUS EVENTS
const char* priv_ibv_event_desc_str(enum ibv_event_type type);

#define priv_rdma_cm_event_type_str(__rdma_cm_ev_t__)	\
				rdma_event_str(__rdma_cm_ev_t__)

// Find pkey_index from the ibv_context + port_num + pkey
int priv_ibv_find_pkey_index(struct ibv_context *verbs, uint8_t port_num, uint16_t pkey, uint16_t *pkey_index);

int priv_ibv_modify_qp_to_err(struct ibv_qp *qp);
int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num);
int priv_ibv_modify_qp_from_err_to_init_ud(struct ibv_qp *qp, uint8_t port_num, uint16_t pkey_index, uint32_t underly_qpn);
int priv_ibv_modify_qp_from_init_to_rts(struct ibv_qp *qp, uint32_t underly_qpn = 0);

// Return 'ibv_qp_state' of the ibv_qp
int priv_ibv_query_qp_state(struct ibv_qp *qp);

// change  ib rate limit
int priv_ibv_modify_qp_ratelimit(struct ibv_qp *qp, struct vma_rate_limit_t &rate_limit, uint32_t rl_changes);

// Modify cq moderation
void priv_ibv_modify_cq_moderation(struct ibv_cq* cq, uint32_t period, uint32_t count);

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK      0xFFF	/* define vlan range: 1-4095. taken from <linux/if_vlan.h> */
#endif

#define FS_MASK_ON_8      (0xff)
#define FS_MASK_ON_16     (0xffff)
#define FS_MASK_ON_32     (0xffffffff)

#define FLOW_TAG_MASK     ((1 << 20) -1)
int priv_ibv_query_flow_tag_supported(struct ibv_qp *qp, uint8_t port_num);
int priv_ibv_create_flow_supported(struct ibv_qp *qp, uint8_t port_num);
int priv_ibv_query_burst_supported(struct ibv_qp *qp, uint8_t port_num);

/* DEFINED_VERBS_VERSION:
 * 1 - Legacy Verbs API
 * 2 - Experimental Verbs API
 * 3 - Upstream Verbs API
 */
#if defined(DEFINED_VERBS_VERSION) && (DEFINED_VERBS_VERSION == 1 || DEFINED_VERBS_VERSION == 3)
//ibv_create_qp
#ifdef DEFINED_IBV_QP_INIT_SOURCE_QPN
#define vma_ibv_create_qp(pd, attr)                ibv_create_qp_ex((pd)->context, attr)
typedef struct ibv_qp_init_attr_ex                 vma_ibv_qp_init_attr;
#define vma_ibv_qp_create_flags(attr)              (attr).create_flags
#define vma_ibv_qp_source_qpn(attr)                (attr).source_qpn
#define VMA_IBV_QP_INIT_QPN_CREATE_FLAGS           IBV_QP_CREATE_SOURCE_QPN
#define VMA_IBV_QP_INIT_QPN_MASK                   IBV_QP_INIT_ATTR_CREATE_FLAGS
#define vma_ibv_qp_init_attr_comp_mask(_pd, _attr) { (_attr).pd = _pd; (_attr).comp_mask |= IBV_QP_INIT_ATTR_PD; }
#else
#define vma_ibv_create_qp(pd, attr)                 ibv_create_qp(pd, attr)
typedef struct ibv_qp_init_attr                     vma_ibv_qp_init_attr;
#define vma_ibv_qp_init_attr_comp_mask(_pd, _attr)  { NOT_IN_USE(_pd); NOT_IN_USE(_attr); }
#endif

//ibv_query_device
#define vma_ibv_device_attr_comp_mask(attr)   NOT_IN_USE(attr)
typedef struct ibv_device_attr                vma_ibv_device_attr;

#ifdef DEFINED_IBV_DEVICE_ATTR_EX
#define vma_ibv_query_device(context, attr)   ibv_query_device_ex(context, NULL, attr)
typedef struct ibv_device_attr_ex             vma_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) &device_attr->orig_attr
#else
#define vma_ibv_query_device(context, attr)   ibv_query_device(context, attr)
typedef vma_ibv_device_attr                   vma_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) device_attr
#endif

//ibv_modify_qp
#define vma_ibv_modify_qp(qp, attr, mask)	ibv_modify_qp(qp, attr, mask)
typedef struct ibv_qp_attr			vma_ibv_qp_attr;
//ibv_poll_cq
#define vma_ibv_poll_cq(cq, num, wc)		ibv_poll_cq(cq, num, wc)
typedef struct ibv_wc				vma_ibv_wc;
#define vma_wc_flags(wc)			(wc).wc_flags
#define vma_wc_opcode(wc)			(wc).opcode
#define VMA_IBV_WC_RECV				IBV_WC_RECV
//csum offload
#ifdef DEFINED_IBV_DEVICE_RAW_IP_CSUM
#define vma_is_rx_hw_csum_supported(attr)	((attr)->device_cap_flags & (IBV_DEVICE_RAW_IP_CSUM | IBV_DEVICE_UD_IP_CSUM))
#define vma_wc_rx_hw_csum_ok(wc)		(vma_wc_flags(wc) & IBV_WC_IP_CSUM_OK)
#else
#define vma_is_rx_hw_csum_supported(attr)	0
#define vma_wc_rx_hw_csum_ok(wc)		(1)
#endif

typedef int            vma_ibv_cq_init_attr;
#define vma_ibv_create_cq(context, cqe, cq_context, channel, comp_vector, attr) ibv_create_cq(context, cqe, cq_context, channel, comp_vector)

//rx hw timestamp
#define VMA_IBV_WC_WITH_TIMESTAMP             0
#define vma_wc_timestamp(wc)                  0
#define vma_ibv_cq_init_ts_attr(attr)         { NOT_IN_USE(attr); }

#ifdef DEFINED_IBV_CQ_TIMESTAMP
#define VMA_IBV_DEVICE_ATTR_HCA_CORE_CLOCK    0
#define VMA_IBV_VALUES_MASK_RAW_CLOCK         IBV_VALUES_MASK_RAW_CLOCK
#define vma_ibv_query_values(ctx, values)     ibv_query_rt_values_ex(ctx, values)
#define vma_get_ts_val(values)                values.raw_clock.tv_nsec
typedef struct ibv_values_ex                  vma_ts_values;
#endif

//ibv_post_send
#define VMA_IBV_SEND_SIGNALED			IBV_SEND_SIGNALED
#define VMA_IBV_SEND_INLINE			IBV_SEND_INLINE
#ifdef DEFINED_IBV_SEND_IP_CSUM
	#define VMA_IBV_SEND_IP_CSUM			(IBV_SEND_IP_CSUM)
#else
	#define DEFINED_SW_CSUM
#endif
#define vma_ibv_send_flags			ibv_send_flags
#define vma_send_wr_send_flags(wr)		(wr).send_flags
#define VMA_IBV_WR_SEND				IBV_WR_SEND
#define vma_ibv_wr_opcode			ibv_wr_opcode
#define vma_send_wr_opcode(wr)			(wr).opcode

#ifdef DEFINED_TSO
  #define VMA_IBV_WR_TSO                  (vma_ibv_wr_opcode)IBV_WR_TSO
  #define vma_check_dev_attr_tso(_attr)   1
  #define vma_get_tso_caps(_attr)         (((vma_ibv_device_attr_ex *)(_attr))->tso_caps)
  #define vma_ibv_qp_init_attr_tso(_attr, _max_tso_header) \
		do { \
			_attr.comp_mask |= IBV_QP_INIT_ATTR_MAX_TSO_HEADER; \
			_attr.max_tso_header = _max_tso_header;   \
		} while (0)
  typedef struct ibv_tso_caps             vma_ibv_tso_caps;
#else
  #define VMA_IBV_WR_TSO                  (vma_ibv_wr_opcode)VMA_IBV_WR_SEND
  #define vma_check_dev_attr_tso(_attr)   0
  #define vma_ibv_qp_init_attr_tso(_attr, _max_tso_header) ((void)0)
#endif /* DEFINED_TSO */

// Dummy send
#ifdef DEFINED_IBV_WR_NOP
#define vma_is_nop_supported(device_attr)    1
#define VMA_IBV_WR_NOP                       (vma_ibv_wr_opcode)MLX5_OPCODE_NOP
#else
#define vma_is_nop_supported(device_attr)    0
#define VMA_IBV_WR_NOP                       (vma_ibv_wr_opcode)(0) // Use 0 as "default" opcode when NOP is not defined.
#endif

#define vma_ibv_post_send(qp, wr, bad_wr)	ibv_post_send(qp, wr, bad_wr)
typedef struct ibv_send_wr			vma_ibv_send_wr;
//ibv_reg_mr
#define VMA_IBV_ACCESS_LOCAL_WRITE		IBV_ACCESS_LOCAL_WRITE
#ifdef DEFINED_IBV_ACCESS_ALLOCATE_MR
#define VMA_IBV_ACCESS_ALLOCATE_MR		IBV_ACCESS_ALLOCATE_MR
#endif
//flow steering
#define VMA_IBV_FLOW_ATTR_NORMAL		IBV_FLOW_ATTR_NORMAL
#define VMA_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK	IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK
#ifdef DEFINED_IBV_FLOW_SPEC_IB
#define VMA_IBV_FLOW_SPEC_IB			IBV_FLOW_SPEC_IB
#endif
#define VMA_IBV_FLOW_SPEC_ETH			IBV_FLOW_SPEC_ETH
#define VMA_IBV_FLOW_SPEC_IPV4			IBV_FLOW_SPEC_IPV4
#define VMA_IBV_FLOW_SPEC_TCP			IBV_FLOW_SPEC_TCP
#define VMA_IBV_FLOW_SPEC_UDP			IBV_FLOW_SPEC_UDP
#define vma_ibv_create_flow(qp, flow)		ibv_create_flow(qp, flow)
#define vma_ibv_destroy_flow(flow_id)		ibv_destroy_flow(flow_id)
typedef struct ibv_flow				vma_ibv_flow;
typedef struct ibv_flow_attr			vma_ibv_flow_attr;
typedef struct ibv_flow_spec_ib			vma_ibv_flow_spec_ib;
typedef struct ibv_flow_spec_eth		vma_ibv_flow_spec_eth;
typedef struct ibv_flow_spec_ipv4		vma_ibv_flow_spec_ipv4;
typedef struct ibv_flow_spec_tcp_udp		vma_ibv_flow_spec_tcp_udp;

// Flow tag
#ifdef DEFINED_IBV_FLOW_TAG
#define VMA_IBV_FLOW_SPEC_ACTION_TAG               IBV_FLOW_SPEC_ACTION_TAG
typedef struct ibv_flow_spec_action_tag            vma_ibv_flow_spec_action_tag;
#define vma_get_flow_tag(cqe)                      ntohl((uint32_t)(cqe->sop_drop_qpn))
#else
typedef struct ibv_flow_spec_action_tag_dummy {}   vma_ibv_flow_spec_action_tag;
#define vma_get_flow_tag(cqe)                      0
#endif // DEFINED_IBV_FLOW_TAG

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
typedef struct ibv_modify_cq_attr               vma_ibv_cq_attr;
#define vma_ibv_modify_cq(cq, cq_attr, mask)    ibv_modify_cq(cq, cq_attr)
#define vma_cq_attr_mask(cq_attr)               (cq_attr).attr_mask
#define vma_cq_attr_moderation(cq_attr)         (cq_attr).moderate
#define VMA_IBV_CQ_MODERATION                   IBV_CQ_ATTR_MODERATE
#endif

// Clock info
#ifdef DEFINED_IBV_CLOCK_INFO
typedef struct mlx5dv_clock_info                    vma_ibv_clock_info;
#define vma_ibv_query_clock_info(ctx, clock_info)   mlx5dv_get_clock_info(ctx, clock_info)
#define vma_ibv_convert_ts_to_ns(clock_info, hw_ts) mlx5dv_ts_to_ns(clock_info, hw_ts)
#endif //DEFINED_IBV_CLOCK_INFO

// ibv_dm
#ifdef DEFINED_IBV_DM
#define vma_ibv_alloc_dm(ctx, attr)      ibv_alloc_dm(ctx, attr)
#define vma_ibv_free_dm(dm)              ibv_free_dm(dm)
#define vma_ibv_reg_dm_mr(mr)            ibv_reg_dm_mr((mr)->pd, (mr)->dm, 0, (mr)->length, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_ZERO_BASED)
#define vma_ibv_memcpy_dm(dm, attr)      ibv_memcpy_to_dm(dm, (attr)->dm_offset, (attr)->host_addr, (attr)->length)
#define vma_ibv_init_memcpy_dm(attr, src, head, size)          { attr.host_addr = src; attr.dm_offset = head; attr.length = size; }
#define vma_ibv_init_dm_mr(in_mr, ctx_pd, size, allocated_dm)  { in_mr.pd = ctx_pd; in_mr.length = size; in_mr.dm = allocated_dm; }
typedef struct ibv_alloc_dm_attr         vma_ibv_alloc_dm_attr;
typedef struct ibv_dm                    vma_ibv_dm;
typedef struct {
	void * host_addr;
	uint64_t dm_offset;
	size_t length;
} vma_ibv_memcpy_dm_attr;
typedef struct {
	struct ibv_pd *pd;
	size_t      length;
	vma_ibv_dm *dm;
} vma_ibv_reg_mr_in;
#endif

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
#define VMA_IBV_QP_RATE_LIMIT                IBV_QP_RATE_LIMIT
#define vma_is_pacing_caps_supported(attr)   (attr->packet_pacing_caps.qp_rate_limit_min)

#ifdef DEFINED_IBV_QP_SUPPORT_BURST
#define vma_ibv_init_burst_attr(qp_attr, rate_limit)    { qp_attr.max_burst_sz = rate_limit.max_burst_sz; qp_attr.typical_pkt_sz = rate_limit.typical_pkt_sz; }
typedef struct ibv_qp_rate_limit_attr                   vma_ibv_rate_limit_attr;
#define vma_ibv_modify_qp_rate_limit(qp, attr, mask)    ibv_modify_qp_rate_limit(qp, attr)
#define vma_ibv_init_qps_attr(qp_attr)                  { NOT_IN_USE(qp_attr); }
#else
typedef vma_ibv_qp_attr                                 vma_ibv_rate_limit_attr;
#define vma_ibv_modify_qp_rate_limit(qp, attr, mask)    vma_ibv_modify_qp(qp, attr, mask)
#define vma_ibv_init_qps_attr(qp_attr)                  { qp_attr.qp_state = IBV_QPS_RTS; }
#endif // DEFINED_IBV_QP_SUPPORT_BURST

#endif // DEFINED_IBV_PACKET_PACING_CAPS

#else /* DEFINED_VERBS_VERSION */

//ibv_create_qp
#define vma_ibv_create_qp(pd, attr)             ibv_exp_create_qp((pd)->context, attr)
typedef struct ibv_exp_qp_init_attr             vma_ibv_qp_init_attr;
#define vma_ibv_qp_init_attr_comp_mask(_pd, _attr)	{ (_attr).pd = _pd; (_attr).comp_mask |= IBV_EXP_QP_INIT_ATTR_PD; }

#ifdef DEFINED_IBV_QP_INIT_SOURCE_QPN
#define vma_ibv_qp_create_flags(attr)              (attr).exp_create_flags
#define vma_ibv_qp_source_qpn(attr)                (attr).associated_qpn
#define VMA_IBV_QP_INIT_QPN_CREATE_FLAGS           0
#define VMA_IBV_QP_INIT_QPN_MASK                   IBV_EXP_QP_INIT_ATTR_ASSOCIATED_QPN
#endif

//ibv_query_device
#define vma_ibv_query_device(context, attr)   ibv_exp_query_device(context, attr)
typedef struct ibv_exp_device_attr            vma_ibv_device_attr;
typedef vma_ibv_device_attr                   vma_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) device_attr
#define vma_ibv_device_attr_comp_mask(attr)   { (attr)->comp_mask = IBV_EXP_DEVICE_ATTR_RESERVED - 1; }

#ifdef DEFINED_IBV_EXP_DEVICE_RX_CSUM_L4_PKT
#define vma_is_rx_hw_csum_supported(attr)	(((attr)->exp_device_cap_flags & IBV_EXP_DEVICE_RX_CSUM_L3_PKT) \
						&& ((attr)->exp_device_cap_flags & IBV_EXP_DEVICE_RX_CSUM_L4_PKT))
#else
#ifdef DEFINED_IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT
#define vma_is_rx_hw_csum_supported(attr)	(((attr)->exp_device_cap_flags & IBV_EXP_DEVICE_RX_CSUM_IP_PKT) \
						&& ((attr)->exp_device_cap_flags & IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT))
#else
#define vma_is_rx_hw_csum_supported(attr)	0
#endif
#endif
//ibv_modify_qp
#define vma_ibv_modify_qp(qp, attr, mask)	ibv_exp_modify_qp(qp, attr, mask)
typedef struct ibv_exp_qp_attr			vma_ibv_qp_attr;

//ibv_exp_poll_cq
#ifdef DEFINED_IBV_EXP_CQ
#define vma_ibv_poll_cq(cq, num, wc)		ibv_exp_poll_cq(cq, num, wc, sizeof(struct ibv_exp_wc))
typedef struct ibv_exp_wc			vma_ibv_wc;
#define vma_wc_flags(wc)			(wc).exp_wc_flags
#define vma_wc_opcode(wc)			(wc).exp_opcode
#define VMA_IBV_WC_RECV				IBV_EXP_WC_RECV

//experimental cq
typedef struct ibv_exp_cq_init_attr           vma_ibv_cq_init_attr;
#define vma_ibv_create_cq(context, cqe, cq_context, channel, comp_vector, attr) ibv_exp_create_cq(context, cqe, cq_context, channel, comp_vector, attr)
#else
//ibv_poll_cq
#define vma_ibv_poll_cq(cq, num, wc)		ibv_poll_cq(cq, num, wc)
typedef struct ibv_wc				vma_ibv_wc;
#define vma_wc_flags(wc)			(wc).wc_flags
#define vma_wc_opcode(wc)			(wc).opcode
#define VMA_IBV_WC_RECV				IBV_WC_RECV

//verbs cq
typedef int            vma_ibv_cq_init_attr;
#define vma_ibv_create_cq(context, cqe, cq_context, channel, comp_vector, attr) ibv_create_cq(context, cqe, cq_context, channel, comp_vector)
#endif

#ifdef DEFINED_IBV_EXP_DEVICE_RX_CSUM_L4_PKT
#define vma_wc_rx_hw_csum_ok(wc)		((vma_wc_flags(wc) & IBV_EXP_L3_RX_CSUM_OK) && (vma_wc_flags(wc) & IBV_EXP_L4_RX_CSUM_OK))
#else
#ifdef DEFINED_IBV_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT
#define vma_wc_rx_hw_csum_ok(wc)		((vma_wc_flags(wc) & IBV_EXP_WC_RX_IP_CSUM_OK) && (vma_wc_flags(wc) & IBV_EXP_WC_RX_TCP_UDP_CSUM_OK))
#else
#define vma_wc_rx_hw_csum_ok(wc)		(1)
#endif
#endif

//rx hw timestamp
#ifdef DEFINED_IBV_CQ_TIMESTAMP
#define VMA_IBV_WC_WITH_TIMESTAMP             IBV_EXP_WC_WITH_TIMESTAMP
#define vma_wc_timestamp(wc)                  (wc).timestamp
#define VMA_IBV_DEVICE_ATTR_HCA_CORE_CLOCK    IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK
#define VMA_IBV_VALUES_MASK_RAW_CLOCK         0
#define vma_ibv_query_values(ctx, values)     ibv_exp_query_values(ctx, IBV_EXP_VALUES_HW_CLOCK, values)
#define vma_get_ts_val(values)                values.hwclock
typedef struct ibv_exp_values                 vma_ts_values;
#define vma_ibv_cq_init_ts_attr(attr)         { (attr)->flags |= IBV_EXP_CQ_TIMESTAMP; (attr)->comp_mask |= IBV_EXP_CQ_INIT_ATTR_FLAGS; }
#else
#define VMA_IBV_WC_WITH_TIMESTAMP             0
#define vma_wc_timestamp(wc)                  0
#define vma_ibv_cq_init_ts_attr(attr)         { NOT_IN_USE(attr); }
#endif

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
typedef struct ibv_exp_cq_attr                  vma_ibv_cq_attr;
#define vma_ibv_modify_cq(cq, cq_attr, mask)    ibv_exp_modify_cq(cq, cq_attr,mask)
#define vma_cq_attr_mask(cq_attr)               (cq_attr).comp_mask
#define vma_cq_attr_moderation(cq_attr)         (cq_attr).moderation
#define VMA_IBV_CQ_MODERATION                   IBV_EXP_CQ_ATTR_MODERATION
#endif

//ibv_post_send
#define VMA_IBV_SEND_SIGNALED			IBV_EXP_SEND_SIGNALED
#define VMA_IBV_SEND_INLINE			IBV_EXP_SEND_INLINE
#ifdef DEFINED_IBV_EXP_SEND_IP_CSUM
	#define VMA_IBV_SEND_IP_CSUM			(IBV_EXP_SEND_IP_CSUM)
#else
	#define DEFINED_SW_CSUM
#endif
#define vma_ibv_send_flags			ibv_exp_send_flags
#define vma_send_wr_send_flags(wr)		(wr).exp_send_flags
#define VMA_IBV_WR_SEND				IBV_EXP_WR_SEND
#define vma_ibv_wr_opcode			ibv_exp_wr_opcode
#define vma_send_wr_opcode(wr)			(wr).exp_opcode

#ifdef DEFINED_TSO
  #define VMA_IBV_WR_TSO                  (vma_ibv_wr_opcode)IBV_EXP_WR_TSO
  #define vma_check_dev_attr_tso(_attr)   ((_attr)->comp_mask & IBV_EXP_DEVICE_ATTR_TSO_CAPS)
  #define vma_get_tso_caps(_attr)         (((vma_ibv_device_attr_ex *)(_attr))->tso_caps)
  #define vma_ibv_qp_init_attr_tso(_attr, _max_tso_header) \
		do { \
			_attr.comp_mask |= IBV_EXP_QP_INIT_ATTR_MAX_TSO_HEADER; \
			_attr.max_tso_header = _max_tso_header;   \
		} while (0)
  typedef struct ibv_exp_tso_caps         vma_ibv_tso_caps;
#else
  #define VMA_IBV_WR_TSO                  (vma_ibv_wr_opcode)VMA_IBV_WR_SEND
  #define vma_check_dev_attr_tso(_attr)   0
  #define vma_ibv_qp_init_attr_tso(_attr, _max_tso_header) ((void)0)
#endif /* DEFINED_TSO */

// Dummy send
#ifdef DEFINED_IBV_WR_NOP
#define vma_is_nop_supported(device_attr)    ((device_attr)->exp_device_cap_flags & IBV_EXP_DEVICE_NOP)
#define VMA_IBV_WR_NOP                       IBV_EXP_WR_NOP
#else
#define vma_is_nop_supported(device_attr)    0
#define VMA_IBV_WR_NOP                      (vma_ibv_wr_opcode)(0) // Use 0 as "default" opcode when NOP is not defined.
#endif

#define vma_ibv_post_send(qp, wr, bad_wr)	ibv_exp_post_send(qp, wr, bad_wr)
typedef struct ibv_exp_send_wr			vma_ibv_send_wr;
//ibv_reg_mr
#define VMA_IBV_ACCESS_LOCAL_WRITE		IBV_EXP_ACCESS_LOCAL_WRITE
#ifdef DEFINED_IBV_EXP_ACCESS_ALLOCATE_MR
#define VMA_IBV_ACCESS_ALLOCATE_MR		IBV_EXP_ACCESS_ALLOCATE_MR
#endif
//flow steering
#define VMA_IBV_FLOW_ATTR_NORMAL		IBV_EXP_FLOW_ATTR_NORMAL
#define VMA_IBV_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK	IBV_EXP_FLOW_ATTR_FLAGS_ALLOW_LOOP_BACK
#ifdef DEFINED_IBV_FLOW_SPEC_IB
#define VMA_IBV_FLOW_SPEC_IB			IBV_EXP_FLOW_SPEC_IB
#endif
#define VMA_IBV_FLOW_SPEC_ETH			IBV_EXP_FLOW_SPEC_ETH
#define VMA_IBV_FLOW_SPEC_IPV4			IBV_EXP_FLOW_SPEC_IPV4
#define VMA_IBV_FLOW_SPEC_TCP			IBV_EXP_FLOW_SPEC_TCP
#define VMA_IBV_FLOW_SPEC_UDP			IBV_EXP_FLOW_SPEC_UDP
#define vma_ibv_create_flow(qp, flow)		ibv_exp_create_flow(qp, flow)
#define vma_ibv_destroy_flow(flow_id)		ibv_exp_destroy_flow(flow_id)
typedef struct ibv_exp_flow			vma_ibv_flow;
typedef struct ibv_exp_flow_attr		vma_ibv_flow_attr;
typedef struct ibv_exp_flow_spec_ib		vma_ibv_flow_spec_ib;
typedef struct ibv_exp_flow_spec_eth		vma_ibv_flow_spec_eth;
typedef struct ibv_exp_flow_spec_ipv4		vma_ibv_flow_spec_ipv4;
typedef struct ibv_exp_flow_spec_tcp_udp	vma_ibv_flow_spec_tcp_udp;

//Flow tag
#ifdef DEFINED_IBV_FLOW_TAG
#define VMA_IBV_FLOW_SPEC_ACTION_TAG                    IBV_EXP_FLOW_SPEC_ACTION_TAG
#define vma_get_flow_tag(cqe)                           ntohl((uint32_t)(cqe->sop_drop_qpn))
typedef struct ibv_exp_flow_spec_action_tag             vma_ibv_flow_spec_action_tag;
#else
#define vma_get_flow_tag(cqe)                           0
typedef struct ibv_exp_flow_spec_action_tag_dummy {}    vma_ibv_flow_spec_action_tag;
#endif //DEFINED_IBV_FLOW_TAG

// Clock info
#ifdef DEFINED_IBV_CLOCK_INFO
typedef struct ibv_exp_values                       vma_ibv_clock_info;
#define vma_ibv_convert_ts_to_ns(info, hw_ts)       ibv_exp_cqe_ts_to_ns(&((info)->clock_info), hw_ts)
#define vma_ibv_query_clock_info(ctx, clock_info)   ibv_exp_query_values(ctx, IBV_EXP_VALUES_CLOCK_INFO, clock_info)
#endif //DEFINED_IBV_CLOCK_INFO

// ibv_dm
#ifdef DEFINED_IBV_DM
#define vma_ibv_alloc_dm(ctx, attr)      ibv_exp_alloc_dm(ctx, attr)
#define vma_ibv_free_dm(dm)              ibv_exp_free_dm(dm)
#define vma_ibv_reg_dm_mr(mr)            ibv_exp_reg_mr(mr)
#define vma_ibv_memcpy_dm(dm, attr)      ibv_exp_memcpy_dm(dm, attr)
#define vma_ibv_init_memcpy_dm(attr, src, head, size)          { attr.memcpy_dir = IBV_EXP_DM_CPY_TO_DEVICE; attr.host_addr = src; attr.dm_offset = head; attr.length = size; }
#define vma_ibv_init_dm_mr(in_mr, ctx_pd, size, allocated_dm)  { in_mr.pd = ctx_pd; in_mr.comp_mask = IBV_EXP_REG_MR_DM; in_mr.length = size; in_mr.dm = allocated_dm; }
typedef struct ibv_exp_alloc_dm_attr     vma_ibv_alloc_dm_attr;
typedef struct ibv_exp_memcpy_dm_attr    vma_ibv_memcpy_dm_attr;
typedef struct ibv_exp_dm                vma_ibv_dm;
typedef struct ibv_exp_reg_mr_in         vma_ibv_reg_mr_in;
#endif

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
#define VMA_IBV_QP_RATE_LIMIT                IBV_EXP_QP_RATE_LIMIT
#define vma_is_pacing_caps_supported(attr)   ((attr)->comp_mask & IBV_EXP_DEVICE_ATTR_PACKET_PACING_CAPS)
typedef vma_ibv_qp_attr                                 vma_ibv_rate_limit_attr;
#define vma_ibv_modify_qp_rate_limit(qp, attr, mask)    vma_ibv_modify_qp(qp, attr, mask)
#define vma_ibv_init_qps_attr(qp_attr)                  { qp_attr.qp_state = IBV_QPS_RTS; }
#endif // DEFINED_IBV_PACKET_PACING_CAPS

#ifdef DEFINED_IBV_QP_SUPPORT_BURST
#define vma_ibv_init_burst_attr(qp_attr, rate_limit)    { qp_attr.burst_info.max_burst_sz = rate_limit.max_burst_sz; qp_attr.burst_info.typical_pkt_sz = rate_limit.typical_pkt_sz; qp_attr.comp_mask |= IBV_EXP_QP_ATTR_BURST_INFO; }
#endif // DEFINED_IBV_QP_SUPPORT_BURST

#endif /* DEFINED_VERBS_VERSION */

// ibv_dm
#ifdef DEFINED_IBV_DM
#define vma_ibv_dm_size(attr)			((attr)->max_dm_size)
#else
#define vma_ibv_dm_size(attr)			(0)
#endif

#ifdef HAVE_MP_RQ
#define vma_is_umr_supported(attr)		((attr)->umr_caps.max_klm_list_size)
#define vma_is_mp_rq_supported(attr)		((attr)->comp_mask & IBV_EXP_DEVICE_ATTR_MP_RQ)
#else
#define vma_is_umr_supported(attr)		(0)
#define vma_is_mp_rq_supported(attr)		(0)
#endif

#if defined(HAVE_IBV_EXP_GET_DEVICE_LIST)
#define vma_ibv_get_device_list(num)		ibv_exp_get_device_list(num)
#else
#define vma_ibv_get_device_list(num)		ibv_get_device_list(num)
#endif

typedef enum {
	RL_RATE = 1<<0,
	RL_BURST_SIZE = 1<<1,
	RL_PKT_SIZE = 1<<2,
} vma_rl_changed;

int vma_rdma_lib_reset();

#ifdef DEFINED_IBV_FLOW_SPEC_IB
static inline void ibv_flow_spec_ib_set_by_dst_gid(vma_ibv_flow_spec_ib* ib, uint8_t* dst_gid)
{
	ib->type = VMA_IBV_FLOW_SPEC_IB;
	ib->size = sizeof(vma_ibv_flow_spec_ib);
	if (dst_gid)
	{
		memcpy(ib->val.dst_gid, dst_gid, 16);
		memset(ib->mask.dst_gid, FS_MASK_ON_8, 16);
	}
}

static inline void ibv_flow_spec_ib_set_by_dst_qpn(vma_ibv_flow_spec_ib* ib, uint32_t dst_qpn)
{
	ib->type = VMA_IBV_FLOW_SPEC_IB;
	ib->size = sizeof(vma_ibv_flow_spec_ib);
	ib->val.qpn = dst_qpn;
	ib->mask.qpn = FS_MASK_ON_32;
}
#endif

static inline void ibv_flow_spec_eth_set(vma_ibv_flow_spec_eth* eth, uint8_t* dst_mac, uint16_t vlan_tag)
{
	eth->type = VMA_IBV_FLOW_SPEC_ETH;
	eth->size = sizeof(vma_ibv_flow_spec_eth);
	eth->val.ether_type = ntohs(ETH_P_IP);
	eth->mask.ether_type = FS_MASK_ON_16;
	memcpy(eth->val.dst_mac, dst_mac, ETH_ALEN);
	memset(eth->mask.dst_mac, FS_MASK_ON_8, ETH_ALEN);
	eth->val.vlan_tag =  vlan_tag & htons(VLAN_VID_MASK);
	eth->mask.vlan_tag = eth->val.vlan_tag ? htons(VLAN_VID_MASK) : 0; //we do not support vlan options
}

static inline void ibv_flow_spec_ipv4_set(vma_ibv_flow_spec_ipv4* ipv4, uint32_t dst_ip, uint32_t src_ip)
{
	ipv4->type = VMA_IBV_FLOW_SPEC_IPV4;
	ipv4->size = sizeof(vma_ibv_flow_spec_ipv4);
	ipv4->val.src_ip = src_ip;
	if (ipv4->val.src_ip) ipv4->mask.src_ip = FS_MASK_ON_32;
	ipv4->val.dst_ip = dst_ip;
	if (ipv4->val.dst_ip) ipv4->mask.dst_ip = FS_MASK_ON_32;
}

static inline void ibv_flow_spec_tcp_udp_set(vma_ibv_flow_spec_tcp_udp* tcp_udp, bool is_tcp, uint16_t dst_port, uint16_t src_port)
{
	tcp_udp->type = is_tcp ? VMA_IBV_FLOW_SPEC_TCP : VMA_IBV_FLOW_SPEC_UDP;
	tcp_udp->size = sizeof(vma_ibv_flow_spec_tcp_udp);
	tcp_udp->val.src_port = src_port;
	if(tcp_udp->val.src_port) tcp_udp->mask.src_port = FS_MASK_ON_16;
	tcp_udp->val.dst_port = dst_port;
	if(tcp_udp->val.dst_port) tcp_udp->mask.dst_port = FS_MASK_ON_16;
}

static inline void ibv_flow_spec_flow_tag_set(vma_ibv_flow_spec_action_tag* flow_tag, uint32_t tag_id)
{
	NOT_IN_USE(tag_id);
	if (flow_tag == NULL)
		return;
#ifdef DEFINED_IBV_FLOW_TAG
	flow_tag->type = VMA_IBV_FLOW_SPEC_ACTION_TAG;
	flow_tag->size = sizeof(vma_ibv_flow_spec_action_tag);
	flow_tag->tag_id = tag_id;
#endif //DEFINED_IBV_FLOW_TAG
}


static inline void ibv_source_qpn_set(vma_ibv_qp_init_attr& qp_init_attr, uint32_t source_qpn)
{
	NOT_IN_USE(qp_init_attr);
	NOT_IN_USE(source_qpn);

#ifdef DEFINED_IBV_QP_INIT_SOURCE_QPN
	if (source_qpn) {
		qp_init_attr.comp_mask |= VMA_IBV_QP_INIT_QPN_MASK;
		vma_ibv_qp_create_flags(qp_init_attr) |= VMA_IBV_QP_INIT_QPN_CREATE_FLAGS;
		vma_ibv_qp_source_qpn(qp_init_attr) = source_qpn;
	}
#endif /* DEFINED_IBV_QP_INIT_SOURCE_QPN */
}

#endif
