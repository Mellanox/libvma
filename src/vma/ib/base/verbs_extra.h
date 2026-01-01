/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef VERBS_EXTRA_H
#define VERBS_EXTRA_H

#include <rdma/rdma_cma.h>
#include <config.h>
#include <infiniband/verbs.h>
#include "vma/util/vtypes.h"
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "vma/ib/mlx5/ib_mlx5.h"

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

// See - IB Arch Spec - 11.6.2 COMPLETION RETURN STATUS
const char* priv_ibv_wc_status_str(enum ibv_wc_status status);

// See - IB Arch Spec - 11.6.3 ASYNCHRONOUS EVENTS
const char* priv_ibv_event_desc_str(enum ibv_event_type type);

int priv_ibv_modify_qp_to_err(struct ibv_qp *qp);
int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num);
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

//ibv_create_qp
#ifdef DEFINED_IBV_QP_INIT_SOURCE_QPN
#define vma_ibv_create_qp(pd, attr)                ibv_create_qp_ex((pd)->context, attr)
typedef struct ibv_qp_init_attr_ex                 vma_ibv_qp_init_attr;
#define vma_ibv_qp_init_attr_comp_mask(_pd, _attr) { (_attr).pd = _pd; (_attr).comp_mask |= IBV_QP_INIT_ATTR_PD; }
#else
#define vma_ibv_create_qp(pd, attr)                 ibv_create_qp(pd, attr)
typedef struct ibv_qp_init_attr                     vma_ibv_qp_init_attr;
#define vma_ibv_qp_init_attr_comp_mask(_pd, _attr)  { NOT_IN_USE(_pd); NOT_IN_USE(_attr); }
#endif

//ibv_query_device
#ifdef DEFINED_IBV_DEVICE_ATTR_EX
#define vma_ibv_query_device(context, attr)   ibv_query_device_ex(context, NULL, attr)
typedef struct ibv_device_attr_ex             vma_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) &device_attr->orig_attr
#else
#define vma_ibv_query_device(context, attr)   ibv_query_device(context, attr)
typedef ibv_device_attr                   	  vma_ibv_device_attr_ex;
#define vma_get_device_orig_attr(device_attr) device_attr
#endif

//ibv_poll_cq
#define vma_wc_flags(wc)			(wc).wc_flags
#define vma_wc_opcode(wc)			(wc).opcode

//csum offload
#ifdef DEFINED_IBV_DEVICE_RAW_IP_CSUM
#define vma_is_rx_hw_csum_supported(attr)	((attr)->device_cap_flags & (IBV_DEVICE_RAW_IP_CSUM | IBV_DEVICE_UD_IP_CSUM))
#define vma_wc_rx_hw_csum_ok(wc)		(vma_wc_flags(wc) & IBV_WC_IP_CSUM_OK)
#else
#define vma_is_rx_hw_csum_supported(attr)	0
#define vma_wc_rx_hw_csum_ok(wc)		(1)
#endif

#ifdef DEFINED_IBV_CQ_TIMESTAMP
#define vma_get_ts_val(values)                values.raw_clock.tv_nsec
#endif

//ibv_post_send
#ifndef DEFINED_IBV_SEND_IP_CSUM
	#define DEFINED_SW_CSUM
#endif

#define vma_send_wr_send_flags(wr)		(wr).send_flags
#define vma_send_wr_opcode(wr)			(wr).opcode

// Dummy send
#ifdef DEFINED_IBV_WR_NOP
#define vma_is_nop_supported(device_attr)    1
#define VMA_IBV_WR_NOP                       (ibv_wr_opcode)MLX5_OPCODE_NOP
#else
#define vma_is_nop_supported(device_attr)    0
#define VMA_IBV_WR_NOP                       (ibv_wr_opcode)(0) // Use 0 as "default" opcode when NOP is not defined.
#endif

typedef struct ibv_flow      vma_ibv_flow;
typedef struct ibv_flow_attr vma_ibv_flow_attr;

// Flow tag
#ifdef DEFINED_IBV_FLOW_TAG
typedef struct ibv_flow_spec_action_tag            vma_ibv_flow_spec_action_tag;
#define vma_get_flow_tag(cqe)                      ntohl((uint32_t)(cqe->sop_drop_qpn))
#else
typedef struct ibv_flow_spec_action_tag_dummy {}   vma_ibv_flow_spec_action_tag;
#define vma_get_flow_tag(cqe)                      0
#endif // DEFINED_IBV_FLOW_TAG

#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
#define vma_cq_attr_mask(cq_attr)               (cq_attr).attr_mask
#define vma_cq_attr_moderation(cq_attr)         (cq_attr).moderate
#endif

// ibv_dm
#ifdef DEFINED_IBV_DM
#define vma_ibv_reg_dm_mr(mr)            ibv_reg_dm_mr((mr)->pd, (mr)->dm, 0, (mr)->length, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_ZERO_BASED)
#define vma_ibv_memcpy_dm(dm, attr)      ibv_memcpy_to_dm(dm, (attr)->dm_offset, (attr)->host_addr, (attr)->length)
#define vma_ibv_init_memcpy_dm(attr, src, head, size)          { attr.host_addr = src; attr.dm_offset = head; attr.length = size; }
#define vma_ibv_init_dm_mr(in_mr, ctx_pd, size, allocated_dm)  { in_mr.pd = ctx_pd; in_mr.length = size; in_mr.dm = allocated_dm; }
typedef struct {
	void * host_addr;
	uint64_t dm_offset;
	size_t length;
} vma_ibv_memcpy_dm_attr;
typedef struct {
	struct ibv_pd *pd;
	size_t        length;
	ibv_dm        *dm;
} vma_ibv_reg_mr_in;
#endif

#ifdef DEFINED_IBV_PACKET_PACING_CAPS
#define vma_is_pacing_caps_supported(attr)   (attr->packet_pacing_caps.qp_rate_limit_min)

#ifdef DEFINED_IBV_QP_SUPPORT_BURST
#define vma_ibv_init_burst_attr(qp_attr, rate_limit)    { qp_attr.max_burst_sz = rate_limit.max_burst_sz; qp_attr.typical_pkt_sz = rate_limit.typical_pkt_sz; }
typedef struct ibv_qp_rate_limit_attr                   vma_ibv_rate_limit_attr;
#define vma_ibv_modify_qp_rate_limit(qp, attr, mask)    ibv_modify_qp_rate_limit(qp, attr)
#define vma_ibv_init_qps_attr(qp_attr)                  { NOT_IN_USE(qp_attr); }
#else
typedef ibv_qp_attr                                     vma_ibv_rate_limit_attr;
#define vma_ibv_modify_qp_rate_limit(qp, attr, mask)    ibv_modify_qp(qp, attr, mask)
#define vma_ibv_init_qps_attr(qp_attr)                  { qp_attr.qp_state = IBV_QPS_RTS; }
#endif // DEFINED_IBV_QP_SUPPORT_BURST

#endif // DEFINED_IBV_PACKET_PACING_CAPS

// ibv_dm
#ifdef DEFINED_IBV_DM
#define vma_ibv_dm_size(attr)			((attr)->max_dm_size)
#else
#define vma_ibv_dm_size(attr)			(0)
#endif

typedef enum {
	RL_RATE = 1<<0,
	RL_BURST_SIZE = 1<<1,
	RL_PKT_SIZE = 1<<2,
} vma_rl_changed;

int vma_rdma_lib_reset();

static inline void ibv_flow_spec_eth_set(ibv_flow_spec_eth* eth, uint8_t* dst_mac, uint16_t vlan_tag)
{
	eth->type = IBV_FLOW_SPEC_ETH;
	eth->size = sizeof(ibv_flow_spec_eth);
	eth->val.ether_type = ntohs(ETH_P_IP);
	eth->mask.ether_type = FS_MASK_ON_16;
	memcpy(eth->val.dst_mac, dst_mac, ETH_ALEN);
	memset(eth->mask.dst_mac, FS_MASK_ON_8, ETH_ALEN);
	eth->val.vlan_tag =  vlan_tag & htons(VLAN_VID_MASK);
	eth->mask.vlan_tag = eth->val.vlan_tag ? htons(VLAN_VID_MASK) : 0; //we do not support vlan options
}

static inline void ibv_flow_spec_ipv4_set(ibv_flow_spec_ipv4* ipv4, uint32_t dst_ip, uint32_t src_ip)
{
	ipv4->type = IBV_FLOW_SPEC_IPV4;
	ipv4->size = sizeof(ibv_flow_spec_ipv4);
	ipv4->val.src_ip = src_ip;
	if (ipv4->val.src_ip) ipv4->mask.src_ip = FS_MASK_ON_32;
	ipv4->val.dst_ip = dst_ip;
	if (ipv4->val.dst_ip) ipv4->mask.dst_ip = FS_MASK_ON_32;
}

static inline void ibv_flow_spec_tcp_udp_set(ibv_flow_spec_tcp_udp* tcp_udp, bool is_tcp, uint16_t dst_port, uint16_t src_port)
{
	tcp_udp->type = is_tcp ? IBV_FLOW_SPEC_TCP : IBV_FLOW_SPEC_UDP;
	tcp_udp->size = sizeof(ibv_flow_spec_tcp_udp);
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
	flow_tag->type = IBV_FLOW_SPEC_ACTION_TAG;
	flow_tag->size = sizeof(vma_ibv_flow_spec_action_tag);
	flow_tag->tag_id = tag_id;
#endif //DEFINED_IBV_FLOW_TAG
}

#endif
