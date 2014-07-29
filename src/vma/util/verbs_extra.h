/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


#ifndef VERBS_EXTRA_H
#define VERBS_EXTRA_H

#include <rdma/rdma_cma.h>
#include <config.h>
#include <infiniband/verbs.h>
#ifndef DEFINED_IBV_OLD_VERBS_MLX_OFED
#include <infiniband/verbs_exp.h>
#endif
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#ifndef DEFINED_IBV_WC_WITH_VLAN
//#warning probaly you are trying to compile on OFED which doesnt support VLAN for RAW QP.
//#error when you see this then you need to manually open the below comment and to comment the current and the previous lines.
//#define IBV_WC_WITH_VLAN		1 << 3
#endif

// Wrapper for all IBVERBS & RDMA_CM API to normalize the return code and errno value
// With these marco all ibverbs & rdma_cm failures are caugth and errno is updated
// Without this marco ibverbs & rdma_cm returns sometimes with -1 and sometimes with -errno
#define IF_VERBS_FAILURE(__func__)		\
        { int __ret__;				\
	if ((__ret__ = (__func__)) < -1) { 	\
		errno = -__ret__;	       	\
	}					\
	if (__ret__)

#define ENDIF_VERBS_FAILURE			}


#define IF_RDMACM_FAILURE(__func__)		IF_VERBS_FAILURE(__func__)
#define ENDIF_RDMACM_FAILURE			ENDIF_VERBS_FAILURE
#define IPOIB_QKEY 0x0b1b

// See - IB Arch Spec - 11.6.2 COMPLETION RETURN STATUS
const char* priv_ibv_wc_status_str(enum ibv_wc_status status);

// See - IB Arch Spec - 11.6.3 ASYNCHRONOUS EVENTS
const char* priv_ibv_event_desc_str(enum ibv_event_type type);

const char* priv_ibv_port_state_str(enum ibv_port_state state);

#define priv_rdma_cm_event_type_str(__rdma_cm_ev_t__)	\
				rdma_event_str(__rdma_cm_ev_t__)

// Find pkey_index from the ibv_context + port_num + pkey
int priv_ibv_find_pkey_index(struct ibv_context *verbs, uint8_t port_num, uint16_t pkey, uint16_t *pkey_index);

int priv_ibv_modify_qp_to_err(struct ibv_qp *qp);
int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num);
int priv_ibv_modify_qp_from_err_to_init_ud(struct ibv_qp *qp, uint8_t port_num, uint16_t pkey_index);
int priv_ibv_modify_qp_from_init_to_rts(struct ibv_qp *qp);

// Return 'ibv_qp_state' of the ibv_qp
int priv_ibv_query_qp_state(struct ibv_qp *qp);


#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK      0xFFF	/* define vlan range: 1-4095. taken from <linux/if_vlan.h> */
#endif

#define FS_MASK_ON_8      (0xff)
#define FS_MASK_ON_16     (0xffff)
#define FS_MASK_ON_32     (0xffffffff)

//old MLNX_OFED verbs (2.1 and older)
#ifdef DEFINED_IBV_OLD_VERBS_MLX_OFED
//ibv_post_send
#define VMA_IBV_SEND_SIGNALED			IBV_SEND_SIGNALED
#define VMA_IBV_SEND_INLINE			IBV_SEND_INLINE
#define VMA_IBV_SEND_IP_CSUM			IBV_SEND_IP_CSUM
#define vma_ibv_send_flags			ibv_send_flags
#define vma_send_wr_send_flags(wr)		(wr).send_flags
#define VMA_IBV_WR_SEND				IBV_WR_SEND
#define vma_send_wr_opcode(wr)			(wr).opcode
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
#else //new MLNX_OFED verbs (2.2 and newer)
//ibv_post_send
#define VMA_IBV_SEND_SIGNALED			IBV_EXP_SEND_SIGNALED
#define VMA_IBV_SEND_INLINE			IBV_EXP_SEND_INLINE
#define VMA_IBV_SEND_IP_CSUM			IBV_EXP_SEND_IP_CSUM
#define vma_ibv_send_flags			ibv_exp_send_flags
#define vma_send_wr_send_flags(wr)		(wr).exp_send_flags
#define VMA_IBV_WR_SEND				IBV_EXP_WR_SEND
#define vma_send_wr_opcode(wr)			(wr).exp_opcode
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
#endif

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

#endif
