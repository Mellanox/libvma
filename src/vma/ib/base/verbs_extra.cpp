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


#include "vma/ib/base/verbs_extra.h"

#include <errno.h>
#include <vlogger/vlogger.h>

#include "vma_extra.h"
#include "vma/util/valgrind.h"

#undef  MODULE_NAME
#define MODULE_NAME 		"verbs_extra:"

// See - IB Arch Spec - 11.6.2 COMPLETION RETURN STATUS
const char* priv_ibv_wc_status_str(enum ibv_wc_status status)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	switch (status) {
	case IBV_WC_SUCCESS: 			return "IBV_WC_SUCCESS";
	case IBV_WC_LOC_LEN_ERR:		return "IBV_WC_LOC_LEN_ERR";
	case IBV_WC_LOC_QP_OP_ERR:		return "IBV_WC_LOC_QP_OP_ERR";
	case IBV_WC_LOC_EEC_OP_ERR: 		return "IBV_WC_LOC_EEC_OP_ERR";
	case IBV_WC_LOC_PROT_ERR:		return "IBV_WC_LOC_PROT_ERR";
	case IBV_WC_WR_FLUSH_ERR:		return "IBV_WC_WR_FLUSH_ERR";
	case IBV_WC_MW_BIND_ERR:		return "IBV_WC_MW_BIND_ERR";
	case IBV_WC_BAD_RESP_ERR:		return "IBV_WC_BAD_RESP_ERR";
	case IBV_WC_LOC_ACCESS_ERR:		return "IBV_WC_LOC_ACCESS_ERR";
	case IBV_WC_REM_INV_REQ_ERR:		return "IBV_WC_REM_INV_REQ_ERR";
	case IBV_WC_REM_ACCESS_ERR:		return "IBV_WC_REM_ACCESS_ERR";
	case IBV_WC_REM_OP_ERR:			return "IBV_WC_REM_OP_ERR";
	case IBV_WC_RETRY_EXC_ERR:		return "IBV_WC_RETRY_EXC_ERR";
	case IBV_WC_RNR_RETRY_EXC_ERR:		return "IBV_WC_RNR_RETRY_EXC_ERR";
	case IBV_WC_LOC_RDD_VIOL_ERR:		return "IBV_WC_LOC_RDD_VIOL_ERR";
	case IBV_WC_REM_INV_RD_REQ_ERR:		return "IBV_WC_REM_INV_RD_REQ_ERR";
	case IBV_WC_REM_ABORT_ERR:		return "IBV_WC_REM_ABORT_ERR";
	case IBV_WC_INV_EECN_ERR:		return "IBV_WC_INV_EECN_ERR";
	case IBV_WC_INV_EEC_STATE_ERR:		return "IBV_WC_INV_EEC_STATE_ERR";
	case IBV_WC_FATAL_ERR:			return "IBV_WC_FATAL_ERR";
	case IBV_WC_RESP_TIMEOUT_ERR:		return "IBV_WC_RESP_TIMEOUT_ERR";
	case IBV_WC_GENERAL_ERR:		return "IBV_WC_GENERAL_ERR";
	default:				break;
	}
	return "IBV_WC_UNKNOWN";
	BULLSEYE_EXCLUDE_BLOCK_END
}

// See - IB Arch Spec - 11.6.3 ASYNCHRONOUS EVENTS
const char* priv_ibv_event_desc_str(enum ibv_event_type type)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	switch (type) {
	case IBV_EVENT_CQ_ERR:			return "CQ_ERR";
	case IBV_EVENT_QP_FATAL:		return "QP_FATAL";
	case IBV_EVENT_QP_REQ_ERR:		return "QP_REQ_ERR";
	case IBV_EVENT_QP_ACCESS_ERR:	return "QP_ACCESS_ERR";
	case IBV_EVENT_COMM_EST:		return "COMM_EST";
	case IBV_EVENT_SQ_DRAINED:		return "SQ_DRAINED";
	case IBV_EVENT_PATH_MIG:		return "PATH_MIG";
	case IBV_EVENT_PATH_MIG_ERR:	return "PATH_MIG_ERR";
	case IBV_EVENT_DEVICE_FATAL:	return "DEVICE_FATAL";
	case IBV_EVENT_PORT_ACTIVE:		return "PORT_ACTIVE";
	case IBV_EVENT_PORT_ERR:		return "PORT_ERR";
	case IBV_EVENT_LID_CHANGE:		return "LID_CHANGE";
	case IBV_EVENT_PKEY_CHANGE:		return "PKEY_CHANGE";
	case IBV_EVENT_SM_CHANGE:		return "SM_CHANGE";
	case IBV_EVENT_SRQ_ERR:			return "SRQ_ERR";
	case IBV_EVENT_SRQ_LIMIT_REACHED:	return "SRQ_LIMIT_REACHED";
	case IBV_EVENT_QP_LAST_WQE_REACHED:	return "QP_LAST_WQE_REACHED";
	case IBV_EVENT_CLIENT_REREGISTER:	return "CLIENT_REREGISTER";
	case IBV_EVENT_GID_CHANGE:		return "GID_CHANGE";
	default:				break;
	}
	return "UNKNOWN";
	BULLSEYE_EXCLUDE_BLOCK_END
}

int priv_ibv_find_pkey_index(struct ibv_context *verbs, uint8_t port_num, uint16_t pkey, uint16_t *pkey_index)
{
	int ret, i;
	uint16_t chk_pkey = 0;
	for (i = 0, ret = 0; !ret; i++) {
		ret = ibv_query_pkey(verbs, port_num, i, &chk_pkey);
		if (!ret && pkey == chk_pkey) {
			*pkey_index = (uint16_t)i;
			return 0;
		}
	}
	return -1;
}

int priv_ibv_modify_qp_to_err(struct ibv_qp *qp)
{
	vma_ibv_qp_attr qp_attr;
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_ERR;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE_EX(vma_ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE), EIO) {
		return -1;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_to_reset(struct ibv_qp *qp)
{
	vma_ibv_qp_attr qp_attr;
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RESET;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE)) {
		return -1;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END
	return 0;
}

int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num)
{
	vma_ibv_qp_attr qp_attr;

	if (qp->qp_type != IBV_QPT_RAW_PACKET)
		return -1;

	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_RESET) {
		if (priv_ibv_modify_qp_to_reset(qp)) {
			return -2;
		}
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = port_num;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp(qp, &qp_attr, (ibv_qp_attr_mask)(IBV_QP_STATE | IBV_QP_PORT))) {
		return -3;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_from_err_to_init_ud(struct ibv_qp *qp, uint8_t port_num, uint16_t pkey_index, uint32_t underly_qpn)
{
	vma_ibv_qp_attr qp_attr;
	ibv_qp_attr_mask qp_attr_mask = (ibv_qp_attr_mask)IBV_QP_STATE;

	if (qp->qp_type != IBV_QPT_UD)
		return -1;

	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_RESET) {
		if (priv_ibv_modify_qp_to_reset(qp)) {
			return -2;
		}
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_INIT;
	if (0 == underly_qpn) {
		qp_attr_mask = (ibv_qp_attr_mask)(qp_attr_mask | IBV_QP_QKEY | IBV_QP_PKEY_INDEX | IBV_QP_PORT);
		qp_attr.qkey = IPOIB_QKEY;
		qp_attr.pkey_index = pkey_index;
		qp_attr.port_num = port_num;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp(qp, &qp_attr, qp_attr_mask)) {
		return -3;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_from_init_to_rts(struct ibv_qp *qp, uint32_t underly_qpn)
{
	vma_ibv_qp_attr qp_attr;
	ibv_qp_attr_mask qp_attr_mask = (ibv_qp_attr_mask)IBV_QP_STATE;

	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_INIT) {
		return -1;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IBV_QPS_RTR;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp(qp, &qp_attr, qp_attr_mask)) {
		return -2;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	qp_attr.qp_state = IBV_QPS_RTS;

	if ((qp->qp_type == IBV_QPT_UD) && (0 == underly_qpn)) {
		qp_attr_mask = (ibv_qp_attr_mask)(qp_attr_mask | IBV_QP_SQ_PSN);
		qp_attr.sq_psn = 0;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp(qp, &qp_attr, qp_attr_mask)) {
		return -3;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

// Return 'ibv_qp_state' of the ibv_qp
int priv_ibv_query_qp_state(struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	struct ibv_qp_init_attr qp_init_attr;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_query_qp(qp, &qp_attr, IBV_QP_STATE, &qp_init_attr)) {
		return -1;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(&qp_attr, sizeof(qp_attr));
	return (ibv_qp_state)qp_attr.qp_state;
}

int priv_ibv_query_burst_supported(struct ibv_qp *qp, uint8_t port_num)
{
#ifdef	DEFINED_IBV_QP_SUPPORT_BURST
	if (priv_ibv_modify_qp_from_err_to_init_raw(qp, port_num) == 0) {
		if (priv_ibv_modify_qp_from_init_to_rts(qp, 0) == 0) {
			struct vma_rate_limit_t rate = {1000, 100, 100};
			if (priv_ibv_modify_qp_ratelimit(qp, rate, RL_RATE | RL_BURST_SIZE | RL_PKT_SIZE) == 0){
				return 0;
			}
		}
	}

#else
	NOT_IN_USE(qp);
	NOT_IN_USE(port_num);
#endif

	return -1;
}

int priv_ibv_query_flow_tag_supported(struct ibv_qp *qp, uint8_t port_num)
{
	NOT_IN_USE(qp);
	NOT_IN_USE(port_num);
	int res = -1;

#ifdef DEFINED_IBV_FLOW_TAG

	// Create
	struct {
		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_eth         eth;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;
		vma_ibv_flow_spec_action_tag  flow_tag;
	} ft_attr;

	// Initialize
	memset(&ft_attr, 0, sizeof(ft_attr));
	ft_attr.attr.size = sizeof(ft_attr);
	ft_attr.attr.num_of_specs = 4;
	ft_attr.attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
	ft_attr.attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
	ft_attr.attr.port = port_num;

	// Set filters
	uint8_t mac_0[ETH_ALEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t mac_f[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	ibv_flow_spec_eth_set(&ft_attr.eth, mac_0 , 0); // L2 filter
	memcpy(ft_attr.eth.val.src_mac, mac_f, ETH_ALEN);
	memset(ft_attr.eth.mask.src_mac, FS_MASK_ON_8, ETH_ALEN);

	ibv_flow_spec_ipv4_set(&ft_attr.ipv4, INADDR_LOOPBACK, INADDR_LOOPBACK); // L3 filter
	ibv_flow_spec_tcp_udp_set(&ft_attr.tcp_udp, true, 0, 0); // L4 filter
	ibv_flow_spec_flow_tag_set(&ft_attr.flow_tag, FLOW_TAG_MASK-1); // enable flow tag

	// Create flow
	vma_ibv_flow *ibv_flow = vma_ibv_create_flow(qp, &ft_attr.attr);
	if (ibv_flow) {
		res = 0;
		vma_ibv_destroy_flow(ibv_flow);
	}
#endif // DEFINED_IBV_FLOW_TAG

	return res;
}

int priv_ibv_create_flow_supported(struct ibv_qp *qp, uint8_t port_num)
{
	int res = -1;

	struct {
		vma_ibv_flow_attr             attr;
		vma_ibv_flow_spec_ipv4        ipv4;
		vma_ibv_flow_spec_tcp_udp     tcp_udp;
	} cf_attr;

	// Initialize
	memset(&cf_attr, 0, sizeof(cf_attr));
	cf_attr.attr.size = sizeof(cf_attr);
	cf_attr.attr.num_of_specs = 2;
	cf_attr.attr.type = VMA_IBV_FLOW_ATTR_NORMAL;
	cf_attr.attr.priority = 1; // almost highest priority, 0 is used for 5-tuple later
	cf_attr.attr.port = port_num;

	ibv_flow_spec_ipv4_set(&cf_attr.ipv4, INADDR_LOOPBACK, INADDR_LOOPBACK); // L3 filter
	ibv_flow_spec_tcp_udp_set(&cf_attr.tcp_udp, true, 0, 0); // L4 filter

	// Create flow
	vma_ibv_flow *ibv_flow = vma_ibv_create_flow(qp, &cf_attr.attr);
	if (ibv_flow) {
		res = 0;
		vma_ibv_destroy_flow(ibv_flow);
	}

	return res;
}

int vma_rdma_lib_reset() {
#ifdef HAVE_RDMA_LIB_RESET
	vlog_printf(VLOG_DEBUG, "rdma_lib_reset called\n");
	return rdma_lib_reset();
#else
	vlog_printf(VLOG_DEBUG, "rdma_lib_reset doesn't exist returning 0\n");
	return 0;
#endif
}

// be advised that this method will change packet pacing value and also change state to RTS
int priv_ibv_modify_qp_ratelimit(struct ibv_qp *qp, struct vma_rate_limit_t &rate_limit, uint32_t rl_changes)
{
#ifdef DEFINED_IBV_PACKET_PACING_CAPS
	vma_ibv_rate_limit_attr qp_attr;
	uint64_t attr_mask = IBV_QP_STATE;

	if (priv_ibv_query_qp_state(qp) != IBV_QPS_RTS) {
		vlog_printf(VLOG_DEBUG, "failed querying QP\n");
		return -1;
	}
	memset(&qp_attr, 0, sizeof(qp_attr));
	vma_ibv_init_qps_attr(qp_attr);

	if (rate_limit.rate && (rl_changes & RL_RATE)) {
		qp_attr.rate_limit = rate_limit.rate;
		attr_mask |= VMA_IBV_QP_RATE_LIMIT;
	}
#ifdef DEFINED_IBV_QP_SUPPORT_BURST
	if (rate_limit.max_burst_sz && rate_limit.typical_pkt_sz && (rl_changes & (RL_BURST_SIZE | RL_PKT_SIZE))) {
		vma_ibv_init_burst_attr(qp_attr, rate_limit);
	}
#endif
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(vma_ibv_modify_qp_rate_limit(qp, &qp_attr, attr_mask)) {
		vlog_printf(VLOG_DEBUG, "failed setting rate limit\n");
		return -2;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END
#ifdef DEFINED_IBV_QP_SUPPORT_BURST
	vlog_printf(VLOG_DEBUG, "qp was set to rate limit %d, burst size %d, packet size %d\n",
			rate_limit.rate, rate_limit.max_burst_sz, rate_limit.typical_pkt_sz);
#else
	vlog_printf(VLOG_DEBUG, "qp was set to rate limit %d\n", rate_limit.rate);
#endif
	return 0;
#else
	vlog_printf(VLOG_DEBUG, "rate limit not supported\n");
	NOT_IN_USE(qp);
	NOT_IN_USE(rate_limit);
	NOT_IN_USE(rl_changes);
	return 0;
#endif // DEFINED_IBV_PACKET_PACING_CAPS
}

void priv_ibv_modify_cq_moderation(struct ibv_cq* cq, uint32_t period, uint32_t count)
{
#ifdef DEFINED_IBV_CQ_ATTR_MODERATE
	vma_ibv_cq_attr cq_attr;
	memset(&cq_attr, 0, sizeof(cq_attr));
	vma_cq_attr_mask(cq_attr) = VMA_IBV_CQ_MODERATION;
	vma_cq_attr_moderation(cq_attr).cq_count = count;
	vma_cq_attr_moderation(cq_attr).cq_period = period;

	vlog_printf(VLOG_FUNC, "modify cq moderation, period=%d, count=%d\n", period, count);

	IF_VERBS_FAILURE_EX(vma_ibv_modify_cq(cq, &cq_attr, VMA_IBV_CQ_MODERATION), EIO) {
		vlog_printf(VLOG_DEBUG, "Failure modifying cq moderation (errno=%d %m)\n", errno);
	} ENDIF_VERBS_FAILURE;
#else
	NOT_IN_USE(cq);
	NOT_IN_USE(count);
	NOT_IN_USE(period);
#endif
}

