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


#include <errno.h>
#include <vlogger/vlogger.h>

#include "verbs_extra.h"

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
	case IBV_EVENT_QP_ACCESS_ERR:		return "QP_ACCESS_ERR";
	case IBV_EVENT_COMM_EST:		return "COMM_EST";
	case IBV_EVENT_SQ_DRAINED:		return "SQ_DRAINED";
	case IBV_EVENT_PATH_MIG:		return "PATH_MIG";
	case IBV_EVENT_PATH_MIG_ERR:		return "PATH_MIG_ERR";
	case IBV_EVENT_DEVICE_FATAL:		return "DEVICE_FATAL";
	case IBV_EVENT_PORT_ACTIVE:		return "PORT_ACTIVE";
	case IBV_EVENT_PORT_ERR:		return "PORT_ERR";
	case IBV_EVENT_LID_CHANGE:		return "LID_CHANGE";
	case IBV_EVENT_PKEY_CHANGE:		return "PKEY_CHANGE";
	case IBV_EVENT_SM_CHANGE:		return "SM_CHANGE";
	case IBV_EVENT_SRQ_ERR:			return "SRQ_ERR";
	case IBV_EVENT_SRQ_LIMIT_REACHED:	return "SRQ_LIMIT_REACHED";
	case IBV_EVENT_QP_LAST_WQE_REACHED:	return "QP_LAST_WQE_REACHED";
	case IBV_EVENT_CLIENT_REREGISTER:	return "CLIENT_REREGISTER";
	default:				break;
	}
	return "UNKNOWN";
	BULLSEYE_EXCLUDE_BLOCK_END
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
const char* priv_ibv_port_state_str(enum ibv_port_state state)
{
	switch (state) {
	case IBV_PORT_NOP:			return "PORT_NOP";
	case IBV_PORT_DOWN:			return "PORT_DOWN";
	case IBV_PORT_INIT:			return "PORT_INIT";
	case IBV_PORT_ARMED:			return "PORT_ARMED";
	case IBV_PORT_ACTIVE:			return "PORT_ACTIVE";
	case IBV_PORT_ACTIVE_DEFER:		return "PORT_ACTIVE_DEFER";
	default:				break;
	}
	return "PORT_STATE_UNKNOWN";
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

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
	struct ibv_qp_attr qp_attr;
	qp_attr.qp_state = IBV_QPS_ERR;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE)) {
		return -1;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_to_reset(struct ibv_qp *qp)
{
	struct ibv_qp_attr qp_attr;
	qp_attr.qp_state = IBV_QPS_RESET;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE)) {
		return -1;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END
	return 0;
}

int priv_ibv_modify_qp_from_err_to_init_raw(struct ibv_qp *qp, uint8_t port_num)
{
	struct ibv_qp_attr qp_attr;

	if (qp->qp_type != IBV_QPT_RAW_PACKET)
		return -1;

	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_RESET) {
		if (priv_ibv_modify_qp_to_reset(qp)) {
			return -2;
		}
	}

	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = port_num;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, (ibv_qp_attr_mask)(IBV_QP_STATE | IBV_QP_PORT))) {
		return -3;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_from_err_to_init_ud(struct ibv_qp *qp, uint8_t port_num, uint16_t pkey_index)
{
	struct ibv_qp_attr qp_attr;

	if (qp->qp_type != IBV_QPT_UD)
		return -1;

	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_RESET) {
		if (priv_ibv_modify_qp_to_reset(qp)) {
			return -2;
		}
	}

	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.qkey = IPOIB_QKEY;
	qp_attr.pkey_index = pkey_index;
	qp_attr.port_num = port_num;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_QKEY | IBV_QP_PKEY_INDEX | IBV_QP_PORT)) {
		return -3;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	return 0;
}

int priv_ibv_modify_qp_from_init_to_rts(struct ibv_qp *qp)
{
	if (priv_ibv_query_qp_state(qp) !=  IBV_QPS_INIT) {
		return -1;
	}

	struct ibv_qp_attr qp_attr;
	qp_attr.qp_state = IBV_QPS_RTR;
	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, (ibv_qp_attr_mask)IBV_QP_STATE)) {
		return -2;
	} ENDIF_VERBS_FAILURE;
	BULLSEYE_EXCLUDE_BLOCK_END

	qp_attr.qp_state = IBV_QPS_RTS;
	ibv_qp_attr_mask qp_attr_mask = (ibv_qp_attr_mask)IBV_QP_STATE;

	if (qp->qp_type == IBV_QPT_UD) {
		qp_attr_mask = (ibv_qp_attr_mask)(qp_attr_mask | IBV_QP_SQ_PSN);
		qp_attr.sq_psn = 0;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	IF_VERBS_FAILURE(ibv_modify_qp(qp, &qp_attr, qp_attr_mask)) {
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
	return (ibv_qp_state)qp_attr.qp_state;
}
