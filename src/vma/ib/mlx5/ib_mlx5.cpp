/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "util/valgrind.h"
#include "vma/util/valgrind.h"
#include "vma/util/utils.h"
#include "vma/ib/mlx5/ib_mlx5.h"

int vma_ib_mlx5_get_qp(struct ibv_qp *qp, vma_ib_mlx5_qp_t *mlx5_qp, uint32_t flags)
{
	int ret = 0;
	struct mlx5dv_obj obj;
	struct mlx5dv_qp dqp;
	enum ibv_qp_attr_mask attr_mask = IBV_QP_CAP;
	struct ibv_qp_attr tmp_ibv_qp_attr;
	struct ibv_qp_init_attr tmp_ibv_qp_init_attr;

	memset(&obj, 0, sizeof(obj));
	memset(&dqp, 0, sizeof(dqp));

	obj.qp.in = qp;
	obj.qp.out = &dqp;
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_QP);
	if (ret != 0) {
		goto out;
	}
	VALGRIND_MAKE_MEM_DEFINED(&dqp, sizeof(dqp));
	mlx5_qp->qp           = qp;
	mlx5_qp->qpn          = qp->qp_num;
	mlx5_qp->flags        = flags;
	mlx5_qp->sq.dbrec     = &dqp.dbrec[MLX5_SND_DBR];
	mlx5_qp->sq.buf       = dqp.sq.buf;
	mlx5_qp->sq.wqe_cnt   = dqp.sq.wqe_cnt;
	mlx5_qp->sq.stride    = dqp.sq.stride;
	mlx5_qp->rq.dbrec     = &dqp.dbrec[MLX5_RCV_DBR];
	mlx5_qp->rq.buf       = dqp.rq.buf;
	mlx5_qp->rq.wqe_cnt   = dqp.rq.wqe_cnt;
	mlx5_qp->rq.stride    = dqp.rq.stride;
	mlx5_qp->rq.wqe_shift = ilog_2(dqp.rq.stride);
	mlx5_qp->rq.head      = 0;
	mlx5_qp->rq.tail      = 0;
	mlx5_qp->bf.reg       = dqp.bf.reg;
	mlx5_qp->bf.size      = dqp.bf.size;
	mlx5_qp->bf.offset    = 0;

	ret = ibv_query_qp(qp, &tmp_ibv_qp_attr, attr_mask, &tmp_ibv_qp_init_attr);
	if (ret != 0) {
		goto out;
	}

	VALGRIND_MAKE_MEM_DEFINED(&tmp_ibv_qp_attr, sizeof(tmp_ibv_qp_attr));
	mlx5_qp->cap.max_send_wr = tmp_ibv_qp_attr.cap.max_send_wr;
	mlx5_qp->cap.max_recv_wr = tmp_ibv_qp_attr.cap.max_recv_wr;
	mlx5_qp->cap.max_send_sge = tmp_ibv_qp_attr.cap.max_send_sge;
	mlx5_qp->cap.max_recv_sge = tmp_ibv_qp_attr.cap.max_recv_sge;
	mlx5_qp->cap.max_inline_data = tmp_ibv_qp_attr.cap.max_inline_data;

out:
    return ret;
}

int vma_ib_mlx5_get_cq(struct ibv_cq *cq, vma_ib_mlx5_cq_t *mlx5_cq)
{
	int ret = 0;
	struct mlx5dv_obj obj;
	struct mlx5dv_cq dcq;

	/* Initialization of cq can be done once to protect
	 * internal data from corruption.
	 * cq field is used to detect one time initialization
	 * For example: this function can be called when QP is moved
	 * from ERROR state to RESET so cq_ci or cq_sn should not be
	 * updated
	 */
	if (mlx5_cq == NULL || mlx5_cq->cq == cq) {
		return 0;
	}

	memset(&obj, 0, sizeof(obj));
	memset(&dcq, 0, sizeof(dcq));

	obj.cq.in = cq;
	obj.cq.out = &dcq;
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_CQ);
	if (ret != 0) {
		return ret;
	}
	VALGRIND_MAKE_MEM_DEFINED(&dcq, sizeof(dcq));
	mlx5_cq->cq           = cq;
	mlx5_cq->cq_num       = dcq.cqn;
	mlx5_cq->cq_ci        = 0;
	mlx5_cq->cq_sn        = 0;
	mlx5_cq->cqe_count    = dcq.cqe_cnt;
	mlx5_cq->cqe_size     = dcq.cqe_size;
	mlx5_cq->cqe_size_log = ilog_2(dcq.cqe_size);
	mlx5_cq->dbrec        = dcq.dbrec;
	mlx5_cq->uar          = dcq.cq_uar;

	/* Move buffer forward for 128b CQE, so we would get pointer to the 2nd
	 * 64b when polling.
	 */
	mlx5_cq->cq_buf       = (uint8_t *)dcq.buf + dcq.cqe_size - sizeof(struct mlx5_cqe64);

    return 0;
}

int vma_ib_mlx5_post_recv(vma_ib_mlx5_qp_t *mlx5_qp,
		struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
	struct mlx5_wqe_data_seg *scat;
	int err = 0;
	int nreq;
	int ind;
	int i, j;

	ind = mlx5_qp->rq.head & (mlx5_qp->rq.wqe_cnt - 1);
	*bad_wr = NULL;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (unlikely((int)mlx5_qp->rq.head - (int)mlx5_qp->rq.tail + nreq >= (int)mlx5_qp->cap.max_recv_wr)) {
			errno = ENOMEM;
			err = -errno;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > (int)mlx5_qp->cap.max_recv_sge)) {
			errno = EINVAL;
			err = -errno;
			*bad_wr = wr;
			goto out;
		}

		scat = (struct mlx5_wqe_data_seg *)((uint8_t *)mlx5_qp->rq.buf + (ind << mlx5_qp->rq.wqe_shift));

		for (i = 0, j = 0; i < wr->num_sge; ++i) {
			if (unlikely(!wr->sg_list[i].length)) continue;

			scat[j].byte_count = htonl(wr->sg_list[i].length);
			scat[j].lkey       = htonl(wr->sg_list[i].lkey);
			scat[j].addr       = htonll(wr->sg_list[i].addr);
			j++;
		}

		if (j < (int)mlx5_qp->cap.max_recv_sge) {
			scat[j].byte_count = 0;
			scat[j].lkey       = htonl(MLX5_INVALID_LKEY);
			scat[j].addr       = 0;
		}

		ind = (ind + 1) & (mlx5_qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		mlx5_qp->rq.head += nreq;

		/*
		 * Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		/*
		 * For Raw Packet QP, avoid updating the doorbell record
		 * as long as the QP isn't in RTR state, to avoid receiving
		 * packets in illegal states.
		 * This is only for Raw Packet QPs since they are represented
		 * differently in the hardware.
		 */
		if (likely(!((mlx5_qp->qp->qp_type == IBV_QPT_RAW_PACKET ||
				mlx5_qp->flags & VMA_IB_MLX5_QP_FLAGS_USE_UNDERLAY) &&
				mlx5_qp->qp->state < IBV_QPS_RTR)))
			*mlx5_qp->rq.dbrec = htonl(mlx5_qp->rq.head & 0xffff);
	}

	return err;
}

int vma_ib_mlx5_req_notify_cq(vma_ib_mlx5_cq_t *mlx5_cq, int solicited)
{
	uint64_t doorbell;
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	sn  = mlx5_cq->cq_sn & 3;
	ci  = mlx5_cq->cq_ci & 0xffffff;
	cmd = solicited ? MLX5_CQ_DB_REQ_NOT_SOL : MLX5_CQ_DB_REQ_NOT;

	doorbell = sn << 28 | cmd | ci;
	doorbell <<= 32;
	doorbell |= mlx5_cq->cq_num;

	mlx5_cq->dbrec[VMA_IB_MLX5_CQ_ARM_DB] = htonl(sn << 28 | cmd | ci);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI WC MMIO.
	 */
	wmb();

	*(uint64_t *)((uint8_t *)mlx5_cq->uar + MLX5_CQ_DOORBELL) = htonll(doorbell);

	wc_wmb();

	return 0;
}

void vma_ib_mlx5_get_cq_event(vma_ib_mlx5_cq_t *mlx5_cq, int count)
{
	mlx5_cq->cq_sn += count;
}
