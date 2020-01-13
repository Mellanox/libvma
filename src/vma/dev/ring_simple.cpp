/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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


#include "ring_simple.h"

#include "vma/util/valgrind.h"
#include "vma/util/sg_array.h"
#include "vma/sock/fd_collection.h"
#if defined(DEFINED_DIRECT_VERBS)
#include "vma/dev/qp_mgr_eth_mlx5.h"
#endif

#undef  MODULE_NAME
#define MODULE_NAME "ring_simple"
#undef  MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define ALIGN_WR_DOWN(_num_wr_) (max(32, ((_num_wr_      ) & ~(0xf))))
#define RING_TX_BUFS_COMPENSATE 256

#define RING_LOCK_AND_RUN(__lock__, __func_and_params__) 	\
		__lock__.lock(); __func_and_params__; __lock__.unlock();

#define RING_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) \
		__lock__.lock(); ret = __func_and_params__; __lock__.unlock();

#define RING_TRY_LOCK_RUN_AND_UPDATE_RET(__lock__, __func_and_params__) \
		if (!__lock__.trylock()) { ret = __func_and_params__; __lock__.unlock(); } \
		else { errno = EAGAIN; }

/**/
/** inlining functions can only help if they are implemented before their usage **/
/**/

inline void ring_simple::send_status_handler(int ret, vma_ibv_send_wr* p_send_wqe)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (unlikely(ret)) {
		// Error during post_send, reclaim the tx buffer
		if(p_send_wqe) {
			mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
			mem_buf_tx_release(p_mem_buf_desc, true);
		}
	}
	else {
		// Update TX statistics
		sg_array sga(p_send_wqe->sg_list, p_send_wqe->num_sge);
		m_p_ring_stat->n_tx_byte_count += sga.length();
		++m_p_ring_stat->n_tx_pkt_count;

		// Decrease counter in order to keep track of how many missing buffers we have when
		// doing ring->restart() and then drain_tx_buffers_to_buffer_pool()
		m_missing_buf_ref_count--;
	}
	BULLSEYE_EXCLUDE_BLOCK_END
}

qp_mgr* ring_eth::create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel)
{
#if defined(DEFINED_DIRECT_VERBS)
	if (qp_mgr::is_lib_mlx5(((ib_ctx_handler*)ib_ctx)->get_ibname())) {
		return new qp_mgr_eth_mlx5(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), m_partition);
	}
#endif
	return new qp_mgr_eth(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), m_partition);
}

qp_mgr* ring_ib::create_qp_mgr(const ib_ctx_handler* ib_ctx, uint8_t port_num, struct ibv_comp_channel* p_rx_comp_event_channel)
{
	return new qp_mgr_ib(this, ib_ctx, port_num, p_rx_comp_event_channel, get_tx_num_wr(), m_partition);
}

ring_simple::ring_simple(int if_index, ring* parent, ring_type_t type):
	ring_slave(if_index, parent, type),
	m_p_ib_ctx(NULL),
	m_p_qp_mgr(NULL),
	m_p_cq_mgr_rx(NULL),
	m_p_cq_mgr_tx(NULL),
	m_lock_ring_tx_buf_wait("ring:lock_tx_buf_wait"), m_tx_num_bufs(0), m_tx_num_wr(0), m_tx_num_wr_free(0),
	m_b_qp_tx_first_flushed_completion_handled(false), m_missing_buf_ref_count(0),
	m_tx_lkey(0),
	m_gro_mgr(safe_mce_sys().gro_streams_max, MAX_GRO_BUFS), m_up(false),
	m_p_rx_comp_event_channel(NULL), m_p_tx_comp_event_channel(NULL), m_p_l2_addr(NULL)
{
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	const slave_data_t * p_slave = p_ndev->get_slave(get_if_index());

	ring_logdbg("new ring_simple()");

	/* m_p_ib_ctx, m_tx_lkey should be initialized to be used
	 * in ring_eth_direct, ring_eth_cb constructors
	 */
	BULLSEYE_EXCLUDE_BLOCK_START
	m_p_ib_ctx = p_slave->p_ib_ctx;
	if(m_p_ib_ctx == NULL) {
		ring_logpanic("m_p_ib_ctx = NULL. It can be related to wrong bonding configuration");
	}

	m_tx_lkey = g_buffer_pool_tx->find_lkey_by_ib_ctx_thread_safe(m_p_ib_ctx);
	if (m_tx_lkey == 0) {
		__log_info_panic("invalid lkey found %lu", m_tx_lkey);
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	/* initialization basing on ndev information */
	m_mtu = p_ndev->get_mtu();

	memset(&m_cq_moderation_info, 0, sizeof(m_cq_moderation_info));
#ifdef DEFINED_TSO
	memset(&m_tso, 0, sizeof(m_tso));
#endif /* DEFINED_TSO */

	m_socketxtreme.active = safe_mce_sys().enable_socketxtreme;
	INIT_LIST_HEAD(&m_socketxtreme.ec_list);
	m_socketxtreme.completion = NULL;
}

ring_simple::~ring_simple()
{
	ring_logdbg("delete ring_simple()");

	// Go over all hash and for each flow: 1.Detach from qp 2.Delete related rfs object 3.Remove flow from hash
	m_lock_ring_rx.lock();
	flow_udp_del_all();
	flow_tcp_del_all();
	m_lock_ring_rx.unlock();

	// Allow last few post sends to be sent by HCA.
	// Was done in order to allow iperf's FIN packet to be sent.
	usleep(25000);

        /* coverity[double_lock] TODO: RM#1049980 */
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();

	if (m_p_qp_mgr) {
		// 'down' the active QP/CQ
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->down();

		// Release QP/CQ resources
		delete m_p_qp_mgr;
		m_p_qp_mgr = NULL;
	}

	delete_l2_address();

	// Delete the rx channel fd from the global fd collection
	if (g_p_fd_collection) {
		if (m_p_rx_comp_event_channel) {
			g_p_fd_collection->del_cq_channel_fd(m_p_rx_comp_event_channel->fd, true);
		}
		if (m_p_tx_comp_event_channel) {
			g_p_fd_collection->del_cq_channel_fd(m_p_tx_comp_event_channel->fd, true);
		}
	}

	if (m_p_rx_comp_event_channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_rx_comp_event_channel)) {
			ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
	}

	delete[] m_p_n_rx_channel_fds;

	ring_logdbg("Tx buffer poll: free count = %u, sender_has = %d, total = %d, %s (%d)",
			m_tx_pool.size(), m_missing_buf_ref_count, m_tx_num_bufs,
			((m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count) ?
					"bad accounting!!" : "good accounting"),
					(m_tx_num_bufs - m_tx_pool.size() - m_missing_buf_ref_count));
	ring_logdbg("Tx WR num: free count = %d, total = %d, %s (%d)",
			m_tx_num_wr_free, m_tx_num_wr,
			((m_tx_num_wr - m_tx_num_wr_free) ? "bad accounting!!":"good accounting"), (m_tx_num_wr - m_tx_num_wr_free));
	ring_logdbg("Rx buffer pool: %d free global buffers available", m_tx_pool.size());

	// Release verbs resources
	if (m_p_tx_comp_event_channel) {
		IF_VERBS_FAILURE(ibv_destroy_comp_channel(m_p_tx_comp_event_channel)) {
			ring_logdbg("destroy comp channel failed (errno=%d %m)", errno);
		} ENDIF_VERBS_FAILURE;
		VALGRIND_MAKE_MEM_UNDEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
		m_p_tx_comp_event_channel = NULL;
	}

	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_ring_rx.unlock();
	m_lock_ring_tx.unlock();

	ring_logdbg("queue of event completion elements is %s",
			(list_empty(&m_socketxtreme.ec_list) ? "empty" : "not empty"));
	while (!list_empty(&m_socketxtreme.ec_list)) {
		struct ring_ec *ec = NULL;
		ec = get_ec();
		if (ec) {
			del_ec(ec);
		}
	}

	ring_logdbg("delete ring_simple() completed");
}

void ring_simple::create_resources()
{
	net_device_val* p_ndev = g_p_net_device_table_mgr->get_net_device_val(m_parent->get_if_index());
	const slave_data_t * p_slave = p_ndev->get_slave(get_if_index());

	save_l2_address(p_slave->p_L2_addr);
	m_p_tx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context());
	if (m_p_tx_comp_event_channel == NULL) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "ibv_create_comp_channel for tx failed. m_p_tx_comp_event_channel = %p (errno=%d %m)", m_p_tx_comp_event_channel, errno);
		if (errno == EMFILE) {
			VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "did we run out of file descriptors? traffic may not be offloaded, increase ulimit -n");
		}
		throw_vma_exception("create event channel failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(m_p_tx_comp_event_channel, sizeof(struct ibv_comp_channel));
	// Check device capabilities for max QP work requests
	uint32_t max_qp_wr = ALIGN_WR_DOWN(m_p_ib_ctx->get_ibv_device_attr()->max_qp_wr - 1);
	m_tx_num_wr = safe_mce_sys().tx_num_wr;
	if (m_tx_num_wr > max_qp_wr) {
		ring_logwarn("Allocating only %d Tx QP work requests while user requested %s=%d for QP on interface %d.%d.%d.%d",
			max_qp_wr, SYS_VAR_TX_NUM_WRE, m_tx_num_wr);
		m_tx_num_wr = max_qp_wr;
	}
	ring_logdbg("ring attributes: m_tx_num_wr = %d", m_tx_num_wr);

	m_tx_num_wr_free = m_tx_num_wr;

#ifdef DEFINED_TSO
	memset(&m_tso, 0, sizeof(m_tso));
	if (safe_mce_sys().enable_tso && (1 == validate_tso(get_if_index()))) {
		if (vma_check_dev_attr_tso(m_p_ib_ctx->get_ibv_device_attr())) {
			const vma_ibv_tso_caps *caps = &vma_get_tso_caps(m_p_ib_ctx->get_ibv_device_attr_ex());
			if (ibv_is_qpt_supported(caps->supported_qpts, IBV_QPT_RAW_PACKET) ||
				ibv_is_qpt_supported(caps->supported_qpts, IBV_QPT_UD)) {
				m_tso.max_payload_sz = caps->max_tso;
				/* ETH(14) + IP(20) + TCP(20) + TCP OPTIONS(40) */
				m_tso.max_header_sz = 94;
			}
		}
	}
	ring_logdbg("ring attributes: m_tso = %d", is_tso());
	ring_logdbg("ring attributes: m_tso:max_payload_sz = %d", get_max_payload_sz());
	ring_logdbg("ring attributes: m_tso:max_header_sz = %d", get_max_header_sz());
#endif /* DEFINED_TSO */

	m_flow_tag_enabled = m_p_ib_ctx->get_flow_tag_capability();
	ring_logdbg("ring attributes: m_flow_tag_enabled = %d", m_flow_tag_enabled);

	m_p_rx_comp_event_channel = ibv_create_comp_channel(m_p_ib_ctx->get_ibv_context()); // ODED TODO: Adjust the ibv_context to be the exact one in case of different devices
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_rx_comp_event_channel == NULL) {
		VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "ibv_create_comp_channel for rx failed. p_rx_comp_event_channel = %p (errno=%d %m)", m_p_rx_comp_event_channel, errno);
		if (errno == EMFILE) {
			VLOG_PRINTF_INFO_ONCE_THEN_ALWAYS(VLOG_ERROR, VLOG_DEBUG, "did we run out of file descriptors? traffic may not be offloaded, increase ulimit -n");
		}
		throw_vma_exception("create event channel failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	VALGRIND_MAKE_MEM_DEFINED(m_p_rx_comp_event_channel, sizeof(struct ibv_comp_channel));
	m_p_n_rx_channel_fds = new int[1];
	m_p_n_rx_channel_fds[0] = m_p_rx_comp_event_channel->fd;
	// Add the rx channel fd to the global fd collection
	if (g_p_fd_collection) {
		// Create new cq_channel info in the global fd collection
		g_p_fd_collection->add_cq_channel_fd(m_p_n_rx_channel_fds[0], this);
		g_p_fd_collection->add_cq_channel_fd(m_p_tx_comp_event_channel->fd, this);
	}

	m_p_qp_mgr = create_qp_mgr(m_p_ib_ctx, p_slave->port_num, m_p_rx_comp_event_channel);
	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_p_qp_mgr == NULL) {
		ring_logerr("Failed to allocate qp_mgr!");
		throw_vma_exception("create qp failed");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	// save cq_mgr pointers
	m_p_cq_mgr_rx = m_p_qp_mgr->get_rx_cq_mgr();
	m_p_cq_mgr_tx = m_p_qp_mgr->get_tx_cq_mgr();

	init_tx_buffers(RING_TX_BUFS_COMPENSATE);

	if (safe_mce_sys().cq_moderation_enable) {
		modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
	}

	if (p_slave->active) {
		// 'up' the active QP/CQ resource
		m_up = true;
		m_p_qp_mgr->up();
	}

	ring_logdbg("new ring_simple() completed");
}

int ring_simple::request_notification(cq_type_t cq_type, uint64_t poll_sn)
{
	int ret = 1;
	if (likely(CQT_RX == cq_type)) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
				m_p_cq_mgr_rx->request_notification(poll_sn);
				++m_p_ring_stat->simple.n_rx_interrupt_requests);
	} else {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_tx, m_p_cq_mgr_tx->request_notification(poll_sn));
	}

	return ret;
}

int ring_simple::ack_and_arm_cq(cq_type_t cq_type)
{
	if (CQT_RX == cq_type) {
		return m_p_cq_mgr_rx->ack_and_request_notification();
	}
	return m_p_cq_mgr_tx->ack_and_request_notification();
}

int ring_simple::poll_and_process_element_rx(uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->poll_and_process_element_rx(p_cq_poll_sn, pv_fd_ready_array));
	return ret;
}

int ring_simple::socketxtreme_poll(struct vma_completion_t *vma_completions, unsigned int ncompletions, int flags)
{
	int ret = 0;
	int i = 0;

	NOT_IN_USE(flags);

	if (likely(vma_completions) && ncompletions) {
		struct ring_ec *ec = NULL;

		m_socketxtreme.completion = vma_completions;

		while (!g_b_exit && (i < (int)ncompletions)) {
			m_socketxtreme.completion->events = 0;
			/* Check list size to avoid locking */
			if (!list_empty(&m_socketxtreme.ec_list)) {
				ec = get_ec();
				if (ec) {
					memcpy(m_socketxtreme.completion, &ec->completion, sizeof(ec->completion));
					ec->clear();
					m_socketxtreme.completion++;
					i++;
				}
			} else {
				/* Internal thread can raise event on this stage before we
				 * start rx processing. In this case we can return event
				 * in right order. It is done to avoid locking and
				 * may be it is not so critical
				 */
				mem_buf_desc_t *desc;
				if (likely(m_p_cq_mgr_rx->poll_and_process_element_rx(&desc))) {
					desc->rx.socketxtreme_polled = true;
					rx_process_buffer(desc, NULL);
					if (m_socketxtreme.completion->events) {
						m_socketxtreme.completion++;
						i++;
					}
				} else {
					break;
				}
			}
		}

		m_socketxtreme.completion = NULL;

		ret = i;
	}
	else {
		ret = -1;
		errno = EINVAL;
	}

	return ret;
}

int ring_simple::wait_for_notification_and_process_element(int cq_channel_fd, uint64_t* p_cq_poll_sn, void* pv_fd_ready_array /*NULL*/)
{
	int ret = -1;
	if (m_p_cq_mgr_rx != NULL) {
		RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx,
				m_p_cq_mgr_rx->wait_for_notification_and_process_element(p_cq_poll_sn, pv_fd_ready_array);
		++m_p_ring_stat->simple.n_rx_interrupt_received);
	} else {
		ring_logerr("Can't find rx_cq for the rx_comp_event_channel_fd (= %d)", cq_channel_fd);
	}

	return ret;
}

bool ring_simple::reclaim_recv_buffers(descq_t *rx_reuse)
{
	bool ret = false;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse));
	return ret;
}

bool ring_simple::reclaim_recv_buffers(mem_buf_desc_t* rx_reuse_lst)
{
	bool ret = false;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->reclaim_recv_buffers(rx_reuse_lst));
	return ret;
}

bool ring_simple::reclaim_recv_buffers_no_lock(mem_buf_desc_t* rx_reuse_lst)
{
	return m_p_cq_mgr_rx->reclaim_recv_buffers_no_lock(rx_reuse_lst);
}

int ring_simple::reclaim_recv_single_buffer(mem_buf_desc_t* rx_reuse)
{
	return m_p_cq_mgr_rx->reclaim_recv_single_buffer(rx_reuse);
}

void ring_simple::mem_buf_desc_completion_with_error_rx(mem_buf_desc_t* p_rx_wc_buf_desc)
{
	m_p_cq_mgr_rx->mem_buf_desc_completion_with_error(p_rx_wc_buf_desc);
}

void ring_simple::mem_buf_desc_completion_with_error_tx(mem_buf_desc_t* p_tx_wc_buf_desc)
{
	if (m_b_qp_tx_first_flushed_completion_handled) {
		p_tx_wc_buf_desc->p_next_desc = NULL; // All wr are flushed so we need to disconnect the Tx list
	}
	else {
		m_b_qp_tx_first_flushed_completion_handled = true; // This is true for all wr except for the first one which might point to already sent wr
	}
	m_tx_num_wr_free += mem_buf_tx_release(p_tx_wc_buf_desc, false, false);
}

void ring_simple::mem_buf_desc_return_to_owner_rx(mem_buf_desc_t* p_mem_buf_desc, void* pv_fd_ready_array /*NULL*/)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_rx, m_p_cq_mgr_rx->mem_buf_desc_return_to_owner(p_mem_buf_desc, pv_fd_ready_array));
}

void ring_simple::mem_buf_desc_return_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, m_tx_num_wr_free += put_tx_buffers(p_mem_buf_desc));
}

void ring_simple::mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t* p_mem_buf_desc)
{
	ring_logfuncall("");
	RING_LOCK_AND_RUN(m_lock_ring_tx, put_tx_single_buffer(p_mem_buf_desc));
}

int ring_simple::drain_and_proccess()
{
	int ret = 0;
	RING_TRY_LOCK_RUN_AND_UPDATE_RET(m_lock_ring_rx, m_p_cq_mgr_rx->drain_and_proccess());
	return ret;
}

mem_buf_desc_t* ring_simple::mem_buf_tx_get(ring_user_id_t id, bool b_block, int n_num_mem_bufs /* default = 1 */)
{
	NOT_IN_USE(id);
	int ret = 0;
	mem_buf_desc_t* buff_list = NULL;
	uint64_t poll_sn = 0;

	ring_logfuncall("n_num_mem_bufs=%d", n_num_mem_bufs);

	m_lock_ring_tx.lock();
	buff_list = get_tx_buffers(n_num_mem_bufs);
	while (!buff_list) {

		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, ret);
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			return NULL;
		}
		else if (ret > 0) {
			ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
			buff_list = get_tx_buffers(n_num_mem_bufs);
		}
		else if (b_block) { // (ret == 0)
			// Arm & Block on tx cq_mgr notification channel
			// until we get a few freed tx mem_buf_desc & data buffers

			// Only a single thread should block on next Tx cqe event, hence the dedicated lock!
			/* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();

			// poll once more (in the hope that we get a few freed tx mem_buf_desc)
			buff_list = get_tx_buffers(n_num_mem_bufs);
			if (!buff_list) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_p_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					/* coverity[double_unlock] coverity[unlock] TODO: RM#1049980 */
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, 100);
					if (ret == 0) {
						m_lock_ring_tx_buf_wait.unlock();
						/* coverity[double_lock] TODO: RM#1049980 */
						m_lock_ring_tx.lock();
						buff_list = get_tx_buffers(n_num_mem_bufs);
						continue;
					} else if (ret < 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						return NULL;
					}
					/* coverity[double_lock] TODO: RM#1049980 */
					m_lock_ring_tx.lock();

					// Find the correct Tx cq_mgr from the CQ event,
					// It might not be the active_cq object since we have a single TX CQ comp channel for all cq_mgr's
					cq_mgr* p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
					if (p_cq_mgr_tx) {

						// Allow additional CQ arming now
						p_cq_mgr_tx->m_b_notification_armed = false;

						// Perform a non blocking event read, clear the fd channel
						ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
						if (ret < 0) {
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
							/* coverity[double_unlock] TODO: RM#1049980 */
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							return NULL;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
				buff_list = get_tx_buffers(n_num_mem_bufs);
			}
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();
		}
		else {
			// get out on non blocked socket
			m_lock_ring_tx.unlock();
			return NULL;
		}
	}

	// We got the buffers
	// Increase counter in order to keep track of how many buffers ring is missing when reclaiming them during ring->restart()
	m_missing_buf_ref_count += n_num_mem_bufs;

	/* coverity[double_unlock] TODO: RM#1049980 */
	m_lock_ring_tx.unlock();
	return buff_list;
}

int ring_simple::mem_buf_tx_release(mem_buf_desc_t* p_mem_buf_desc_list, bool b_accounting, bool trylock/*=false*/)
{
	ring_logfuncall("");

	if (!trylock)
		m_lock_ring_tx.lock();
	else if (m_lock_ring_tx.trylock())
		return 0;

	int accounting = put_tx_buffers(p_mem_buf_desc_list);
	if (b_accounting)
		m_missing_buf_ref_count -= accounting;
	m_lock_ring_tx.unlock();
	return accounting;
}

/* note that this function is inline, so keep it above the functions using it */
inline int ring_simple::send_buffer(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	//Note: this is debatable logic as it count of WQEs waiting completion but
	//our SQ is cyclic buffer so in reality only last WQE is still being sent
	//and other SQ is mostly free to work on.
	int ret = 0;
	if (likely(m_tx_num_wr_free > 0)) {
		ret = m_p_qp_mgr->send(p_send_wqe, attr);
		--m_tx_num_wr_free;
	} else if (is_available_qp_wr(is_set(attr, VMA_TX_PACKET_BLOCK))) {
		ret = m_p_qp_mgr->send(p_send_wqe, attr);
	} else {
		ring_logdbg("silent packet drop, no available WR in QP!");
		ret = -1;
		if(p_send_wqe) {
			mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
			p_mem_buf_desc->p_next_desc = NULL;
		}
	}
	return ret;
}

bool ring_simple::get_hw_dummy_send_support(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe)
{
	NOT_IN_USE(id);
	NOT_IN_USE(p_send_wqe);

	return m_p_qp_mgr->get_hw_dummy_send_support();
}

void ring_simple::send_ring_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);

#ifdef DEFINED_SW_CSUM
	{
#else
	if (attr & VMA_TX_SW_CSUM) {
#endif
		compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);
		attr = (vma_wr_tx_packet_attr) (attr & ~(VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM));
	}

	auto_unlocker lock(m_lock_ring_tx);
#ifdef DEFINED_TSO
#else
	p_send_wqe->sg_list[0].lkey = m_tx_lkey;
#endif /* DEFINED_TSO */
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

void ring_simple::send_lwip_buffer(ring_user_id_t id, vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr)
{
	NOT_IN_USE(id);

#ifdef DEFINED_SW_CSUM
	compute_tx_checksum((mem_buf_desc_t*)(p_send_wqe->wr_id), attr & VMA_TX_PACKET_L3_CSUM, attr & VMA_TX_PACKET_L4_CSUM);
	attr = (vma_wr_tx_packet_attr) (attr & ~(VMA_TX_PACKET_L3_CSUM | VMA_TX_PACKET_L4_CSUM));
#endif

	auto_unlocker lock(m_lock_ring_tx);
#ifdef DEFINED_TSO
#else
	p_send_wqe->sg_list[0].lkey = m_tx_lkey;
	mem_buf_desc_t* p_mem_buf_desc = (mem_buf_desc_t*)(p_send_wqe->wr_id);
	p_mem_buf_desc->lwip_pbuf.pbuf.ref++;
#endif /* DEFINED_TSO */
	int ret = send_buffer(p_send_wqe, attr);
	send_status_handler(ret, p_send_wqe);
}

/*
 * called under m_lock_ring_tx lock
 */
bool ring_simple::is_available_qp_wr(bool b_block)
{
	int ret = 0;
	uint64_t poll_sn = 0;

	while (m_tx_num_wr_free <= 0) {
		// Try to poll once in the hope that we get a few freed tx mem_buf_desc
		ret = m_p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
		if (ret < 0) {
			ring_logdbg("failed polling on tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (ret=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, ret);
			/* coverity[missing_unlock] */
			return false;
		} else if (ret > 0) {
			ring_logfunc("polling succeeded on tx cq_mgr (%d wce)", ret);
		} else if (b_block){
			// Arm & Block on tx cq_mgr notification channel
			// until we get a few freed tx mem_buf_desc & data buffers

			// Only a single thread should block on next Tx cqe event, hence the dedicated lock!
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.lock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();

			if (m_tx_num_wr_free <= 0) {
				// Arm the CQ event channel for next Tx buffer release (tx cqe)
				ret = m_p_cq_mgr_tx->request_notification(poll_sn);
				if (ret < 0) {
					// this is most likely due to cq_poll_sn out of sync, need to poll_cq again
					ring_logdbg("failed arming tx cq_mgr (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
				}
				else if (ret == 0) {

					// prepare to block
					// CQ is armed, block on the CQ's Tx event channel (fd)
					struct pollfd poll_fd = { /*.fd=*/ 0, /*.events=*/ POLLIN, /*.revents=*/ 0};
					poll_fd.fd = get_tx_comp_event_channel()->fd;

					// Now it is time to release the ring lock (for restart events to be handled while this thread block on CQ channel)
					/* coverity[double_unlock] TODO: RM#1049980 */
					m_lock_ring_tx.unlock();

					ret = orig_os_api.poll(&poll_fd, 1, -1);
					if (ret <= 0) {
						ring_logdbg("failed blocking on tx cq_mgr (errno=%d %m)", errno);
						m_lock_ring_tx_buf_wait.unlock();
						/* coverity[double_lock] TODO: RM#1049980 */
						m_lock_ring_tx.lock();
						/* coverity[missing_unlock] */
						return false;
					}
					/* coverity[double_lock] TODO: RM#1049980 */
					m_lock_ring_tx.lock();

					// Find the correct Tx cq_mgr from the CQ event,
					// It might not be the active_cq object since we have a single TX CQ comp channel for all cq_mgr's
					cq_mgr* p_cq_mgr_tx = get_cq_mgr_from_cq_event(get_tx_comp_event_channel());
					if (p_cq_mgr_tx) {

						// Allow additional CQ arming now
						p_cq_mgr_tx->m_b_notification_armed = false;

						// Perform a non blocking event read, clear the fd channel
						ret = p_cq_mgr_tx->poll_and_process_element_tx(&poll_sn);
						if (ret < 0) {
							ring_logdbg("failed handling Tx cq_mgr channel (qp_mgr=%p, cq_mgr_tx=%p) (errno=%d %m)", m_p_qp_mgr, m_p_cq_mgr_tx, errno);
							/* coverity[double_unlock] TODO: RM#1049980 */
							m_lock_ring_tx.unlock();
							m_lock_ring_tx_buf_wait.unlock();
							/* coverity[double_lock] TODO: RM#1049980 */
							m_lock_ring_tx.lock();
							return false;
						}
						ring_logfunc("polling/blocking succeeded on tx cq_mgr (we got %d wce)", ret);
					}
				}
			}
			/* coverity[double_unlock] TODO: RM#1049980 */
			m_lock_ring_tx.unlock();
			m_lock_ring_tx_buf_wait.unlock();
			/* coverity[double_lock] TODO: RM#1049980 */
			m_lock_ring_tx.lock();
		} else {
			return false;
		}
	}

	--m_tx_num_wr_free;
	return true;
}

void ring_simple::init_tx_buffers(uint32_t count)
{
	request_more_tx_buffers(count, m_tx_lkey);
	m_tx_num_bufs = m_tx_pool.size();
}

void ring_simple::inc_cq_moderation_stats(size_t sz_data)
{
	m_cq_moderation_info.bytes += sz_data;
	++m_cq_moderation_info.packets;
}

//call under m_lock_ring_tx lock
mem_buf_desc_t* ring_simple::get_tx_buffers(uint32_t n_num_mem_bufs)
{
	mem_buf_desc_t* head = NULL;
	if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
		int count = MAX(RING_TX_BUFS_COMPENSATE, n_num_mem_bufs);
		if (request_more_tx_buffers(count, m_tx_lkey)) {
			m_tx_num_bufs += count;
		}

		if (unlikely(m_tx_pool.size() < n_num_mem_bufs)) {
			return head;
		}
	}

	head = m_tx_pool.get_and_pop_back();
	head->lwip_pbuf.pbuf.ref = 1;
	n_num_mem_bufs--;

	mem_buf_desc_t* next = head;
	while (n_num_mem_bufs) {
		next->p_next_desc = m_tx_pool.get_and_pop_back();
		next = next->p_next_desc;
		next->lwip_pbuf.pbuf.ref = 1;
		n_num_mem_bufs--;
	}

	return head;
}

void ring_simple::return_to_global_pool()
{
	if (unlikely(m_tx_pool.size() > (m_tx_num_bufs / 2) &&  m_tx_num_bufs >= RING_TX_BUFS_COMPENSATE * 2)) {
		int return_bufs = m_tx_pool.size() / 2;
		m_tx_num_bufs -= return_bufs;
		g_buffer_pool_tx->put_buffers_thread_safe(&m_tx_pool, return_bufs);
	}
}

//call under m_lock_ring_tx lock
int ring_simple::put_tx_buffers(mem_buf_desc_t* buff_list)
{
	int count = 0, freed=0;
	mem_buf_desc_t *next;

	while (buff_list) {
		next = buff_list->p_next_desc;
		buff_list->p_next_desc = NULL;

		if (buff_list->tx.dev_mem_length)
			m_p_qp_mgr->dm_release_data(buff_list);

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff_list->lwip_pbuf.pbuf.ref))
			buff_list->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", buff_list);

		if (buff_list->lwip_pbuf.pbuf.ref == 0) {
			free_lwip_pbuf(&buff_list->lwip_pbuf);
			m_tx_pool.push_back(buff_list);
			freed++;
		}
		count++;
		buff_list = next;
	}
	ring_logfunc("buf_list: %p count: %d freed: %d\n", buff_list, count, freed);

	return_to_global_pool();

	return count;
}

//call under m_lock_ring_tx lock
int ring_simple::put_tx_single_buffer(mem_buf_desc_t* buff)
{
	int count = 0;

	if (likely(buff)) {

		if (buff->tx.dev_mem_length)
			m_p_qp_mgr->dm_release_data(buff);

		//potential race, ref is protected here by ring_tx lock, and in dst_entry_tcp & sockinfo_tcp by tcp lock
		if (likely(buff->lwip_pbuf.pbuf.ref))
			buff->lwip_pbuf.pbuf.ref--;
		else
			ring_logerr("ref count of %p is already zero, double free??", buff);

		if (buff->lwip_pbuf.pbuf.ref == 0) {
			buff->p_next_desc = NULL;
			free_lwip_pbuf(&buff->lwip_pbuf);
			m_tx_pool.push_back(buff);
			count++;
		}
	}

	return_to_global_pool();

	return count;
}

void ring_simple::modify_cq_moderation(uint32_t period, uint32_t count)
{
	uint32_t period_diff = period > m_cq_moderation_info.period ?
			period - m_cq_moderation_info.period : m_cq_moderation_info.period - period;
	uint32_t count_diff = count > m_cq_moderation_info.count ?
			count - m_cq_moderation_info.count : m_cq_moderation_info.count - count;

	if (period_diff < (m_cq_moderation_info.period / 20) && (count_diff < m_cq_moderation_info.count / 20))
		return;

	m_cq_moderation_info.period = period;
	m_cq_moderation_info.count = count;

	m_p_ring_stat->simple.n_rx_cq_moderation_period = period;
	m_p_ring_stat->simple.n_rx_cq_moderation_count = count;

	//todo all cqs or just active? what about HA?
	priv_ibv_modify_cq_moderation(m_p_cq_mgr_rx->get_ibv_cq_hndl(), period, count);
}

void ring_simple::adapt_cq_moderation()
{
	if (m_lock_ring_rx.trylock()) {
		++m_cq_moderation_info.missed_rounds;
		return; //todo try again sooner?
	}

	uint32_t missed_rounds = m_cq_moderation_info.missed_rounds;

	//todo collect bytes and packets from all rings ??
	int64_t interval_bytes = m_cq_moderation_info.bytes - m_cq_moderation_info.prev_bytes;
	int64_t interval_packets = m_cq_moderation_info.packets - m_cq_moderation_info.prev_packets;

	m_cq_moderation_info.prev_bytes = m_cq_moderation_info.bytes;
	m_cq_moderation_info.prev_packets = m_cq_moderation_info.packets;
	m_cq_moderation_info.missed_rounds = 0;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (interval_bytes < 0 || interval_packets < 0) {
		//rare wrap-around of 64 bit, just ignore
		m_lock_ring_rx.unlock();
		return;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (interval_packets == 0) {
		// todo if no traffic, set moderation to default?
		modify_cq_moderation(safe_mce_sys().cq_moderation_period_usec, safe_mce_sys().cq_moderation_count);
		m_lock_ring_rx.unlock();
		return;
	}

	uint32_t avg_packet_size = interval_bytes / interval_packets;
	uint32_t avg_packet_rate = (interval_packets * 1000) / (safe_mce_sys().cq_aim_interval_msec * (1 + missed_rounds));

	uint32_t ir_rate = safe_mce_sys().cq_aim_interrupts_rate_per_sec;

	int count = MIN(avg_packet_rate / ir_rate, safe_mce_sys().cq_aim_max_count);
	int period = MIN(safe_mce_sys().cq_aim_max_period_usec, ((1000000 / ir_rate) - (1000000 / MAX(avg_packet_rate, ir_rate))));

	if (avg_packet_size < 1024 && avg_packet_rate < 450000) {
		modify_cq_moderation(0, 0); //latency mode
		//todo latency for big messages is not good
		// the rate is affected by the moderation and the moderation by the rate..
		// so each cycle change from 0 to max, and max to 0, ..
	} else {
		modify_cq_moderation(period, count); //throughput mode
	}

	m_lock_ring_rx.unlock();
}

void ring_simple::start_active_qp_mgr() {
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();
	if (!m_up) {
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->up();
		m_b_qp_tx_first_flushed_completion_handled = false;
		m_up = true;
	}
	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();
}

void ring_simple::stop_active_qp_mgr() {
	m_lock_ring_rx.lock();
	m_lock_ring_tx.lock();
	if (m_up) {
		m_up = false;
		/* TODO: consider avoid using sleep */
		/* coverity[sleep] */
		m_p_qp_mgr->down();
	}
	m_lock_ring_tx.unlock();
	m_lock_ring_rx.unlock();
}

bool ring_simple::is_up() {
	return m_up;
}

int ring_simple::modify_ratelimit(struct vma_rate_limit_t &rate_limit)
{
	if (!m_p_ib_ctx->is_packet_pacing_supported(rate_limit.rate)) {
		ring_logwarn("Packet pacing is not supported for this device");
		return -1;
	}

	if ((rate_limit.max_burst_sz || rate_limit.typical_pkt_sz) && !m_p_ib_ctx->get_burst_capability()) {
		ring_logwarn("Burst is not supported for this device");
		return -1;
	}

	uint32_t rl_changes = m_p_qp_mgr->is_ratelimit_change(rate_limit);

	if (m_up && rl_changes)
		return m_p_qp_mgr->modify_qp_ratelimit(rate_limit, rl_changes);

	return 0;
}

int ring_simple::get_ring_descriptors(vma_mlx_hw_device_data &d)
{
	d.dev_data.vendor_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_id;
	d.dev_data.vendor_part_id = m_p_ib_ctx->get_ibv_device_attr()->vendor_part_id;
	if (m_p_ib_ctx->is_packet_pacing_supported()) {
		d.dev_data.device_cap |= VMA_HW_PP_EN;
	}
	if (m_p_ib_ctx->get_burst_capability()) {
		d.dev_data.device_cap |= VMA_HW_PP_BURST_EN;
	}
	if (vma_is_umr_supported(m_p_ib_ctx->get_ibv_device_attr())) {
		d.dev_data.device_cap |= VMA_HW_UMR_EN;
	}
	if (vma_is_mp_rq_supported(m_p_ib_ctx->get_ibv_device_attr())) {
		d.dev_data.device_cap |= VMA_HW_MP_RQ_EN;
	}
	d.valid_mask = DATA_VALID_DEV;

	ring_logdbg("found device with Vendor-ID %u, ID %u, Device cap %u", d.dev_data.vendor_part_id,
		    d.dev_data.vendor_id, d.dev_data.device_cap);
	if (!m_p_qp_mgr->fill_hw_descriptors(d)) {
		return -1;
	}
	if (m_p_cq_mgr_rx->fill_cq_hw_descriptors(d.rq_data.wq_data.cq_data)) {
		d.valid_mask |= DATA_VALID_RQ;
	}

	if (m_p_cq_mgr_tx->fill_cq_hw_descriptors(d.sq_data.wq_data.cq_data)) {
		d.valid_mask |= DATA_VALID_SQ;
	}
	VALGRIND_MAKE_MEM_DEFINED(&d, sizeof(d));
	return 0;
}

uint32_t ring_simple::get_max_inline_data()
{
	return m_p_qp_mgr->get_max_inline_data();
}

#ifdef DEFINED_TSO
uint32_t ring_simple::get_max_send_sge(void)
{
	return m_p_qp_mgr->get_max_send_sge();
}

uint32_t ring_simple::get_max_payload_sz(void)
{
	return m_tso.max_payload_sz;
}

uint16_t ring_simple::get_max_header_sz(void)
{
	return m_tso.max_header_sz;
}

bool ring_simple::is_tso(void)
{
	return (m_tso.max_payload_sz && m_tso.max_header_sz);
}
#endif /* DEFINED_TSO */
