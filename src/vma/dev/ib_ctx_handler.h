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


#ifndef IB_CTX_HANDLER_H
#define IB_CTX_HANDLER_H

#include <infiniband/verbs.h>

// client to event manager 'command' invoker (??)
//
class ib_ctx_handler
{
public:
	ib_ctx_handler(struct ibv_context* ctx);
	virtual ~ib_ctx_handler();
	/*
	 * on init or constructor:
	 *      register to event manager with m_channel and this.
	 * */
	//void execute(struct ibv_async_event ibv_event) { handle_ibv_event(ibv_event); }
	void                    set_dev_configuration();
	ibv_mr*                 mem_reg(void *addr, size_t length, uint64_t access);
	ibv_port_state          get_port_state(int port_num);
	ibv_device*             get_ibv_device() { return m_p_ibv_device;}
	ibv_pd*			get_ibv_pd() { return m_p_ibv_pd;}
	struct ibv_context*     get_ibv_context() { return m_p_ibv_context;}
	ibv_device_attr&        get_ibv_device_attr() { return m_ibv_device_attr;}
	struct ibv_port_attr    get_ibv_port_attr(int port_num);

private:
	struct ibv_context*     m_p_ibv_context;
	struct ibv_port_attr    m_ibv_port_attr;
	ibv_device*             m_p_ibv_device; // HCA handle
	ibv_device_attr         m_ibv_device_attr;
	ibv_pd*                 m_p_ibv_pd;
	int                     m_channel; // fd channel

	bool                    update_port_attr(int port_num);

	//void handle_ibv_event(struct ibv_async_event ibv_event); // will be called by the command execute
	//
	//conf params
	uint32_t                m_conf_attr_rx_num_wre;
	uint32_t                m_conf_attr_tx_num_post_send_notify;
	uint32_t                m_conf_attr_tx_max_inline;
	uint32_t                m_conf_attr_tx_num_wre;
};

#endif
