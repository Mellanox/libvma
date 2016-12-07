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


#include "ring.h"

#undef  MODULE_NAME
#define MODULE_NAME     "ring"
#undef  MODULE_HDR
#define MODULE_HDR      MODULE_NAME "%d:%s() "


ring::ring(int count, uint32_t mtu) :
	m_n_num_resources(count), m_p_n_rx_channel_fds(NULL), m_parent(NULL),
	m_vma_active(true), /* TODO: This VMA version supports vma_poll() usage mode only */
	m_mtu(mtu)
{
	INIT_LIST_HEAD(&m_ec_list);
	m_vma_poll_completion = NULL;
}

ring::~ring()
{
	ring_logdbg("queue of event completion elements is %s",
			(list_empty(&m_ec_list) ? "empty" : "not empty"));
}
