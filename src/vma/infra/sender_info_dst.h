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


#ifndef SENDER_INFO_DST_H
#define SENDER_INFO_DST_H

#include "sender.h"
#include "proto/dst_entry.h"

class sender::send_info_dst: public sender::send_info
{
public:
	sender::send_info_dst(ibv_send_wr *send_wqe, dst_entry *dst_entry): m_p_send_wqe(send_wqe) {};
	sender::send_info_dst(): m_p_send_wqe(NULL) {};
	virtual ~send_info() {};

	dst_entry *m_p_send_wqe;

};



#endif /* SENDER_INFO_DST_H */
