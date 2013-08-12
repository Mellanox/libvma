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


#ifndef PKT_SNDR_SOURCE_H
#define PKT_SNDR_SOURCE_H

/**
 * @class pkt_sndr_source
 * An object must implement pkt_sndr_source to register with ib_conn_mgr_base
 * When no packet transmitters (or receivers) are registered the objects will be
 * deleted.
 */
class pkt_sndr_source
{
public:
	virtual ~pkt_sndr_source() {};
};


#endif
