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


#ifndef PKT_RECVR_SINK_H
#define PKT_RECVR_SINK_H

struct mem_buf_desc_t;
class flow_tuple_with_local_if;
class ring;

/*
 * Class pkt_rcvr_sink
 * An object must implement pkt_rcvr_sink to register with ib_conn_mgr_base
 * The rx_joined_notify_cb() will be called when the IBCM is ready to start 
 * receiving packets (MC join is complete and CQ is mapped).
 * The rx_diconnect_notify_cb() will be called before the IB stops receiving
 * packets (CQ is being removed and MC leave is called).
 * The rx_pkt_notify_cb() will be called when a ip packet is in the ready q for the socket.
 * The implementing object should register the information and release calling context immediately.
 * When no packet receivers (or transmitters) are registered the objects will be deleted
*/
class pkt_rcvr_sink
{
public:
	virtual ~pkt_rcvr_sink() {};

	// Callback from lower layer notifying new receive packets
	// Return: 'true' if object queuing this receive packet
	//         'false' if not interested in this receive packet
	virtual bool rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array = NULL) = 0;

	// Callback from lower layer notifying completion of RX registration process
	virtual void rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false) = 0;
	
	// Callback from lower layer notifying before RX resources deallocation
	virtual void rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring, bool is_migration = false) = 0;
};

#endif
