/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef PKT_RECVR_SINK_H
#define PKT_RECVR_SINK_H

class mem_buf_desc_t;
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
	virtual bool rx_input_cb(mem_buf_desc_t* p_rx_pkt_mem_buf_desc_info, void* pv_fd_ready_array) = 0;

	// Callback from lower layer notifying completion of RX registration process
	virtual void rx_add_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring) = 0;
	
	// Callback from lower layer notifying before RX resources deallocation
	virtual void rx_del_ring_cb(flow_tuple_with_local_if &flow_key, ring* p_ring) = 0;
};

#endif
