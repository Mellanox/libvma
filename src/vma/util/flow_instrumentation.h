/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


/*
 * VMA instrumental - measure the times that certain actions takes.
 * Currently support: RX,TX,IOMUX
 * Enable: use --enable-time_measure in ./configure
 * Parameters:
 * 	VMA_TIME_MEASURE_DUMP_FILE - Name of the results file. Default: /tmp/VMA_inst.dump
 * 	VMA_TIME_MEASURE_NUM_SAMPLES - Number of samples for a dump file. Default: 10000
 * Limitations:
 * 	- No support for multi-threading
 * 	- Support only one socket
 */

#ifndef FLOWINSTRUMENTATION_H
#define FLOWINSTRUMENTATION_H

// RECIEVE FLOW
 #define FLOW_RECV_TO_CQMGR_RING
 #define FLOW_CQ_MGR_POLL_WRAPPER
 #define FLOW_CQ_MGR_HIT_TO_RX_INPUT_CB
 #define FLOW_CQ_MGR_MISS_TO_RECV
 #define FLOW_RX_INPUT_CB_TCP_TO_RECV
 #define FLOW_RX_INPUT_CB_UDP_TO_RECV
 #define FLOW_RX_INPUT_CB_TCP_WRAPPER
 #define FLOW_RX_INPUT_CB_UDP_WRAPPER


// SEND FLOW

 #define FLOW_SEND_TO_FASTSEND_TCP
 #define FLOW_SEND_TO_FASTSEND_UDP
 #define FLOW_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER
 #define FLOW_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER
 #define FLOW_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER
// #define FLOW_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND 

/***********************************************************************/

#ifdef FLOW_RECV_TO_CQMGR_RING
	#define INSTRUMENT_START_RECV_TO_CQMGR_RING              VMA_TIME_IBPROF_START(11, "recv/select to cq_mgr::poll");
	#define INSTRUMENT_END_RECV_TO_CQMGR_RING                VMA_TIME_IBPROF_END(11);
#else
        #define INSTRUMENT_START_RECV_TO_CQMGR_RING
        #define INSTRUMENT_END_RECV_TO_CQMGR_RING
#endif


#ifdef FLOW_CQ_MGR_POLL_WRAPPER
	#define INSTRUMENT_START_CQ_MGR_POLL_WRAPPER             VMA_TIME_IBPROF_START(22, "cq_mgr::poll");
        #define INSTRUMENT_END_CQ_MGR_POLL_WRAPPER               VMA_TIME_IBPROF_END(22);
#else
        #define INSTRUMENT_START_CQ_MGR_POLL_WRAPPER
        #define INSTRUMENT_END_CQ_MGR_POLL_WRAPPER
#endif


#ifdef FLOW_CQ_MGR_HIT_TO_RX_INPUT_CB
        #define INSTRUMENT_START_CQ_MGR_HIT_TO_RX_INPUT_CB       VMA_TIME_IBPROF_START(33, "cq_mgr::poll(HIT) to rx_input_cb");
        #define INSTRUMENT_END_CQ_MGR_HIT_TO_RX_INPUT_CB         VMA_TIME_IBPROF_END(33);
#else
	#define INSTRUMENT_START_CQ_MGR_HIT_TO_RX_INPUT_CB 
	#define INSTRUMENT_END_CQ_MGR_HIT_TO_RX_INPUT_CB
#endif


#ifdef FLOW_CQ_MGR_MISS_TO_RECV
	#define INSTRUMENT_START_CQ_MGR_MISS_TO_RECV             VMA_TIME_IBPROF_START(44, "cq_mgr::poll(MISS) to recv/select");
	#define INSTRUMENT_END_CQ_MGR_MISS_TO_RECV               VMA_TIME_IBPROF_END(44);
#else
        #define INSTRUMENT_START_CQ_MGR_MISS_TO_RECV
        #define INSTRUMENT_END_CQ_MGR_MISS_TO_RECV
#endif

#ifdef FLOW_RX_INPUT_CB_TCP_TO_RECV
	#define INSTRUMENT_START_RX_INPUT_CB_TCP_TO_RECV    VMA_TIME_IBPROF_START(55, "rx_input_cb(tcp) to recv/select");
	#define INSTRUMENT_END_RX_INPUT_CB_TCP_TO_RECV    VMA_TIME_IBPROF_END(55); 
#else
	#define INSTRUMENT_START_RX_INPUT_CB_TCP_TO_RECV
	#define INSTRUMENT_END_RX_INPUT_CB_TCP_TO_RECV
#endif

#ifdef FLOW_RX_INPUT_CB_UDP_TO_RECV
	#define INSTRUMENT_START_RX_INPUT_CB_UDP_TO_RECV       VMA_TIME_IBPROF_START(66, "rx_input_cb(udp) to recv/select");
        #define INSTRUMENT_END_RX_INPUT_CB_UDP_TO_RECV         VMA_TIME_IBPROF_END(66);
#else
	#define INSTRUMENT_START_RX_INPUT_CB_UDP_TO_RECV    
        #define INSTRUMENT_END_RX_INPUT_CB_UDP_TO_RECV    

#endif

#ifdef FLOW_RX_INPUT_CB_TCP_WRAPPER
	#define INSTRUMENT_START_RX_INPUT_CB_TCP_WRAPPER	VMA_TIME_IBPROF_START(77, "rx_input_cb(tcp)");
	#define INSTRUMENT_END_RX_INPUT_CB_TCP_WRAPPER		VMA_TIME_IBPROF_END(77);
#else
        #define INSTRUMENT_START_RX_INPUT_CB_TCP_WRAPPER
        #define INSTRUMENT_END_RX_INPUT_CB_TCP_WRAPPER
#endif

#ifdef FLOW_RX_INPUT_CB_UDP_WRAPPER
	#define INSTRUMENT_START_RX_INPUT_CB_UDP_WRAPPER	VMA_TIME_IBPROF_START(88, "rx_input_cb(udp)");
        #define INSTRUMENT_END_RX_INPUT_CB_UDP_WRAPPER		VMA_TIME_IBPROF_END(88);
#else
        #define INSTRUMENT_START_RX_INPUT_CB_UDP_WRAPPER
        #define INSTRUMENT_END_RX_INPUT_CB_UDP_WRAPPER
#endif



/*************************************************************************/

#ifdef FLOW_SEND_TO_FASTSEND_TCP
	#define INSTRUMENT_START_SEND_TO_FASTSEND_TCP	     VMA_TIME_IBPROF_START(101, "send to fast_send(tcp)");
	#define INSTRUMENT_END_SEND_TO_FASTSEND_TCP	     VMA_TIME_IBPROF_END(101);
#else
       #define INSTRUMENT_START_SEND_TO_FASTSEND_TCP
        #define INSTRUMENT_END_SEND_TO_FASTSEND_TCP

#endif

#ifdef FLOW_SEND_TO_FASTSEND_UDP
        #define INSTRUMENT_START_SEND_TO_FASTSEND_UDP        VMA_TIME_IBPROF_START(102, "send to fast_send(udp)");
        #define INSTRUMENT_END_SEND_TO_FASTSEND_UDP          VMA_TIME_IBPROF_END(102);
#else
	#define INSTRUMENT_START_SEND_TO_FASTSEND_UDP
        #define INSTRUMENT_END_SEND_TO_FASTSEND_UDP

#endif

#ifdef FLOW_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER
	#define INSTRUMENT_START_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER VMA_TIME_IBPROF_START(111, "fastsend(tcp) to send_ring_buffer");
	#define INSTRUMENT_END_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER   VMA_TIME_IBPROF_END(111);
#else
        #define INSTRUMENT_START_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER
        #define INSTRUMENT_END_FASTSEND_TCP_TO_SIMPLE_SEND_RING_BUFFER
#endif

#ifdef FLOW_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER
        #define INSTRUMENT_START_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER VMA_TIME_IBPROF_START(112, "fastsend(udp) to send_ring_buffer");
        #define INSTRUMENT_END_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER   VMA_TIME_IBPROF_END(112); 
#else
        #define INSTRUMENT_START_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER
        #define INSTRUMENT_END_FASTSEND_UDP_TO_SIMPLE_SEND_RING_BUFFER
#endif


#ifdef FLOW_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER
        #define INSTRUMENT_START_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER VMA_TIME_IBPROF_START(121, "ring_simple::send_ring_buffer()");
        #define INSTRUMENT_END_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER   VMA_TIME_IBPROF_END(121);
#else
        #define INSTRUMENT_START_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER
        #define INSTRUMENT_END_RING_SIMPLE_SEND_RING_BUFFER_WRAPPER
#endif

#ifdef FLOW_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND
        #define INSTRUMENT_START_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND  VMA_TIME_IBPROF_START(131, "send_ring_buffer() to send");
        #define INSTRUMENT_END_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND    VMA_TIME_IBPROF_END(131);
#else
        #define INSTRUMENT_START_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND
        #define INSTRUMENT_END_RING_SIMPLE_SEND_RING_BUFFER_TO_SEND
#endif




#endif //FLOWINSTRUMENTATION


