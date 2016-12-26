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


#ifndef VMA_EXTRA_H
#define VMA_EXTRA_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/*
 * Flags for recvfrom_zcopy()
 */
#define MSG_VMA_ZCOPY_FORCE	0x01000000 // don't fallback to bcopy
#define	MSG_VMA_ZCOPY		0x00040000 // return: zero copy was done

/*
 * Options for setsockopt()/getsockopt()
 */
#define SO_VMA_GET_API       2800
#define SO_VMA_USER_DATA     2801

/*
 * Flags for Dummy send API
 */
#define VMA_SND_FLAGS_DUMMY MSG_SYN // equals to 0x400

/* 
 * Return values for the receive packet notify callback function
 */
typedef enum {
	VMA_PACKET_DROP,     /* VMA will drop the received packet and recycle 
	                        the buffer if no other socket needs it */

	VMA_PACKET_RECV,     /* VMA will queue the received packet on this socket ready queue.
	                        The application will read it with the usual recv socket APIs */

	VMA_PACKET_HOLD      /* Application will handle the queuing of the received packet. The application
	                        must return the descriptor to VMA using the free_packet function
				But not in the context of VMA's callback itself. */
} vma_recv_callback_retval_t;


/************ vma_poll() API types definition start***************/

typedef enum {
    VMA_POLL_PACKET 			= (1ULL << 32), /* New packet is available */
    VMA_POLL_NEW_CONNECTION_ACCEPTED	= (1ULL << 33)  /* New connection is auto accepted by server */
} vma_poll_events_t;

/*
 * Represents  VMA buffer
 * Used in vma_poll() extended API.
 */
struct vma_buff_t {
	struct vma_buff_t*	next;		/* next buffer (for last buffer next == NULL) */
	void*		payload;		/* pointer to data */
	uint16_t	len;			/* data length */
};

/**
 * Represents one VMA packet
 * Used in vma_poll() extended API.
 */
struct vma_packet_desc_t {
	size_t			num_bufs;	/* number of packet's buffers */
	uint16_t		total_len;	/* total data length */
	struct vma_buff_t*	buff_lst;	/* list of packet's buffers */
};

/*
 * Represents VMA Completion.
 * Used in vma_poll() extended API.
 */
struct vma_completion_t {
	/* Packet is valid in case VMA_POLL_PACKET event is set
         */
	struct vma_packet_desc_t packet;
	/* Set of events
         */
	uint64_t                 events;
	/* User provided data.
         * By default this field has FD of the socket
         * User is able to change the content using setsockopt()
         * with level argument SOL_SOCKET and opname as SO_VMA_USER_DATA
         */ 
	uint64_t                 user_data;
	/* Source address (in network byte order) set for:
	 * VMA_POLL_PACKET and VMA_POLL_NEW_CONNECTION_ACCEPTED events
	 */
	struct sockaddr_in       src;
	/* Connected socket's parent/listen socket fd number.
	 * Valid in case VMA_POLL_NEW_CONNECTION_ACCEPTED event is set.
	*/
	int 			listen_fd;
};

/************ vma_poll() API types definition end ***************/

// REVIEW - remove unecessary legacy API

/**
 * Represents one VMA packets 
 * Used in zero-copy extended API.
 */
struct __attribute__ ((packed)) vma_packet_t {
	void*		packet_id;		// packet identifier
	size_t		sz_iov;			// number of fragments
	struct iovec	iov[];			// fragments size+data
};

/**
 * Represents received packets in VMA
 * Used in zero-copy extended API.
 */
struct __attribute__ ((packed)) vma_packets_t {
	size_t n_packet_num;		// number of received packets
	struct vma_packet_t	pkts[];	// array of received packets
};

/* 
 * Structure holding additional information on the packet and socket
 * Note: Check structure size value for future VMA libraries changes
 */
struct __attribute__ ((packed)) vma_info_t {
	size_t 			struct_sz;	/* Compare this value with sizeof(vma_info_t) to check version compatability */
	void*			packet_id;	/* VMA's handle to received packet buffer to be return if zero copy logic is used */

	/* Packet addressing information (in network byte order) */
	struct sockaddr_in*	src;
	struct sockaddr_in*	dst;

	/* Packet information */
	size_t			payload_sz;

	/* Socket's information */
	uint32_t		socket_ready_queue_pkt_count;	/* Current count of packets waiting to be read from the socket */
	uint32_t		socket_ready_queue_byte_count;	/* Current count of bytes waiting to be read from the socket */
	/* Packet timestamping information */
	struct timespec		hw_timestamp;
	struct timespec		sw_timestamp;
};

/** 
 *  
 * VMA Notification callback for incoming packet on socket
 * @param fd Socket's file descriptor which this packet refers to
 * @param iov iovector structure array point holding the packet 
 *            received data buffer pointers and size of each buffer
 * @param iov_sz Size of iov array
 * @param vma_info Additional information on the packet and socket
 * @param context User-defined value provided during callback 
 *                registration for each socket
 *
 *   This callback function should be registered with VMA by calling
 * register_recv_callback() in the extended API. It can be unregistered by 
 * setting a NULL function pointer. VMA will call the callback to notify 
 * of new incoming packets after the IP & UDP header processing and before 
 * they are queued in the socket's receive queue. 
 *   Context of the callback will always be from one of the user's application
 * threads when calling the following socket APIs: select, poll, epoll, recv, 
 * recvfrom, recvmsg, read, readv. 
 * 
 * Notes:
 * - The application can call all of the Socket APIs control and send from
 *   within the callback context.
 * - Packet loss might occur depending on the applications behavior in the 
 *   callback context.
 * - Parameters `iov' and `vma_info' are only valid until callback context 
 *   is returned to VMA. User should copy these structures for later use 
 *   if working with zero copy logic.
 */
typedef vma_recv_callback_retval_t 
(*vma_recv_callback_t) (int fd, size_t sz_iov, struct iovec iov[], 
                        struct vma_info_t* vma_info, void *context);


/**
 * VMA Extended Socket API
 */
struct __attribute__ ((packed)) vma_api_t {
	/**
	 * Register a received packet notification callback.
	 * 
	 * @param s Socket file descriptor.
	 * @param callback Callback function.
	 * @param context user contex for callback function.
	 * 
	 * @return 0 - success, -1 - error
	 * errno is set to: EINVAL - not VMA offloaded socket 
	 */
	int (*register_recv_callback)(int s, vma_recv_callback_t callback, void *context);
	
	/**
	 * Zero-copy revcfrom implementation.
	 * 
	 * @param s Socket file descriptor.
	 * @param buf Buffer to fill with received data or pointers to data (see below).
	 * @param flags Pointer to flags (see below).
	 * @param from If not NULL, will be filled with source address (same as recvfrom).
	 * @param fromlen If not NULL, will be filled with source address size (same as recvfrom).
	 * 
	 * This function attempts to receive a packet without doing data copy.
	 * The flags argument can contain the usual flags of recvmsg(), and also the
	 * MSG_VMA_ZCOPY_FORCE flag. If the latter is set, the function will not
	 * fall back to data copy. Otherwise, the function falls back to data copy
	 * if zero-copy cannot be performed. If zero-copy is done then MSG_VMA_ZCOPY
	 * flag is set upon exit.
	 * 
	 * If zero copy is performed (MSG_VMA_ZCOPY flag is returned), the buffer 
	 * is filled with a vma_packets_t structure, holding as much fragments 
         * as `len' allows. The total size of all fragments is returned.
         * Otherwise the MSG_VMA_ZCOPY flag is not set and the buffer is filled
         * with actual data and it's size is returned (same as recvfrom())
	 * If no data was received the return value is zero.
	 * 
	 * NOTE: The returned packet must be freed with free_packet() after
	 * the application finished using it.
	 */
	int (*recvfrom_zcopy)(int s, void *buf, size_t len, int *flags,
                              struct sockaddr *from, socklen_t *fromlen);
	
	/**
	 * Frees a packet received by recvfrom_zcopy() or held by receive callback.
	 * 
	 * @param s Socket from which the packet was received.
	 * @param pkts Array of packet.
	 * @param count Number of packets in the array.
	 * @return 0 on success, -1 on failure
	 * 
	 * errno is set to: EINVAL - not a VMA offloaded socket
	 *                  ENOENT - the packet was not received from `s'.
	 */
	int (*free_packets)(int s, struct vma_packet_t *pkts, size_t count);


	/*
	 * Add a libvma.conf rule to the top of the list.
	 * This rule will not apply to existing sockets which already considered the conf rules.
	 * (around connect/listen/send/recv ..)
	 * @param config_line A char buffer with the exact format as defined in libvma.conf, and should end with '\0'.
	 * @return 0 on success, or error code on failure.
	 */
	int (*add_conf_rule)(char *config_line);

	/*
	 * Create sockets on pthread tid as offloaded/not-offloaded.
	 * This does not affect existing sockets.
	 * Offloaded sockets are still subject to libvma.conf rules.
	 * @param offload 1 for offloaded, 0 for not-offloaded.
	 * @return 0 on success, or error code on failure.
	 */
	int (*thread_offload)(int offload, pthread_t tid);


	/**
	 * vma_poll() polls for VMA completions
	 *
	 * @param fd File descriptor.
	 * @param completions VMA completions array.
	 * @param ncompletions Maximum number of completion to return.
	 * @param flags Flags.
	 * @return On success, return the number of ready completions.
	 * 	   On error, -1 is returned, and TBD:errno is set?.
	 *
	 * This function polls the `fd` for VMA completions and returns maximum `ncompletions` ready
	 * completions via `completions` array.
	 * The `fd` can represent a ring, socket or epoll file descriptor.
	 *
	 * VMA completions are indicated for incoming packets and/or for other events.
	 * If VMA_POLL_PACKET flag is enabled in vma_completion_t.events field
	 * the completion points to incoming packet descriptor that can be accesses
	 * via vma_completion_t.packet field.
	 * Packet descriptor points to VMA buffers that contain data scattered
	 * by HW, so the data is deliver to application with zero copy.
	 * Notice: after application finished using the returned packets
	 * and their buffers it must free them using free_vma_packets()/free_vma_buff()
	 * functions.
	 * If VMA_POLL_PACKET flag is disabled vma_completion_t.packet field is
	 * reserved.
	 *
	 * In addition to packet arrival event (indicated by VMA_POLL_PACKET flag)
	 * VMA also reports VMA_POLL_NEW_CONNECTION_ACCEPTED event and standard
	 * epoll events via vma_completion_t.events field.
	 * VMA_POLL_NEW_CONNECTION_ACCEPTED event is reported when new connection is
	 * accepted by the server.
	 * When working with vma_poll() new connections are accepted
	 * automatically and accept(listen_socket) must not be called.
	 * VMA_POLL_NEW_CONNECTION_ACCEPTED event is reported for the new
	 * connected/child socket (vma_completion_t.user_data refers to child socket)
	 * and EPOLLIN event is not generated for the listen socket.
	 * For events other than packet arrival and new connection acceptance
	 * vma_completion_t.events bitmask composed using standard epoll API
	 * events types.
	 * Notice: the same completion can report multiple events, for example
	 * VMA_POLL_PACKET flag can be enabled together with EPOLLOUT event,
	 * etc...
	 *
	 * * errno is set to: TBD...
	 */
	 int (*vma_poll)(int fd, struct vma_completion_t* completions, unsigned int ncompletions, int flags);

	 /**
	 * Returns the amount of rings that are associated with socket.
	 *
	 * @param fd File Descriptor number of the socket.
	 * @return On success, return the amount of rings.
	 * 	   On error, -1 is returned.
	 *
	 * errno is set to: EINVAL - not a VMA offloaded fd
	 */
	 int (*get_socket_rings_num)(int fd);

	 /**
	 * Returns FDs of the rings that are associated with the socket.
	 *
	 * This function gets socket FD + int array + array size and populates
	 * the array with FD numbers of the rings that are associated
	 * with the socket.
	 *
	 * @param fd File Descriptor number.
	 * @param ring_fds Int array of ring fds
	 * @param ring_fds_sz Size of the array
	 * @return On success, return the number populated array entries.
	 * 	   On error, -1 is returned.
	 *
	 * errno is set to: EINVAL - not a VMA offloaded fd + TBD
	 */
	 int (*get_socket_rings_fds)(int fd, int *ring_fds, int ring_fds_sz);

	/**
	 * Frees packets received by vma_poll().
	 *
	 * @param packets Packets to free.
	 * @param num Number of packets in `packets` array
	 * @return 0 on success, -1 on failure
	 *
	 * For each packet in `packet` array this function:
	 * - Updates receive queue size and the advertised TCP
	 *   window size, if needed, for the socket that received
	 *   the packet.
	 * - Frees vma buffer list that is associated with the packet.
	 *   Notice: for each buffer in buffer list VMA decreases buffer's
	 *   ref count and only buffers with ref count zero are deallocated.
	 *   Notice:
	 *   - Application can increase buffer reference count,
	 *     in order to hold the buffer even after free_vma_packets()
	 *     was called for the buffer, using vma_buff_ref().
	 *   - Application is responsible to free buffers, that
	 *     couldn't be deallocated during free_vma_packets() due to
	 *     non zero reference count, using free_vma_buff() function.
	 *
	 * errno is set to: EINVAL if NULL pointer is provided.
	 */
	int (*free_vma_packets)(struct vma_packet_desc_t *packets, int num);

	/* This function increments the reference count of the buffer.
	 * This function should be used in order to hold the buffer
	 * even after vma_free_packets() call.
	 * When buffer is not needed any more it should be freed via
	 * vma_buff_free().
	 *
	 * @param buff Buffer to update.
	 * @return On success, return buffer's reference count after the change
	 * 	   On errors -1 is returned
	 *
	 * errno is set to EINVAL if NULL pointer is provided.
	 */
	int (*ref_vma_buff)(struct vma_buff_t *buff);

	/* This function decrements the buff reference count.
	 * When buff's reference count reaches zero, the buff is
	 * deallocated.
	 *
	 * @param buff Buffer to free.
	 * @return On success, return buffer's reference count after the change
	 * 	   On error -1 is returned
	 *
	 * Notice: return value zero means that buffer was deallocated.
	 *
	 * errno is set to EINVAL if NULL pointer is provided.
	 */
	int (*free_vma_buff)(struct vma_buff_t *buff);

	/*
	 * Dump fd statistics using VMA logger.
	 *
	 * @param fd to dump, 0 for all open fds.
	 * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
	 * @return 0 on success, or error code on failure.
	 */
	int (*dump_fd_stats) (int fd, int log_level);

};


#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

/**
 * Retrieve VMA extended API.
 *
 * @return Pointer to the VMA Extended Socket API, of NULL if VMA not found. 
 */
static inline struct vma_api_t* vma_get_api()
{
	struct vma_api_t *api_ptr = NULL;
	socklen_t len = sizeof(api_ptr);
	getsockopt(-1, SOL_SOCKET, SO_VMA_GET_API, &api_ptr, &len);
	return api_ptr;
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

/* 
 * vma_poll() Demo Usage
 *


struct vma_api_t* vma_api = NULL;


 *
 * Main loop
 *
myapp_socket_main_loop()
{
	int flags = 0;
	char buf[256];
	int rings;
	vma_completion_t comp;
	int ready_comp = 0;
	bool to_exit = false;


	// Try to find if VMA is loaded and the Extra API is available
	vma_api = vma_get_api();

	// Create my application's  socket
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	//Configure/connect the socket
	setsockopt()
	connect()
	...

	//Get socket's ring, we skip reading the number of rings
	//since connected TCP socket is associated with a single ring
	if (vma_api) {
		vma_api->get_socket_rings_fds(fd, &ring, 1);
	}
	else {
		exit...
	}

	// Main traffic processing loop going into VMA engine
	while (!to_exit) {

		ready_comp = vma_api->vma_poll(ring_fd, &comp, 1, flags);

		// recv path socket API...
		if (ready_comp > 0) {
			if (comp.events & VMA_COMPLETION_TYPE_PACKET) {
				myapp_processes_packet_func(comp.user_data, &comp.packet);

				//Hold the buffers
				vma_buff_t curr_buff = comp.packet.buff_lst;
				while (curr_buff) {
					vma_api->vma_buff_ref(curr_buff);
					curr_buff = curr_buff->next;
				}
				//Update socket's TCP window size
				vma_api->free_vma_packets(socket_fd, &comp.packet, 1);
			}
			myapp_processes_events_func(comp.user_data,comp.events);

			//The buffers are not needed any more, deallocate them
			vma_buff_t curr_buff = comp.packet.buff_lst;
			while (curr_buff) {
				//Free the buffer
				vma_api->vma_buff_ref(curr_buff);
				curr_buff = curr_buff->next;
			}
		}
		else if (ready_comp < 0) {
			to_exit = true;
		}
	}
}

 *
 * Process VMA buffer
 *
myapp_processes_packet_func(
	int socket,
	vma_packet_t* packet)
{
	vma_buff_t* curr_buff = packet->buff_lst;

	printf("[fd=%d] Received packet from: %s:%d \n", socket, inet_ntoa(packet->src.sin_addr), ntohs(packet->src.sin_port));
	printf("Packet total length is: %u\n", packet->total_len);
	printf("Packet's buffers: \n");
	while (curr_buff) {
		printf("Address: %p, Length: %u\n", curr_buff->payload, curr_buff->len);
		curr_buff = curr_buff->next;
	}

}

 *
 * Process VMA event
 *
myapp_processes_events_func(
	int socket,
	uint64_t events)
{
	if (comp.events & EPOLLHUP){
		printf("[fd=%d] EPOLLHUP event occurred\n", socket);
	}
}


 *
 * vma_poll() UDP Demo Usage
 *


struct vma_api_t* vma_api = NULL;


 *
 * Main loop
 *
myapp_socket_main_loop()
{
	int flags = 0;
	char buf[256];
	int rings;
	vma_completion_t comp;
	int ready_comp = 0;
	bool to_exit = false;


	// Try to find if VMA is loaded and the Extra API is available
	vma_api = vma_get_api();

	// Create my application's  socket
	int fd = socket(AF_INET, SOCK_DGRAM, 0)

	//Bind the socket
	...

	//Get socket's ring, we skip reading the number of rings
	//since connected UDP socket is associated with a single ring
	if (vma_api) {
		vma_api->get_socket_rings_fds(fd, &ring, 1);
	}
	else {
		exit...
	}

	// Main traffic processing loop going into VMA engine
	while (!to_exit) {

		ready_comp = vma_api->vma_poll(ring_fd, &comp, 1, flags);

		// recv path socket API...
		if (ready_comp > 0) {
			if (comp.events & VMA_POLL_PACKET) {
				myapp_processes_packet_func(comp.user_data, &comp.packet);

				//Hold the buffers
				vma_buff_t curr_buff = comp.packet.buff_lst;
				while (curr_buff) {
					vma_api->vma_buff_ref(curr_buff);
					curr_buff = curr_buff->next;
				}
			}
			myapp_processes_events_func(comp.user_data,comp.events);

			//The buffers are not needed any more, deallocate them
			vma_buff_t curr_buff = comp.packet.buff_lst;
			while (curr_buff) {
				//Free the buffer
				vma_api->vma_buff_ref(curr_buff);
				curr_buff = curr_buff->next;
			}
		}
		else if (ready_comp < 0) {
			to_exit = true;
		}
	}
}

 *
 * Process VMA buffer
 *
myapp_processes_packet_func(
	int socket,
	vma_packet_t* packet)
{
	vma_buff_t* curr_buff = packet->buff_lst;

	printf("[fd=%d] Received packet from: %s:%d \n", socket, inet_ntoa(packet->src.sin_addr), ntohs(packet->src.sin_port));
	printf("Packet total length is: %u\n", packet->total_len);
	printf("Packet's buffers: \n");
	while (curr_buff) {
		printf("Address: %p, Length: %u\n", curr_buff->payload, curr_buff->len);
		curr_buff = curr_buff->next;
	}
}

 *
 * Process VMA event
 *
myapp_processes_events_func(
	int socket,
	uint64_t events)
{
	if (comp.events){
		printf("[fd=%d] event occurred\n", socket);
	}
}


 *
 * VMA callback + recvfrom_zcopy Demo Usage
 *


struct vma_api_t* vma_api = NULL;


 *
 * Your application receive notification callback function
 *

vma_recv_callback_retval_t myapp_vma_recv_pkt_notify_callback(
	int fd, 
	size_t sz_iov, 
	struct iovec iov[], 
	struct vma_info_t* vma_info, 
	void *context)
{
	// Check info structure version
	if (vma_info->struct_sz < sizeof(vma_info_t)) {
		printf("VMA's info struct is not something we recognize so un register the application's callback function");
		void* option_value = NULL;
		vma_api->register_recv_callback(fd, option_value, &fd);
		return VMA_PACKET_RECV;
	}

	if ("rule to check if packet should be dropped") {
		return VMA_PACKET_DROP; 
	}

	if ("Do we support zero copy logic?") {
		// Application must duplicate the iov' & 'vma_info' parameters for later usage
		struct iovec* my_iov = calloc(iov_sz, sizeof(struct iovec));
		memcpy(my_iov, iov, sizeof(struct iovec)*iov_sz);
		myapp_processes_packet_func(my_iov, iov_sz, vma_info->packet_id);
		return VMA_PACKET_HOLD;
	}

	return VMA_PACKET_RECV;
}

 
 * 
 * Register appliction callback with VMA"
 *
myapp_socket_main_loop()
{
	int flags = 0;
	char buf[256];

	// Try to find if VMA is loaded and the Extra API is avilable
	vma_api = vma_get_api();

	// Create my application's multicast socket
	int fd = socket("My Multicast socket")
	setsockopt(fd, IP_ADD_MEMBERSHIP, ...)
	...

	// Try to register with VMA's special receive notification callback logic
	if (vma_api && (vma_api->register_recv_callback(fd, myapp_vma_recv_pkt_notify_callback, &fd) < 0)) {
		printf("VMA does not support the receive packet notify callback!");
	}
	...

	// Main traffic processesing loop going into VMA engine
	while () {
	
		select(...); // VMA callback will be called form this context!!

		// recv path socket API...
		flags = 0;
		int ret = vma_api->recvfrom_zcopy(fd, buf, 256, &flags, NULL, NULL);
		if (flags == MSG_VMA_ZCOPY) {
			vma_packets_t* vma_packets = (vma_packets_t*)buf;
			for (int i = 0; i < vma_packets->n_packet_num; i++) {
				vma_packet_t* vma_packet = &vma_packets->pkts[i];
				myapp_processes_packet_func(vma_packet->iov, vma_packet->iov_sz,
							    vma_packet->packet_id);
			}
		}
	}
}



 * 
 * Process and Release VMA buffer
 *
myapp_processes_packet_func(
	struct iovec* iov, 
	size_t iov_sz, 
	void* packet_id)
{
	myapp_processes_packet_func(.....);

	// Return zero copied datagram buffer back to VMA
	// Would be better to collect a bunch of buffers and return them all at once
	// which will save locks inside VMA
	vma_api->free_datagrams(s, &packet_id, 1);
}


*/

#endif /* VMA_EXTRA_H */
