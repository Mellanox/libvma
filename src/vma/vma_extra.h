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


#ifndef VMA_EXTRA_H
#define VMA_EXTRA_H

#include <stddef.h>
#include <stdint.h>
/*
 * Flags for recvfrom_zcopy()
 */
#define MSG_VMA_ZCOPY_FORCE	0x01000000 // don't fallback to bcopy
#define	MSG_VMA_ZCOPY		0x00040000 // return: zero copy was done


/* 
 * Return values for the receive packet notify callback function
 */
typedef enum {
	VMA_PACKET_DROP,     /* VMA will drop the received datagram and recycle 
	                        the buffer if no other socket needs it */

	VMA_PACKET_RECV,     /* VMA will queue the received datagram on this socket ready queue.
	                        The application will read it with the usual recv socket APIs */

	VMA_PACKET_HOLD      /* Application will handle the queuing of the received datagram. The application
	                        must return the descriptor to VMA using the free_datagram function
				But not in the context of VMA's callback itself. */
} vma_recv_callback_retval_t;


/**
 * Represents a VMA datagram.
 * Used in zero-copy extended API.
 */
struct __attribute__ ((packed)) vma_datagram_t {
	void*		datagram_id;		// datagram identifier
	size_t		sz_iov;			// number of fragments
	struct iovec	iov[];			// fragments size+data
};


/* 
 * Structure holding additional information on the packet and socket
 * Note: Check structure size value for future VMA libraries changes
 */
struct __attribute__ ((packed)) vma_info_t {
	size_t 			struct_sz;	/* Compare this value with sizeof(vma_info_t) to check version compatability */
	void*			datagram_id;	/* VMA's handle to received packet buffer to be return if zero copy logic is used */

	/* Packet addressing information (in network byte order) */
	struct sockaddr_in*	src;
	struct sockaddr_in*	dst;

	/* Packet information */
	size_t			payload_sz;

	/* Socket's information */
	uint32_t		socket_ready_queue_pkt_count;	/* Current count of packets waiting to be read from the socket */
	uint32_t		socket_ready_queue_byte_count;	/* Current count of bytes waiting to be read from the socket */
};


/** 
 *  
 * VMA Notification callback for incoming datagram on socket
 * @param fd Socket's file descriptor which this packet refers to
 * @param iov iovector structure array point holding the datagram 
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
	 * Register a received datagram notification callback.
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
	 * This function attempts to receive a datagram without doing data copy.
	 * The flags argument can contain the usual flags of recvmsg(), and also the
	 * MSG_VMA_ZCOPY_FORCE flag. If the latter is set, the function will not
	 * fall back to data copy. Otherwise, the function falls back to data copy
	 * if zero-copy cannot be performed. If zero-copy is done then MSG_VMA_ZCOPY
	 * flag is set upon exit.
	 * 
	 * If zero copy is performed (MSG_VMA_ZCOPY flag is returned), the buffer 
	 * is filled with a vma_datagram_t structure, holding as much fragments 
         * as `len' allows. The total size of all fragments is returned.
         * Otherwise the MSG_VMA_ZCOPY flag is not set and the buffer is filled
         * with actual data and it's size is returned (same as recvfrom())
	 * If no data was received the return value is zero.
	 * 
	 * NOTE: The returned datagram must be freed with free_datagram() after
	 * the application finished using it.
	 */
	int (*recvfrom_zcopy)(int s, void *buf, size_t len, int *flags,
                              struct sockaddr *from, socklen_t *fromlen);
	
	/**
	 * Frees a datagram received by recvfrom_zcopy() or held by receive callback.
	 * 
	 * @param s Socket from which the datagram was received.
	 * @param datagram_ids Array of datagram identifiers.
	 * @param count Number of datagrams in the array.
	 * @return 0 on success, -1 on failure
	 * 
	 * errno is set to: EINVAL - not a VMA offloaded socket
	 *                  ENOENT - the datagram was not received from `s'.
	 */
	int (*free_datagrams)(int s, void **datagram_ids, size_t count);


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
};


#define SO_VMA_GET_API				2800

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
 * Demo Usage
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
		myapp_processes_packet_func(my_iov, iov_sz, vma_info->datagram_id);
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
			vma_datagram_t* vma_datagram = (vma_datagram_t*)buf;
			myapp_processes_packet_func(vma_datagram->iov, vma_datagram->iov_sz, 
						     vma_datagram->datagram_id);
		}
	}
}



 * 
 * Process and Release VMA buffer
 *
myapp_processes_packet_func(
	struct iovec* iov, 
	size_t iov_sz, 
	void* datagram_id)
{
	myapp_processes_packet_func(.....);

	// Return zero copied datagram buffer back to VMA
	// Would be better to collect a bunch of buffers and return them all at once
	// which will save locks inside VMA
	vma_api->free_datagrams(s, &datagram_id, 1);
}


*/

#endif /* VMA_EXTRA_H */
