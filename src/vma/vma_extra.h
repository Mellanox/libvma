/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
#define SO_VMA_GET_API          2800
#define SO_VMA_USER_DATA        2801
#define SO_VMA_RING_ALLOC_LOGIC 2810
#define SO_VMA_RING_USER_MEMORY 2811
#define SO_VMA_FLOW_TAG         2820
#define SO_VMA_SHUTDOWN_RX      2821

enum {
	/* cmsg_level is SOL_SOCKET as protocol independent option
	 * cmsg_data has data in vma_cmsg_ioctl_user_alloc_t format
	 */
	CMSG_VMA_IOCTL_USER_ALLOC = 2900
};

/**
 * @brief This structure as an argument for vma_ioctl() call with
 *  @ref CMSG_VMA_IOCTL_USER_ALLOC to use user provided functions for
 *  internal pool allocation.
 * 
 * @note CMSG_VMA_IOCTL_USER_ALLOC must be called before the library
 * initialization that is done during first call of following functions
 * as socket(), epoll_create(), epoll_create1(), pipe().
 *
 * @param flags - set a internal memory pool to apply.
 * @param memalloc - ponter to the function to allocate memory.
 * @param memfree - ponter to the function to free previously allocated memory.
 */

enum {
	VMA_IOCTL_USER_ALLOC_FLAG_TX = (1 << 0),
	VMA_IOCTL_USER_ALLOC_FLAG_RX = (1 << 1)
};

struct __attribute__ ((packed)) vma_cmsg_ioctl_user_alloc_t {
	uint8_t flags;
	void* (*memalloc)(size_t);
	void (*memfree)(void *);
};

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


/************ SocketXtreme API types definition start***************/

typedef enum {
    VMA_SOCKETXTREME_PACKET 			= (1ULL << 32), /* New packet is available */
    VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED	= (1ULL << 33)  /* New connection is auto accepted by server */
} vma_socketxtreme_events_t;

/*
 * Represents  VMA buffer
 * Used in SocketXtreme extended API.
 */
struct vma_buff_t {
	struct vma_buff_t*	next;		/* next buffer (for last buffer next == NULL) */
	void*		payload;		/* pointer to data */
	uint16_t	len;			/* data length */
};

/**
 * Represents one VMA packet
 * Used in SocketXtreme extended API.
 */
struct vma_packet_desc_t {
	size_t			num_bufs;	/* number of packet's buffers */
	uint16_t		total_len;	/* total data length */
	struct vma_buff_t*	buff_lst;	/* list of packet's buffers */
	struct timespec 	hw_timestamp;	/* packet hw_timestamp */
};

/*
 * Represents VMA Completion.
 * Used in SocketXtreme extended API.
 */
struct vma_completion_t {
	/* Packet is valid in case VMA_SOCKETXTREME_PACKET event is set
	 */
	struct vma_packet_desc_t packet;
	/* Set of events
	 */
	uint64_t events;
	/* User provided data.
	 * By default this field has FD of the socket
	 * User is able to change the content using setsockopt()
	 * with level argument SOL_SOCKET and opname as SO_VMA_USER_DATA
	 */
	uint64_t                 user_data;
	/* Source address (in network byte order) set for:
	 * VMA_SOCKETXTREME_PACKET and VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED events
	 */
	struct sockaddr_in       src;
	/* Connected socket's parent/listen socket fd number.
	 * Valid in case VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is set.
	 */
	int 			listen_fd;
};

/************ SocketXtreme API types definition end ***************/

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

struct vma_rate_limit_t {
	uint32_t rate;				/* rate limit in Kbps */
	uint32_t max_burst_sz;			/* maximum burst size in bytes */
	uint16_t typical_pkt_sz;		/* typical packet size in bytes */
};

typedef int vma_ring_profile_key;

typedef enum {
	RING_LOGIC_PER_INTERFACE = 0,            //!< RING_LOGIC_PER_INTERFACE
	RING_LOGIC_PER_IP = 1,                   //!< RING_LOGIC_PER_IP
	RING_LOGIC_PER_SOCKET = 10,              //!< RING_LOGIC_PER_SOCKET
	RING_LOGIC_PER_USER_ID = 11,             //!< RING_LOGIC_PER_USER_ID
	RING_LOGIC_PER_THREAD = 20,              //!< RING_LOGIC_PER_THREAD
	RING_LOGIC_PER_CORE = 30,                //!< RING_LOGIC_PER_CORE
	RING_LOGIC_PER_CORE_ATTACH_THREADS = 31, //!< RING_LOGIC_PER_CORE_ATTACH_THREADS
	RING_LOGIC_LAST                          //!< RING_LOGIC_LAST
} ring_logic_t;

typedef enum {
	VMA_RING_ALLOC_MASK_RING_PROFILE_KEY = (1 << 0),
	VMA_RING_ALLOC_MASK_RING_USER_ID = (1 << 1),
	VMA_RING_ALLOC_MASK_RING_INGRESS = (1 << 2),
	VMA_RING_ALLOC_MASK_RING_ENGRESS = (1 << 3),
} vma_ring_alloc_logic_attr_comp_mask;

/**
 * @brief pass this struct to vma using setsockopt with @ref SO_VMA_RING_ALLOC_LOGIC
 * 	to set the allocation logic of this FD when he requests a ring.
 * 	@note ring_alloc_logic is a mandatory
 * @param comp_mask - what fields are read when processing this struct
 * 	see @ref vma_ring_alloc_logic_attr_comp_mask
 * @param ring_alloc_logic- allocation ratio to use
 * @param ring_profile_key - what ring profile to use - get the profile when
 * 	creating ring using @ref vma_add_ring_profile in extra_api
 * 	can only be set once
 * @param user_idx - when used RING_LOGIC_PER_USER_ID int @ref ring_alloc_logic
 * 	this is the user id to define. This lets you define the same ring for
 * 	few FD's regardless the interface\thread\core.
 * @param ingress - RX ring
 * @param engress - TX ring
 */
struct vma_ring_alloc_logic_attr {
	uint32_t	comp_mask;
	ring_logic_t	ring_alloc_logic;
	uint32_t	ring_profile_key;
	uint32_t	user_id;
	uint32_t	ingress:1;
	uint32_t	engress:1;
	uint32_t	reserved:30;
};

typedef enum {
	VMA_MODIFY_RING_CQ_MODERATION = (1 << 0),
	VMA_MODIFY_RING_CQ_ARM = (1 << 1),
} vma_modify_ring_mask;

struct vma_cq_moderation_attr {
	uint32_t cq_moderation_count;
	uint32_t cq_moderation_period_usec;
};

struct vma_cq_arm_attr {
};

/**
 * @param comp_mask - what fields should be read when processing this struct
 * 	see @ref vma_modify_ring_mask
 * @param ring_fd - ring fd
 */
struct vma_modify_ring_attr {
	uint32_t comp_bit_mask;
	int ring_fd;
	union {
		struct vma_cq_moderation_attr cq_moderation;
		struct vma_cq_arm_attr cq_arm;
	};
};

struct vma_packet_queue_ring_attr {
	uint32_t	comp_mask;
};

struct vma_external_mem_attr {
	uint32_t	comp_mask;
};

typedef enum {
	// for future use
	VMA_RING_ATTR_LAST
} vma_ring_type_attr_mask;

typedef enum {
	VMA_RING_PACKET,
	VMA_RING_EXTERNAL_MEM,
} vma_ring_type;

/**
 * @param comp_mask - what fields are read when processing this struct
 * 	see @ref vma_ring_type_attr_mask
 * @param ring_type - use cyclic buffer ring or default packets ring
 *
 */
struct vma_ring_type_attr {
	uint32_t	comp_mask;
	vma_ring_type	ring_type;
	union {
		struct vma_packet_queue_ring_attr	ring_pktq;
		struct vma_external_mem_attr		ring_ext;
	};
};

typedef enum {
	VMA_HW_PP_EN = (1 << 0),
	VMA_HW_PP_BURST_EN = (1 << 3),
} mlx_hw_device_cap;

struct dev_data {
	uint32_t vendor_id;
	uint32_t vendor_part_id;
	uint32_t device_cap; // mlx_hw_device_cap
};

struct hw_cq_data {
	void *buf;
	volatile uint32_t *dbrec;
	uint32_t cq_size;
	uint32_t cqe_size;
	uint32_t cqn;
	void *uar;
	// for notifications
	uint32_t *cons_idx;
};

struct hw_wq_data {
	void *buf;
	uint32_t wqe_cnt;
	uint32_t stride;
	volatile uint32_t *dbrec;
	struct hw_cq_data cq_data;
};

struct hw_rq_data {
	struct hw_wq_data wq_data;
	// TBD do we need it
	uint32_t *head;
	uint32_t *tail;
};

struct hw_sq_data {
	struct hw_wq_data wq_data;
	uint32_t sq_num;
	struct {
		void *reg;
		uint32_t size;
		uint32_t offset;
	} bf;
};

typedef enum {
	DATA_VALID_DEV,
	DATA_VALID_SQ,
	DATA_VALID_RQ,
} vma_mlx_hw_valid_data_mask;

struct vma_mlx_hw_device_data {
	uint32_t valid_mask; // see vma_mlx_hw_valid_data_mask
	struct dev_data dev_data;
	struct hw_sq_data sq_data;
	struct hw_rq_data rq_data;
};

typedef enum {
	VMA_EXTRA_API_REGISTER_RECV_CALLBACK         = (1 << 0),
	VMA_EXTRA_API_RECVFROM_ZCOPY                 = (1 << 1),
	VMA_EXTRA_API_FREE_PACKETS                   = (1 << 2),
	VMA_EXTRA_API_ADD_CONF_RULE                  = (1 << 3),
	VMA_EXTRA_API_THREAD_OFFLOAD                 = (1 << 4),
	VMA_EXTRA_API_DUMP_FD_STATS                  = (1 << 5),
	VMA_EXTRA_API_SOCKETXTREME_POLL              = (1 << 6),
	VMA_EXTRA_API_SOCKETXTREME_FREE_VMA_PACKETS  = (1 << 7),
	VMA_EXTRA_API_SOCKETXTREME_REF_VMA_BUFF      = (1 << 8),
	VMA_EXTRA_API_SOCKETXTREME_FREE_VMA_BUFF     = (1 << 9),
	VMA_EXTRA_API_GET_SOCKET_RINGS_NUM           = (1 << 10),
	VMA_EXTRA_API_GET_SOCKET_RINGS_FDS           = (1 << 11),
	VMA_EXTRA_API_GET_SOCKET_TX_RING_FD          = (1 << 12),
	VMA_EXTRA_API_GET_SOCKET_NETWORK_HEADER      = (1 << 13),
	VMA_EXTRA_API_GET_RING_DIRECT_DESCRIPTORS    = (1 << 14),
	VMA_EXTRA_API_ADD_RING_PROFILE               = (1 << 16),
	VMA_EXTRA_API_REGISTER_MEMORY_ON_RING        = (1 << 17),
	VMA_EXTRA_API_DEREGISTER_MEMORY_ON_RING      = (1 << 18),
	VMA_EXTRA_API_MODIFY_RING                    = (1 << 20),
	VMA_EXTRA_API_IOCTL                          = (1 << 21),
} vma_extra_api_mask;

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
(*vma_recv_callback_t)(int fd, size_t sz_iov, struct iovec iov[],
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
	 * @return 0 - success, -1 - error
	 * 
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
	int (*add_conf_rule)(const char *config_line);

	/*
	 * Create sockets on pthread tid as offloaded/not-offloaded.
	 * This does not affect existing sockets.
	 * Offloaded sockets are still subject to libvma.conf rules.
	 * @param offload 1 for offloaded, 0 for not-offloaded.
	 * @return 0 on success, or error code on failure.
	 */
	int (*thread_offload)(int offload, pthread_t tid);

	/**
	 * socketxtreme_poll() polls for VMA completions
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
	 * If VMA_SOCKETXTREME_PACKET flag is enabled in vma_completion_t.events field
	 * the completion points to incoming packet descriptor that can be accesses
	 * via vma_completion_t.packet field.
	 * Packet descriptor points to VMA buffers that contain data scattered
	 * by HW, so the data is deliver to application with zero copy.
	 * Notice: after application finished using the returned packets
	 * and their buffers it must free them using socketxtreme_free_vma_packets(),
	 * socketxtreme_free_vma_buff() functions.
	 *
	 * If VMA_SOCKETXTREME_PACKET flag is disabled vma_completion_t.packet field is
	 * reserved.
	 *
	 * In addition to packet arrival event (indicated by VMA_SOCKETXTREME_PACKET flag)
	 * VMA also reports VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event and standard
	 * epoll events via vma_completion_t.events field.
	 * VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is reported when new connection is
	 * accepted by the server.
	 * When working with socketxtreme_poll() new connections are accepted
	 * automatically and accept(listen_socket) must not be called.
	 * VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is reported for the new
	 * connected/child socket (vma_completion_t.user_data refers to child socket)
	 * and EPOLLIN event is not generated for the listen socket.
	 * For events other than packet arrival and new connection acceptance
	 * vma_completion_t.events bitmask composed using standard epoll API
	 * events types.
	 * Notice: the same completion can report multiple events, for example
	 * VMA_SOCKETXTREME_PACKET flag can be enabled together with EPOLLOUT event,
	 * etc...
	 *
	 * * errno is set to: EOPNOTSUPP - socketXtreme was not enabled during configuration time.
	 */
	int (*socketxtreme_poll)(int fd, struct vma_completion_t* completions, unsigned int ncompletions, int flags);

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
	 * Returns FDs of the RX rings that are associated with the socket.
	 *
	 * This function gets socket FD + int array + array size and populates
	 * the array with FD numbers of the rings that are associated
	 * with the socket.
	 *
	 * @param fd File Descriptor number.
	 * @param ring_fds Array of ring fds
	 * @param ring_fds_sz Size of the array
	 * @return On success, return the number populated array entries.
	 * 	   On error, -1 is returned.
	 *
	 * errno is set to: EINVAL - not a VMA offloaded fd + TBD
	 */
	int (*get_socket_rings_fds)(int fd, int *ring_fds, int ring_fds_sz);

	/**
	 * Returns the ring FD of the TX rings used by this socket.
	 * should be used after connect or joining a MC group.
	 * @param sock_fd - UDP socket fd
	 * @param to - the destination the socket is connected to.
	 * @param tolen - so len
	 * @return ring fd on success -1 on failure (e.g. no ring, non offloaded fd)
	 * @note @ref get_socket_rings_fds returns the RX ring fd
	 * errno is set to: EINVAL - not a VMA offloaded fd
	 * 		    ENODATA - no rings fds available
	 */
	int (*get_socket_tx_ring_fd)(int sock_fd, struct sockaddr *to, socklen_t tolen);

	/**
	 * Frees packets received by socketxtreme_poll().
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
	 *   reference count and only buffers with reference count zero are deallocated.
	 *   Notice:
	 *   - Application can increase buffer reference count,
	 *     in order to hold the buffer even after socketxtreme_free_vma_packets()
	 *     was called for the buffer, using socketxtreme_ref_vma_buff().
	 *   - Application is responsible to free buffers, that
	 *     couldn't be deallocated during socketxtreme_free_vma_packets() due to
	 *     non zero reference count, using socketxtreme_free_vma_buff() function.
	 *
	 * errno is set to: EINVAL - NULL pointer is provided.
	 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
	 */
	int (*socketxtreme_free_vma_packets)(struct vma_packet_desc_t *packets, int num);

	/* This function increments the reference count of the buffer.
	 * This function should be used in order to hold the buffer
	 * even after socketxtreme_free_vma_packets() call.
	 * When buffer is not needed any more it should be freed via
	 * socketxtreme_free_vma_buff().
	 *
	 * @param buff Buffer to update.
	 * @return On success, return buffer's reference count after the change
	 * 	   On errors -1 is returned
	 *
	 * errno is set to: EINVAL - NULL pointer is provided.
	 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
	 */
	int (*socketxtreme_ref_vma_buff)(struct vma_buff_t *buff);

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
	 * errno is set to: EINVAL - NULL pointer is provided.
	 *                  EOPNOTSUPP - socketXtreme was not enabled during configuration time.
	 */
	int (*socketxtreme_free_vma_buff)(struct vma_buff_t *buff);

	/*
	 * Dump fd statistics using VMA logger.
	 * @param fd to dump, 0 for all open fds.
	 * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
	 * @return 0 on success, or error code on failure.
	 *
	 * errno is set to: EOPNOTSUPP - Function is not supported when socketXtreme is enabled.
	 */
	int (*dump_fd_stats)(int fd, int log_level);

	/**
	 * add a ring profile to VMA ring profile list. you can use this
	 * to create advacned rings like MP_RQ ring
	 * the need to pass vma the ring profile using the fd's setsockopt
	 * @param profile the profile to add to the list
	 * @param key - the profile key
	 * @return 0 on success -1 on failure
	 */
	int (*vma_add_ring_profile)(struct vma_ring_type_attr *profile, int *key);

	/**
	 * get the socket's network header created by VMA
	 * @param fd - the socket's fd
	 * @param ptr - pointer to write the data to. can be NULL see notes
	 * @param len - IN\OUT parameter
	 * 	IN - len given by user
	 * 	OUT- len used by header
	 * @return 0 on success -1 on error
	 * 	errno EINVAL - bad fd
	 * 	errno ENOBUFS - ptr is too small
	 * 	errno ENOTCONN - header no available since socket is not
	 * 		ofloaded or not connected
	 * @note this function should be called for connected socket
	 * @note calling with ptr NULL will update the len with the size needed
	 * 	by VMA so application will allocate the exact needed space
	 * @note application can:
	 * 	call twice once with ptr == NULL and get the size needed to allocate
	 * 	and call again to get the data.
	 * 	if application called with big enough buffer vma will update the
	 * 	size actually used.
	 */
	int (*get_socket_network_header)(int fd, void *ptr, uint16_t *len);

	/**
	 * get the HW descriptors created by VMA
	 * @param fd - the ring fd
	 * @param data - result see @ref vma_mlx_hw_device_data
	 * @return -1 on failure 0 on success
	 */
	int (*get_ring_direct_descriptors)(int fd,
					   struct vma_mlx_hw_device_data *data);

	/**
	 * register memory to use on a ring.
	 * @param fd - the ring fd see @ref socketxtreme_get_socket_rings_fds
	 * @param addr - the virtual address to register
	 * @param length - hte length of addr
	 * @param key - out parameter to use when accessing this memory
	 * @return 0 on success, -1 on failure
	 *
	 * @note in vma_extra_api ring is associated with device, although you
	 * can use the key in other rings using the same port we decided to leave
	 * the ring fd as the bridge in the "extra" convention instead of
	 * using an opaque ib_ctx or src ip (that can cause routing issues).
	 */
	int (*register_memory_on_ring)(int fd, void *addr, size_t length,
				       uint32_t *key);

	/**
	 * deregister the addr that was previously registered in this ring
	 * @return 0 on success, -1 on failure
	 *
	 * @note - this function doens't free the memory
	 */
	int (*deregister_memory_on_ring)(int fd, void *addr, size_t length);

	/**
	 * perform ring modifications
	 *
	 * @param mr_data ring modification parameters
	 *
	 * @return 0 on success -1 on failure 1 on busy
	 */
	int (*vma_modify_ring)(struct vma_modify_ring_attr *mr_data);

	/**
	 * Used to identify which methods were initialized by VMA as part of vma_get_api().
	 * The value content is based on vma_extra_api_mask enum.
	 * Order of fields in this structure should not be changed to keep abi compatibility.
	 */
	uint64_t vma_extra_supported_mask;

	/**
	 * This function allows to communicate with library using extendable protocol
	 * based on struct cmshdr.
	 *
	 * Ancillary data is a sequence of cmsghdr structures with appended data.
	 * The sequence of cmsghdr structures should never be accessed directly.
	 * Instead, use only the following macros: CMSG_ALIGN, CMSG_SPACE, CMSG_DATA,
	 * CMSG_LEN.
	 *
	 * @param cmsg_hdr - point to control message
	 * @param cmsg_len - the byte count of the ancillary data,
	 *                   which contains the size of the structure header.
	 *
	 * @return -1 on failure and 0 on success
	 */
	int (*ioctl)(void *cmsg_hdr, size_t cmsg_len);
};

/**
 * Retrieve VMA extended API.
 * This function can be called as an alternative to getsockopt() call
 * when library is preloaded using LD_PRELOAD
 * getsockopt() call should be used in case application loads library
 * using dlopen()/dlsym().
 *
 * @return Pointer to the VMA Extended Socket API, of NULL if VMA not found.
 */
static inline struct vma_api_t* vma_get_api()
{
	struct vma_api_t *api_ptr = NULL;
	socklen_t len = sizeof(api_ptr);

	/* coverity[negative_returns] */
	int err = getsockopt(-1, SOL_SOCKET, SO_VMA_GET_API, &api_ptr, &len);
	if (err < 0) {
		return NULL;
	}
	return api_ptr;
}

#endif /* VMA_EXTRA_H */
