/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef VTYPES_H
#define VTYPES_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/kernel.h>
#include <byteswap.h>

#include "utils/types.h"
#include "utils/bullseye.h"
#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

#define likely(x)			__builtin_expect(!!(x), 1)
#define unlikely(x)			__builtin_expect(!!(x), 0)

// Check if given IP address is in a specific ip class / range
#define ZERONET_N(a)			(((long int)(a)) == (long int)(htonl(0x00000000)))
#define LOOPBACK_N(a)			(((long int)(a) & htonl(0xff000000)) == htonl(0x7f000000))
#define IN_CLASSD_N(a)			(((long int)(a) & htonl(0xf0000000)) == htonl(0xe0000000))
#define IN_CLASSE_N(a)			(((long int)(a) & htonl(0xffffffff)) == htonl(0xffffffff))
#define	IN_MULTICAST_N(a)		IN_CLASSD_N(a)
#define IS_BROADCAST_N(a)		IN_CLASSE_N(a)


// printf formating when IP is in network byte ordering (for LITTLE_ENDIAN)
#define NETWORK_IP_PRINTQUAD_LITTLE_ENDIAN(ip)     		(uint8_t)((ip)&0xff), (uint8_t)(((ip)>>8)&0xff),(uint8_t)(((ip)>>16)&0xff),(uint8_t)(((ip)>>24)&0xff)

// printf formating when IP is in host byte ordering (for LITTLE_ENDIAN)
#define HOST_IP_PRINTQUAD_LITTLE_ENDIAN(ip)     		(uint8_t)(((ip)>>24)&0xff),(uint8_t)(((ip)>>16)&0xff),(uint8_t)(((ip)>>8)&0xff),(uint8_t)((ip)&0xff)



#if __BYTE_ORDER == __LITTLE_ENDIAN

/* The host byte order is the same as network byte order, so these functions are all just identity.  */

#  define NIPQUAD(ip)     		NETWORK_IP_PRINTQUAD_LITTLE_ENDIAN(ip)
#  define HIPQUAD(ip)     		HOST_IP_PRINTQUAD_LITTLE_ENDIAN(ip)

#else
# if __BYTE_ORDER == __BIG_ENDIAN

#  define NIPQUAD(ip)     		HOST_IP_PRINTQUAD_LITTLE_ENDIAN(ip)
#  define HIPQUAD(ip)     		NETWORK_IP_PRINTQUAD_LITTLE_ENDIAN(ip)

# endif
#endif

#define ETH_HW_ADDR_PRINT_FMT 		"%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_HW_ADDR_PRINT_ADDR(__addr) \
	((unsigned char *)(__addr))[0], ((unsigned char *)(__addr))[1], \
	((unsigned char *)(__addr))[2], ((unsigned char *)(__addr))[3], \
	((unsigned char *)(__addr))[4], ((unsigned char *)(__addr))[5]

#define ETH_HW_ADDR_SSCAN_FMT 		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define ETH_HW_ADDR_SSCAN(__addr) \
	&(__addr[0]),&(__addr[1]),   \
	&(__addr[2]),&(__addr[3]),   \
	&(__addr[4]),&(__addr[5])

#define ETH_HDR_LEN			(ETH_HLEN)
#define ETH_VLAN_HDR_LEN		(ETH_HDR_LEN + sizeof(struct vlanhdr))
#define IPV4_VERSION			0x4
#define IPV4_HDR_LEN_WITHOUT_OPTIONS (sizeof(struct iphdr)) // Ip Header without any options
#define DONT_FRAGMENT_FLAG		0x4000
#define MORE_FRAGMENTS_FLAG		0x2000
#define FRAGMENT_OFFSET			0x1FFF
#define MAX_APP_ID_LENGHT		64

#define INPORT_ANY			((uint16_t)0x0000)

#define MCE_IMM_DATA_MASK_MC_TX_LOOP_DISABLED	(1 << 0)

#define BROADCAST_IP "255.255.255.255"

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1            /* Ethernet 10Mbps                   */
#endif

#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772            /* Loopback device                   */
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#endif

struct __attribute__((packed)) vlanhdr {
	uint16_t	h_vlan_TCI;                /* Encapsulates priority and VLAN ID */
	uint16_t	h_vlan_encapsulated_proto; /* packet type ID field (or len) */
};

#include <sys/epoll.h>
//support for RH 5.7 and older OS
#ifndef EPOLLHUP
#define EPOLLHUP    0x010
#endif
#ifndef EPOLLRDHUP
#define EPOLLRDHUP  0x2000
#endif

#endif //VTYPES_H
