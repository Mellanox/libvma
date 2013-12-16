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


#ifndef VTYPES_H
#define VTYPES_H

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/kernel.h>

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
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

#define NOT_IN_USE(a)			((void)(a))


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


#define IPOIB_HW_ADDR_PRINT_FMT_16		"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X"
#define IPOIB_HW_ADDR_PRINT_ADDR_16(__addr) \
	((unsigned char *)(__addr))[0],((unsigned char *)(__addr))[1],   \
	((unsigned char *)(__addr))[2],((unsigned char *)(__addr))[3],   \
	((unsigned char *)(__addr))[4],((unsigned char *)(__addr))[5],   \
	((unsigned char *)(__addr))[6],((unsigned char *)(__addr))[7],   \
	((unsigned char *)(__addr))[8],((unsigned char *)(__addr))[9],   \
	((unsigned char *)(__addr))[10],((unsigned char *)(__addr))[11], \
	((unsigned char *)(__addr))[12],((unsigned char *)(__addr))[13], \
	((unsigned char *)(__addr))[14],((unsigned char *)(__addr))[15]

#define IPOIB_HW_ADDR_PRINT_FMT		"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X"
#define IPOIB_HW_ADDR_PRINT_ADDR(__addr) \
	((unsigned char *)(__addr))[0],((unsigned char *)(__addr))[1],   \
	((unsigned char *)(__addr))[2],((unsigned char *)(__addr))[3],   \
	((unsigned char *)(__addr))[4],((unsigned char *)(__addr))[5],   \
	((unsigned char *)(__addr))[6],((unsigned char *)(__addr))[7],   \
	((unsigned char *)(__addr))[8],((unsigned char *)(__addr))[9],   \
	((unsigned char *)(__addr))[10],((unsigned char *)(__addr))[11], \
	((unsigned char *)(__addr))[12],((unsigned char *)(__addr))[13], \
	((unsigned char *)(__addr))[14],((unsigned char *)(__addr))[15], \
	((unsigned char *)(__addr))[16],((unsigned char *)(__addr))[17], \
	((unsigned char *)(__addr))[18],((unsigned char *)(__addr))[19]

#define ETH_HW_ADDR_SSCAN_FMT 		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define ETH_HW_ADDR_SSCAN(__addr) \
	&(__addr[0]),&(__addr[1]),   \
	&(__addr[2]),&(__addr[3]),   \
	&(__addr[4]),&(__addr[5])


#define IPOIB_HW_ADDR_SSCAN_FMT		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define IPOIB_HW_ADDR_SSCAN(__addr) \
	&(__addr[0]),&(__addr[1]),   \
	&(__addr[2]),&(__addr[3]),   \
	&(__addr[4]),&(__addr[5]),   \
	&(__addr[6]),&(__addr[7]),   \
	&(__addr[8]),&(__addr[9]),   \
	&(__addr[10]),&(__addr[11]), \
	&(__addr[12]),&(__addr[13]), \
	&(__addr[14]),&(__addr[15]), \
	&(__addr[16]),&(__addr[17]), \
	&(__addr[18]),&(__addr[19])

#define ETH_HDR_LEN			(ETH_HLEN)
#define ETH_VLAN_HDR_LEN		(ETH_HDR_LEN + sizeof(struct vlanhdr))
#define GRH_HDR_LEN			(sizeof(struct ibv_grh))
#define IPOIB_HDR_LEN			(sizeof(struct ipoibhdr))
#define IPOIB_HEADER			((uint32_t)0x08000000)
#define IPOIB_ARP_HEADER		((uint32_t)0x08060000)
#define IPOIB_HW_ADDR_LEN		20
#define IPV4_VERSION			0x4
#define IPV4_HDR_LEN			(sizeof(struct iphdr))
#define IPV4_HDR_LEN_WORDS		(IPV4_HDR_LEN / sizeof(uint32_t))
#define IPV4_IGMP_HDR_LEN		(IPV4_HDR_LEN + sizeof(uint32_t))
#define IPV4_IGMP_HDR_LEN_WORDS		(IPV4_IGMP_HDR_LEN / sizeof(uint32_t))
#define IGMP_HDR_LEN			(sizeof(struct igmphdr))
#define IGMP_HDR_LEN_WORDS		(IGMP_HDR_LEN / sizeof(uint32_t))
#define DONT_FRAGMENT_FLAG		0x4000
#define MORE_FRAGMENTS_FLAG		0x2000
#define FRAGMENT_OFFSET			0x1FFF
#define MAX_APP_ID_LENGHT		64

#define INPORT_ANY			((uint16_t)0x0000)

#define MCE_IMM_DATA_MASK_MC_TX_LOOP_DISABLED	(1 << 0)

#define BROADCAST_IP "255.255.255.255"

#ifndef ARPHRD_INFINIBAND
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#endif

struct __attribute__ ((packed)) ipoibhdr {
	uint32_t	ipoib_header;
};

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
