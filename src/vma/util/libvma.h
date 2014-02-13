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


#ifndef _LIBVMA_H
#define _LIBVMA_H

#include <netinet/in.h>

#include "vtypes.h"

/*
 * VMA specific includes
 */
#include "lwip/netif.h"


/* --------------------------------------------------------------------- */
/* library static and global variables                                   */
/* --------------------------------------------------------------------- */

/* max string length to store any IPv4/IPv6 address */
#define MAX_ADDR_STR_LEN 49
#define MAX_IF_NAME_LEN 10
#define MAX_CONF_FILE_ENTRY_STR_LEN 512

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	ROLE_TCP_SERVER,
	ROLE_TCP_CLIENT,
	ROLE_UDP_RECEIVER,
	ROLE_UDP_SENDER,
	ROLE_UDP_CONNECT
} role_t;

typedef enum {
	TRANS_OS = 1,
	TRANS_VMA,
	TRANS_SDP,
	TRANS_SA,
	TRANS_ULP,
	TRANS_DEFAULT
} transport_t;

typedef enum {
	PROTO_UNDEFINED,
	PROTO_UDP,
	PROTO_TCP,
	PROTO_ALL
} in_protocol_t;

typedef enum {
	DEV_CLONE,
	DEV_REPLACE
} dev_conf_mode_t;

typedef enum {
	IN_ADDR_DHCP,
	IN_ADDR_STATIC
} in_addr_alloc_mode_t;

typedef enum {
	MAC_AUTO_GEN,
	MAC_MANUAL
} mac_alloc_mode_t;


/* some state to string functions */
static inline const char *__vma_get_transport_str(transport_t transport )
{
	switch (transport) {
	case TRANS_OS:
		return "OS";
		break;
	case TRANS_VMA:
		return "VMA";
		break;
	case TRANS_SDP:
		return "SDP";
		break;
	case TRANS_SA:
		return "SA";
		break;
	case TRANS_ULP:
		return "ULP";
		break;
	case TRANS_DEFAULT:
		return "DEFAULT";
		break;
	}
	return ( "UNKNOWN-TRANSPORT" );
}

/* some state to string functions */
static inline const char *__vma_get_protocol_str(in_protocol_t protocol)
{
	switch (protocol) {
	case PROTO_UNDEFINED: 	return "UNDEFINED";
	case PROTO_UDP:		return "UDP";
	case PROTO_TCP:		return "TCP";
	case PROTO_ALL:		return "*";
	default:
		break;
	}
	return ("unknown-protocol");
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
/* some state to string functions */
static inline const char *__vma_get_dev_conf_mode_str(dev_conf_mode_t mode )
{
	switch ( mode ) {
	case DEV_CLONE:
		return "clone";
		break;
	case DEV_REPLACE:
		return "replace";
		break;
	}
	return ( "unknown-mode" );
}

/* some state to string functions */
static inline const char *__vma_get_dev_address_alloc_mode_str(
		in_addr_alloc_mode_t mode )
{
	switch ( mode ) {
	case IN_ADDR_DHCP:
		return "dhcp";
		break;
	case IN_ADDR_STATIC:
		return "static";
		break;
	}
	return ( "unknown-mode" );
}
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

static inline const char *__vma_get_role_str(int role)
{
	switch (role) {
		case ROLE_TCP_CLIENT:
			return("tcp_client");
			break;
		case ROLE_TCP_SERVER:
			return("tcp_server");
			break;
		case ROLE_UDP_RECEIVER:
			return("udp_receiver");
			break;
		case ROLE_UDP_SENDER:
			return("udp_sender");
			break;
		case ROLE_UDP_CONNECT:
			return("udp_connect");
			break;
		default:
			break;
	}
	return("unknown role");
}

struct dbl_lst_node
{
	struct dbl_lst_node *prev, *next;
	void *data;
};

struct dbl_lst
{
	struct dbl_lst_node *head;
	struct dbl_lst_node *tail;
};

struct address_port_rule
{
	int match_by_addr;			/* if 0 ignore address match		*/
	struct in_addr ipv4;			/* IPv4 address for mapping		*/
	unsigned char prefixlen;		/* length of CIDR prefix (ie /24)	*/
	int match_by_port;			/* if 0 ignore port match		*/
	unsigned short sport, eport;		/* start port - end port, inclusive	*/
};

/* data structure for holding address family mapping rules */
/* note we filter non relevant programs during parsing ...  */
struct use_family_rule
{
	struct address_port_rule first;
	struct address_port_rule second;
	unsigned char use_second;
	transport_t target_transport;		/* if match - use this transport	*/
	in_protocol_t protocol;			/* protocol family for mapping		*/
};

/* data structure for holding the devices vma will handle */
struct vma_device
{
	dev_conf_mode_t conf_mode;		/* clone or replace insterface		*/
	u8_t hw_addr[NETIF_MAX_HWADDR_LEN];	/* interface physical address		*/
	u8_t hw_addr_len;			/* interface physical address length	*/
	in_addr_alloc_mode_t in_addr_alloc_mode;/* static or dhcp			*/
	mac_alloc_mode_t mac_alloc_mode;	/* manual or autogen			*/
	struct in_addr ipv4;			/* interface IPv4 address 		*/
	unsigned char prefixlen;		/* prefix len of interface IPv4 address */
	char if_name[MAX_IF_NAME_LEN + 1];	/*base interface name			*/
};

struct instance_id
{
	char *prog_name_expr;
	char *user_defined_id;
};

/* data structure for holding the instances descriptors */
struct instance
{
	struct instance_id id;			/* instance id				*/
	struct dbl_lst tcp_clt_rules_lst;	/* tcp client's rules list		*/
	struct dbl_lst tcp_srv_rules_lst;	/* tcp server's rules list		*/
	struct dbl_lst udp_snd_rules_lst;	/* udp sender rules list		*/
	struct dbl_lst udp_rcv_rules_lst;	/* udp receiver rules list		*/
	struct dbl_lst udp_con_rules_lst;	/* udp connect rules list		*/
};

extern struct dbl_lst __instance_list;
extern int __vma_min_level;

#define VMA_NETMASK(n) ((n == 0) ? 0 : ~((1UL<<(32 - n)) - 1))
#define IF_NAME_LEN 10

/* match.cpp */
transport_t __vma_match_tcp_client(transport_t my_transport, const char *app_id, const struct sockaddr *sin_first, const socklen_t  sin_addrlen_first, const struct sockaddr *sin_second, const socklen_t  sin_addrlen_second);

transport_t __vma_match_tcp_server(transport_t my_transport, const char *app_id, const struct sockaddr *sin, const socklen_t  addrlen);

transport_t __vma_match_udp_sender(transport_t my_transport, const char *app_id, const struct sockaddr * sin, const socklen_t addrlen);

transport_t __vma_match_udp_receiver(transport_t my_transport, const char *app_id, const struct sockaddr * sin, const socklen_t addrlen);

transport_t __vma_match_udp_connect(transport_t my_transport, const char *app_id, const struct sockaddr *sin_first, const socklen_t  sin_addrlen_first, const struct sockaddr *sin_second, const socklen_t  sin_addrlen_second);

/* config.c */
int __vma_config_empty();

int __vma_parse_config_file(const char *config_file);

int __vma_parse_config_line(char *config_line);

void __vma_print_conf_file(struct dbl_lst conf_lst);

void __vma_free_resources();

int __vma_match_program_name(struct instance *instance);

int __vma_match_user_defined_id(struct instance *instance, const char *app_id);

transport_t __vma_match_by_program(in_protocol_t my_protocol, const char *app_id);

/* log.c */
#if 0
static inline
void __vma_log(
	int level,
	char *format,
	... )
{
	NOT_IN_USE(level)
	vlog_
};
#endif

#define __vma_log(level, format, args...) \
	printf(format, ##args)

static inline int __vma_log_get_level()
{
	return __vma_min_level;
}

static inline void __vma_log_set_min_level(int level )
{
	__vma_min_level= level;
};

//TODO AlexV: implement this function
static inline int __vma_log_set_log_stderr() {return 0;};

//TODO AlexV: implement this function
static inline int __vma_log_set_log_syslog() {return 0;};

//TODO AlexV: implement this function
static inline int __vma_log_set_log_file(char *filename )
{
	NOT_IN_USE(filename);
	return 0;
};

int __vma_sockaddr_to_vma(const struct sockaddr *addr_in, socklen_t addrlen, struct sockaddr_in *addr_out, int *was_ipv6 );

#ifdef __cplusplus
};
#endif

#endif
