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


/*
 * system includes
 */
#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */


#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <vlogger/vlogger.h>

/*
 * VMA specific includes
 */
#include "libvma.h"

// debugging macros
#define MODULE_NAME "match:"

#define match_logpanic             __log_panic
#define match_logerr               __log_err
#define match_logwarn              __log_warn
#define match_loginfo              __log_info
#define match_logdbg               __log_dbg
#define match_logfunc              __log_func
#define match_logfuncall           __log_funcall

/* --------------------------------------------------------------------- */
/* library static and global variables                                   */
/* --------------------------------------------------------------------- */
extern char *program_invocation_name, *program_invocation_short_name;

static void free_dbl_lst(struct dbl_lst *dbl_lst)
{
	struct dbl_lst_node *node, *tmp;

	node = dbl_lst->head;
	while (node) {
		tmp = node->next;
		if (node->data)
			free(node->data);

		free(node);
		node = tmp;
	}
	dbl_lst->head = NULL;
	dbl_lst->tail = NULL;
}

static void free_instance_content(struct instance *instance)
{
	if (!instance)
		return;

	/* free srever's rules */
	free_dbl_lst(&instance->tcp_srv_rules_lst);

	/*free client's rules */
	free_dbl_lst(&instance->tcp_clt_rules_lst);

	/* free the instance id content*/
	if (instance->id.prog_name_expr)
		free(instance->id.prog_name_expr);

	if (instance->id.user_defined_id)
		free(instance->id.user_defined_id);
	free(instance);
}

void __vma_free_resources()
{
	struct dbl_lst_node *node, *tmp;

	/* free the instances */
	node = __instance_list.head;
	while (node) {
		tmp = node->next;
		free_instance_content((struct instance *)node->data);
		free(node);
		node = tmp;
	}
	__instance_list.head = NULL;
	__instance_list.tail = NULL;
}

static void get_rule_str(struct use_family_rule *rule, char *buf, size_t len)
{
	if (!rule) {
		snprintf(buf, len, " ");
		return;
	}

	char addr_buf[MAX_ADDR_STR_LEN];
	char ports_buf[16];
	const char *target = __vma_get_transport_str(rule->target_transport);
	const char *protocol = __vma_get_protocol_str(rule->protocol);

	/* TODO: handle IPv6 in rule */
	if (rule->match_by_addr) {
		if (rule->prefixlen != 32)
			sprintf(addr_buf, "%s/%d", inet_ntoa(rule->ipv4), rule->prefixlen );
		else
			sprintf(addr_buf, "%s", inet_ntoa(rule->ipv4));
	} else
		strcpy(addr_buf, "*");

	if (rule->match_by_port)
		if (rule->eport > rule->sport)
			sprintf(ports_buf, "%d-%d", rule->sport, rule->eport);
		else
			sprintf(ports_buf, "%d", rule->sport);
	else
		sprintf(ports_buf, "*");

	snprintf(buf, len, "use %s %s %s:%s", target, protocol, addr_buf, ports_buf);
}

static void get_instance_id_str(struct instance *instance, char *buf, size_t len)
{
	if (instance)
		snprintf(buf, len, "application-id %s %s", instance->id.prog_name_expr,  instance->id.user_defined_id);
	else
		snprintf(buf, len, " ");
}

static void  print_rule(struct use_family_rule *rule)
{
	char rule_str[MAX_CONF_FILE_ENTRY_STR_LEN] = " ";

	if(rule) {
		get_rule_str(rule, rule_str, MAX_CONF_FILE_ENTRY_STR_LEN);
	}
	match_logdbg("\t\t\t%s", rule_str);
}

static void  print_instance_id_str(struct instance *instance)
{
	char instance_str[MAX_CONF_FILE_ENTRY_STR_LEN] = " ";

	if(instance) {
		get_instance_id_str(instance, instance_str, MAX_CONF_FILE_ENTRY_STR_LEN);
	}
	match_logdbg("%s:", instance_str);
}

static void print_rules_lst(struct dbl_lst_node *curr_node)
{
	while (curr_node) {
		struct use_family_rule *rule = (struct use_family_rule *)curr_node->data;
		print_rule(rule);
		curr_node = curr_node->next;
	}
}

static void print_instance_conf(struct instance *instance)
{
	if (!instance)
		match_logdbg("\tinstance is empty");
	else {
		print_instance_id_str(instance);

		struct dbl_lst_node *node = instance->tcp_srv_rules_lst.head;
		match_logdbg("\ttcp_server's rules:");
		print_rules_lst(node);

		node = instance->tcp_clt_rules_lst.head;
		match_logdbg("\ttcp_clinet's rules:");
		print_rules_lst(node);

		node = instance->udp_rcv_rules_lst.head;
		match_logdbg("\tudp receiver rules:");
		print_rules_lst(node);

		node = instance->udp_snd_rules_lst.head;
		match_logdbg("\tudp sender rules:");
		print_rules_lst(node);

		match_logdbg(" ");
	}
}

void __vma_print_conf_file(struct dbl_lst conf_lst)
{
	struct dbl_lst_node *node = conf_lst.head;

	match_logdbg("Configuration File:");
	while (node) {
		struct instance *instance = (struct instance *)node->data;
		print_instance_conf(instance);
		node = node->next;
	}
}

/* return 0 if the addresses match */
static inline int match_ipv4_addr(struct use_family_rule *rule, const struct sockaddr_in *sin)
{
	// Added netmask on rule side to avoid user mistake when configuring ip rule: 1.1.1.x/24 instead of 1.1.1.0/24
	match_logdbg("rule ip address:%d.%d.%d.%d, socket ip address:%d.%d.%d.%d ", NIPQUAD(rule->ipv4.s_addr & htonl(VMA_NETMASK(rule->prefixlen))), NIPQUAD(sin->sin_addr.s_addr & htonl(VMA_NETMASK(rule->prefixlen))));
	return ( (rule->ipv4.s_addr & htonl(VMA_NETMASK(rule->prefixlen))) != (sin->sin_addr.s_addr & htonl(VMA_NETMASK(rule->prefixlen))));
}

static int match_ip_addr_and_port(transport_t my_transport, struct use_family_rule *rule, const struct sockaddr *addr_in, const socklen_t addrlen)
{
	const struct sockaddr_in *sin = ( const struct sockaddr_in * )addr_in;
	const struct sockaddr_in6 *sin6 = ( const struct sockaddr_in6 * )addr_in;
	struct sockaddr_in tmp_sin;
	unsigned short port;
	int match = 1;
	char addr_buf[MAX_ADDR_STR_LEN];
	const char *addr_str;
	char rule_str[512];

	if ( g_vlogger_level >= VLOG_DEBUG ){
		if ( sin6->sin6_family == AF_INET6 ) {
			addr_str = inet_ntop( AF_INET6, (void *)&(sin6->sin6_addr), addr_buf, MAX_ADDR_STR_LEN);
			port = ntohs(sin6->sin6_port);
		} else {
			addr_str = inet_ntop( AF_INET, (void *)&(sin->sin_addr), addr_buf, MAX_ADDR_STR_LEN);
			port = ntohs(sin->sin_port);
		}
		if (addr_str == NULL)
			addr_str = "INVALID_ADDR";

		get_rule_str(rule, rule_str, sizeof(rule_str));
		match_logdbg("MATCH: matching %s:%d to %s => ", addr_str, port, rule_str);
	}

	/* We currently only support IPv4 and IPv4 embedded in IPv6 */
	if ( rule->match_by_port ) {
		if ( sin6->sin6_family == AF_INET6 )
			port = ntohs( sin6->sin6_port );
		else
			port = ntohs( sin->sin_port );

		if ((port < rule->sport) || (port > rule->eport)) {
			match_logdbg("NEGATIVE MATCH by port range" );
			match = 0;
		}
	}

	if ( match && rule->match_by_addr ) {
		if ( __vma_sockaddr_to_vma( addr_in, addrlen, &tmp_sin, NULL ) ||
			  match_ipv4_addr(rule, &tmp_sin)) {
			match_logdbg("NEGATIVE MATCH by address" );
			match = 0;
		}
	}

	if (match) {
		if (!(rule->target_transport == TRANS_OS || rule->target_transport == TRANS_ULP || rule->target_transport == my_transport)) {
			match_logdbg("NEGATIVE MATCH by transport" );
			match = 0;
		}
		else {
			match_logdbg("POSITIVE MATCH");
		}
	}

	return match;
}

/* return 1 on match */
int __vma_match_program_name(struct instance *instance)
{
	if (!instance)
		return 1;

	return !fnmatch( instance->id.prog_name_expr, program_invocation_short_name, 0);
}

/* return 1 on match */
int __vma_match_user_defined_id(struct instance *instance, const char *app_id)
{
	int ret_val = 0;

	if (!instance || !instance->id.user_defined_id || !app_id )
		ret_val = 1;
	else if (!strcmp(app_id, "*"))
		ret_val = 1;
	else if (!strcmp(instance->id.user_defined_id, "*"))
		ret_val = 1;
	else
		ret_val = !strcmp(app_id, instance->id.user_defined_id);

	return ret_val;
}

static transport_t get_family_by_first_matching_rule(transport_t my_transport, const struct sockaddr *sin, const socklen_t addrlen, struct dbl_lst rules_lst)
{
	struct dbl_lst_node *node;

	for (node = rules_lst.head; node != NULL; node = node->next) {
		/* first rule wins */
		struct use_family_rule *rule = (struct use_family_rule *)node->data;
		if (rule)
			if (match_ip_addr_and_port(my_transport, rule, sin, addrlen))
				return rule->target_transport;
	}

	match_logdbg("No matching rule. Using VMA (default)" );
	return TRANS_VMA; //No matching rule or no rule at all. Don't continue to next application-id
}

static transport_t get_family_by_instance_first_matching_rule(transport_t my_transport, const struct sockaddr *sin, const socklen_t addrlen, role_t role, const char *app_id)
{
	transport_t target_family = TRANS_DEFAULT;

	/* if we do not have any rules we use vma */
	if ( __vma_config_empty()){
		target_family = TRANS_VMA;
	}
	else{
		struct dbl_lst_node *curr = __instance_list.head;

		while (curr && target_family == TRANS_DEFAULT) {
			struct instance *curr_instance = (struct instance *)curr->data;
			if (curr_instance) {
				/* skip if not our program */
				if (__vma_match_program_name(curr_instance) && __vma_match_user_defined_id(curr_instance, app_id)) {
					match_logdbg("MATCHING program name: %s, application-id: %s",curr_instance->id.prog_name_expr, curr_instance->id.user_defined_id);
					switch (role) {
						case ROLE_TCP_SERVER:
							target_family =	get_family_by_first_matching_rule(my_transport, sin, addrlen, curr_instance->tcp_srv_rules_lst);
							break;
						case ROLE_TCP_CLIENT:
							target_family =	get_family_by_first_matching_rule(my_transport, sin, addrlen, curr_instance->tcp_clt_rules_lst);
							break;
						case ROLE_UDP_SENDER:
							target_family =	get_family_by_first_matching_rule(my_transport, sin, addrlen, curr_instance->udp_snd_rules_lst);
							break;
						case ROLE_UDP_RECEIVER:
							target_family =	get_family_by_first_matching_rule(my_transport, sin, addrlen, curr_instance->udp_rcv_rules_lst);
							break;
						BULLSEYE_EXCLUDE_BLOCK_START
						default:
							break;
						BULLSEYE_EXCLUDE_BLOCK_END
					}
				}
			}
			curr = curr->next;
		}
		if(!curr && target_family == TRANS_DEFAULT) {
			target_family = TRANS_VMA;
		}
	}
	return target_family;
}

/* return the result of the first matching rule found */
transport_t __vma_match_tcp_server(transport_t my_transport, const struct sockaddr * sin, const socklen_t addrlen, const char *app_id)
{
	transport_t target_family;

	target_family = get_family_by_instance_first_matching_rule(my_transport, sin, addrlen, ROLE_TCP_SERVER, app_id);

	match_logdbg("MATCH TCP SERVER (LISTEN): => %s", __vma_get_transport_str(target_family));

	return target_family;
}

transport_t __vma_match_tcp_client(transport_t my_transport, const struct sockaddr * sin, const socklen_t addrlen, const char *app_id)
{
	transport_t target_family;

	target_family = get_family_by_instance_first_matching_rule(my_transport, sin, addrlen, ROLE_TCP_CLIENT, app_id);

	match_logdbg("MATCH TCP CLIENT (CONNECT): => %s", __vma_get_transport_str(target_family));

	return target_family;
}

/* return the result of the first matching rule found */
transport_t __vma_match_udp_sender(transport_t my_transport, const struct sockaddr * sin, const socklen_t addrlen, const char *app_id)
{
	transport_t target_family;

	target_family = get_family_by_instance_first_matching_rule(my_transport, sin, addrlen, ROLE_UDP_SENDER, app_id);

	match_logdbg("MATCH UDP SENDER: => %s", __vma_get_transport_str(target_family));

	return target_family;
}

transport_t __vma_match_udp_receiver(transport_t my_transport, const struct sockaddr * sin, const socklen_t addrlen, const char *app_id)
{
	transport_t target_family;

	target_family = get_family_by_instance_first_matching_rule(my_transport, sin, addrlen, ROLE_UDP_RECEIVER, app_id);

	match_logdbg("MATCH UDP RECEIVER: => %s", __vma_get_transport_str(target_family));

	return target_family;
}

/* given a set of rules see if there is a global match for current program */
static transport_t match_by_all_rules_program(in_protocol_t my_protocol, struct dbl_lst rules_lst)
{
	int any_vma = 0;
	int any_os = 0;
	int any_sdp = 0;
	transport_t target_family = TRANS_DEFAULT;
	struct dbl_lst_node *node;
	struct use_family_rule *rule;

	for (node = rules_lst.head; (node != NULL) && (target_family == TRANS_DEFAULT) ; node = node->next ) {
		/*
		 * to declare a dont care we either have a dont care address and port
		 * or the previous non global rules use the same target family as the
		 * global rule
		 */
		rule = (struct use_family_rule *)node->data;

		if (!rule)
			continue;
		if ((rule->protocol == my_protocol || my_protocol == PROTO_ALL) &&
				(rule->match_by_addr || rule->match_by_port)) {
			/* not a global match rule - just track the target family */
			if (rule->target_transport == TRANS_VMA || rule->target_transport == TRANS_ULP)
				any_vma++;
			else if (rule->target_transport == TRANS_OS)
				any_os++;
		} else if (rule->protocol == my_protocol && ((!rule->match_by_addr && !rule->match_by_port))){
			/* a global match so we can declare a match by program */
			if ((rule->target_transport == TRANS_VMA || rule->target_transport == TRANS_ULP) && (any_os == 0))
				target_family = TRANS_VMA;
			else if ((rule->target_transport == TRANS_OS) && (any_vma == 0) && (any_sdp == 0))
				target_family = TRANS_OS;
		}
	}
	if (target_family == TRANS_DEFAULT) {// no matching rules under application-id. use VMA. Don't continue to next application-id
		target_family = TRANS_VMA;
	}
	return target_family;
}

/* return tcp or vma if the port and role are don't cares */
transport_t __vma_match_by_program(in_protocol_t my_protocol, const char *app_id)
{
	transport_t server_target_family = TRANS_DEFAULT;
	transport_t client_target_family = TRANS_DEFAULT;
	transport_t target_family = TRANS_DEFAULT;
	bool b_found_app_id_match = false;

	if ( __vma_config_empty() ){
		match_logdbg("Configuration file is empty. Using VMA (default)" );
		target_family = TRANS_VMA;
	}
	else{
		struct dbl_lst_node *node = __instance_list.head;

		while (node && target_family == TRANS_DEFAULT) {
			/* need to try both server and client rules */
			struct instance* instance;
			instance = (struct instance *)node->data;
			if (instance && __vma_match_program_name(instance) && __vma_match_user_defined_id(instance, app_id)) {
				b_found_app_id_match = true;
				if (my_protocol == PROTO_TCP)
				{
					/* TCP */
					server_target_family =
							match_by_all_rules_program(my_protocol, instance->tcp_srv_rules_lst);
					client_target_family =
							match_by_all_rules_program(my_protocol, instance->tcp_clt_rules_lst);
				}
				else if(my_protocol == PROTO_UDP){
					/* UDP */
					server_target_family =
							match_by_all_rules_program(my_protocol, instance->udp_rcv_rules_lst);
					client_target_family =
							match_by_all_rules_program(my_protocol, instance->udp_snd_rules_lst);
				}

				/* only if both agree */
				if (server_target_family == client_target_family)
					target_family = server_target_family;
			}
			node = node->next;
		}
	}

	if (strcmp("VMA_DEFAULT_APPLICATION_ID", app_id) && !b_found_app_id_match)
		match_logwarn("requested VMA_APPLICATION_ID does not exist in the configuration file");
	
	return target_family;
}

/* is_ipv4_embedded_in_ipv6 -- return 1 if the given ipv6 address is ipv4   */
static int is_ipv4_embedded_in_ipv6(const struct sockaddr_in6 *sin6)
{
        static struct in6_addr ipv4_embedded_addr = {{{0}}};

        /* 10 first bytes must be 0 */
        if (memcmp(&ipv4_embedded_addr.s6_addr[0], &sin6->sin6_addr.s6_addr[0], 10))
                return 0;

        /* next two must be all zeros or all ones */
        if (((sin6->sin6_addr.s6_addr[10] == 0) &&
                 (sin6->sin6_addr.s6_addr[11] == 0)) ||
                ((sin6->sin6_addr.s6_addr[10] == 0xff) &&
                 (sin6->sin6_addr.s6_addr[11] == 0xff)))
                return 1;

        return 0;
}

#define IPV6_ADDR_IN_MIN_LEN 24
int __vma_sockaddr_to_vma(const struct sockaddr *addr_in, socklen_t addrlen, struct sockaddr_in *addr_out, int *was_ipv6)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *) addr_in;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) addr_in;
	char buf[MAX_ADDR_STR_LEN];

	/* currently VMA supports only IPv4 ... */
	if (!addr_in) {
		match_logdbg("Error __vma_sockaddr_to_vma: "
				  "provided NULL input pointer");
		errno = EINVAL;
		return -1;
	}
	if (!addr_out) {
		match_logdbg("Error __vma_sockaddr_to_vma: "
				  "provided NULL output pointer");
		errno = EINVAL;
		return -1;
	}

	if (sin->sin_family == AF_INET) {
		match_logdbg("__vma_sockaddr_to_vma: Given IPv4");
		if (addrlen < sizeof(struct sockaddr_in)) {
			match_logdbg("Error __vma_sockaddr_to_vma: "
					  "provided address length:%u < IPv4 length %d",
					  (unsigned)addrlen, (int)sizeof(struct sockaddr_in));
			errno = EINVAL;
			return -1;
		}

	memcpy(addr_out, sin, sizeof(struct sockaddr_in));
	if (was_ipv6)
		*was_ipv6 = 0;
	} else if (sin6->sin6_family == AF_INET6) {
		if (addrlen < IPV6_ADDR_IN_MIN_LEN) {
			match_logdbg("Error __vma_sockaddr_to_vma: "
					  "provided address length:%d < IPv6 length %d",
					  addrlen, IPV6_ADDR_IN_MIN_LEN);
			errno = EINVAL;
			return -1;
		}

		/* cannot convert IPv6 that is not IPv4 embedding */
		if (!is_ipv4_embedded_in_ipv6(sin6)) {
			match_logdbg("Error __vma_sockaddr_to_vma: "
					  "Given IPv6 address not an embedded IPv4");
			errno = EINVAL;
			return -1;
		}
		memset(addr_out, 0, sizeof(struct sockaddr_in));
		memcpy(&addr_out->sin_addr, &(sin6->sin6_addr.s6_addr[12]), 4);

		if (addr_out->sin_addr.s_addr == ntohl(1)) {
			addr_out->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			match_logdbg("__vma_sockaddr_to_vma: Given IPv6 loopback address");
		} else
			match_logdbg("__vma_sockaddr_to_vma: Given IPv4 embedded in IPv6");

		addr_out->sin_family = AF_INET;
		addr_out->sin_port = sin6->sin6_port;


		if (inet_ntop (addr_out->sin_family, (void *) &(addr_out->sin_addr), buf,
				 MAX_ADDR_STR_LEN) == NULL)
			match_logdbg("__vma_sockaddr_to_vma: Converted IPv4 address is illegal");
		else
			match_logdbg("__vma_sockaddr_to_vma: Converted IPv4 is:%s", buf);

		if (was_ipv6)
			*was_ipv6 = 1;

	} else if (sin->sin_family == 0) {

		match_logdbg("__vma_sockaddr_to_vma: Converted NULL address");
		memcpy(addr_out, addr_in, addrlen);
	} else {
		match_logdbg("Error __vma_sockaddr_to_vma: "
				  "address family <%d> is unknown", sin->sin_family);
		errno = EAFNOSUPPORT;
		return -1;
	}

	return 0;
}
