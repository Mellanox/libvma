/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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


#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hash.h"
#include "tc.h"
#include "daemon.h"
#include "nl.h"


/* Traffic control usage method
 * 0 - tc application
 * 1 - netlink api
 */
#define USE_NETLINK 1

/**
 * @struct tc_object
 * @brief tc container
 */
struct tc_object {
	nl_t nl;                  /**< netlink object */
	struct nl_req req;        /**< netlink request storage */
};

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
static int pack_key(struct tc_u32_sel *sel, uint32_t  key, uint32_t mask, int off, int offmask);
#endif /* USE_NETLINK */


tc_t tc_create(void)
{
	tc_t tc = NULL;

	tc = (struct tc_object *)malloc(sizeof(*tc));
	if (tc) {
		tc->nl = nl_create();
		if (NULL == tc->nl) {
			log_error("Unable to create a netlink object\n");
			goto err;
		}
		memset(&tc->req, 0, sizeof(tc->req));
	}

	return tc;
err:
	free(tc);
	tc = NULL;

	return NULL;
}

void tc_destroy(tc_t tc)
{
	if (tc) {
		nl_destroy(tc->nl);
		free(tc);
		tc = NULL;
	}
}

void tc_req(tc_t tc, int ifindex, uint16_t type, uint16_t flags, struct tc_qdisc qdisc)
{
	memset(&tc->req, 0, sizeof(tc->req));

	tc->req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(tc->req.msg));
	tc->req.hdr.nlmsg_type = type;
	tc->req.hdr.nlmsg_flags = (flags ? flags : (NLM_F_REQUEST | NLM_F_ACK));
	tc->req.hdr.nlmsg_pid = 0; /* to communicate kernel */
	tc->req.hdr.nlmsg_seq = 0; /* update during send */

	tc->req.msg.tcm_family = AF_UNSPEC;
	tc->req.msg.tcm_ifindex = ifindex;
	tc->req.msg.tcm_handle = qdisc.handle;
	tc->req.msg.tcm_parent = qdisc.parent;
	tc->req.msg.tcm_info = TC_H_MAKE(qdisc.prio << 16, htons(ETH_P_IP));
}

int tc_add_qdisc(tc_t tc, int ifindex)
{
	int rc = 0;

	log_debug("add qdisc using if_id: %d\n", ifindex);

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {TC_H_MAKE(TC_H_INGRESS, 0), TC_H_INGRESS, 0};
	struct rtattr *opts = NULL;

	tc_req(tc, ifindex, RTM_NEWQDISC,
			(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, "ingress", sizeof("ingress"));

	opts = nl_attr_nest_start(&tc->req.hdr, TCA_OPTIONS);
	nl_attr_nest_end(&tc->req.hdr, opts);

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if ((nl_recv(tc->nl, NULL, NULL) < 0) && (errno != EEXIST)) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];

	NOT_IN_USE(tc);

	if (NULL == if_indextoname(ifindex, if_name)) {
		rc = -errno;
		goto err;
	}

	out_buf = sys_exec("tc qdisc add dev %s handle ffff: ingress "
			"> /dev/null 2>&1 || echo $?", if_name);
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

int tc_del_qdisc(tc_t tc, int ifindex)
{
	int rc = 0;

	log_debug("remove qdisc using if_id: %d\n", ifindex);

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {TC_H_MAKE(TC_H_INGRESS, 0), TC_H_INGRESS, 0};
	struct rtattr *opts = NULL;

	tc_req(tc, ifindex, RTM_DELQDISC,
			0,
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, "ingress", sizeof("ingress"));

	opts = nl_attr_nest_start(&tc->req.hdr, TCA_OPTIONS);
	nl_attr_nest_end(&tc->req.hdr, opts);

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if ((nl_recv(tc->nl, NULL, NULL) < 0) && (errno != EINVAL)) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];

	NOT_IN_USE(tc);

	if (NULL == if_indextoname(ifindex, if_name)) {
		rc = -errno;
		goto err;
	}

	out_buf = sys_exec("tc qdisc del dev %s handle ffff: ingress "
			"> /dev/null 2>&1 || echo $?", if_name);
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

int tc_add_filter_divisor(tc_t tc, int ifindex, int prio, int ht)
{
	int rc = 0;

	log_debug("apply filter divisor using if_id: %d\n", ifindex);

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {HANDLE_SET(ht, 0, 0), 0xffff0000, prio};
	char opt_kind[] = "u32";
	uint32_t opt_divisor = 256;
	struct rtattr *opts = NULL;

	tc_req(tc, ifindex, RTM_NEWTFILTER ,
			(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, opt_kind, sizeof(opt_kind));

	opts = nl_attr_nest_start(&tc->req.hdr, TCA_OPTIONS);
	nl_attr_add(&tc->req.hdr, TCA_U32_DIVISOR, &opt_divisor, sizeof(opt_divisor));
	nl_attr_nest_end(&tc->req.hdr, opts);

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if (nl_recv(tc->nl, NULL, NULL) < 0) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];

	NOT_IN_USE(tc);

	if (NULL == if_indextoname(ifindex, if_name)) {
		rc = -errno;
		goto err;
	}

	out_buf = sys_exec("tc filter add dev %s parent ffff: prio %d handle %x: protocol ip u32 divisor 256 "
			"> /dev/null 2>&1 || echo $?",
			if_name, prio, ht);
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

int tc_add_filter_link(tc_t tc, int ifindex, int prio, int ht, int id, uint32_t ip)
{
	int rc = 0;

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {HANDLE_SET(0, 0, id), 0xffff0000, prio};
	char opt_kind[] = "u32";
	uint32_t opt_link = HANDLE_SET(id, 0, 0);
	uint32_t opt_ht = HANDLE_SET(ht, 0, 0);
	struct rtattr *opts = NULL;
	struct {
		struct tc_u32_sel sel;
		struct tc_u32_key keys[5];
	} opt_sel;

	tc_req(tc, ifindex, RTM_NEWTFILTER,
			(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, opt_kind, sizeof(opt_kind));

	opts = nl_attr_nest_start(&tc->req.hdr, TCA_OPTIONS);
	nl_attr_add(&tc->req.hdr, TCA_U32_LINK, &opt_link, sizeof(opt_link));
	nl_attr_add(&tc->req.hdr, TCA_U32_HASH, &opt_ht, sizeof(opt_ht));
	memset(&opt_sel, 0, sizeof(opt_sel));
	/* hashkey option:
	 * mask: 0x000000ff
	 * at: 20
	 */
	opt_sel.sel.hmask = htonl(0x000000ff);
	opt_sel.sel.hoff = 20;
	/* match option for ip protocol:
	 * dst: 16
	 * addr/mask: ip/0xffffffff
	 */
	pack_key(&opt_sel.sel, ip, 0xffffffff, 16, 0);
	nl_attr_add(&tc->req.hdr, TCA_U32_SEL, &opt_sel, sizeof(opt_sel.sel) + opt_sel.sel.nkeys * sizeof(opt_sel.sel.keys[0]));
	nl_attr_nest_end(&tc->req.hdr, opts);

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if (nl_recv(tc->nl, NULL, NULL) < 0) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];

	UNREFERENCED_PARAMETER(tc);

	if (NULL == if_indextoname(ifindex, if_name)) {
		rc = -errno;
		goto err;
	}

	out_buf = sys_exec("tc filter add dev %s protocol ip parent ffff: prio %d handle ::%x u32 "
			"ht %x:: match ip dst %s/32 hashkey mask 0x000000ff at 20 link %x: "
			"> /dev/null 2>&1 || echo $?",
			if_name, prio, id, ht, sys_ip2str(ip), id);
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

int tc_add_filter_tap2dev(tc_t tc, int ifindex, int prio, int id, uint32_t ip, int ifindex_to)
{
	int rc = 0;

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {HANDLE_SET(0, 0, id), 0xffff0000, prio};
	char opt_kind[] = "u32";
	uint32_t opt_ht = HANDLE_SET(0x800, 0, 0);
	struct rtattr *opts = NULL;
	struct {
		struct tc_u32_sel sel;
		struct tc_u32_key keys[5];
	} opt_sel;

	tc_req(tc, ifindex, RTM_NEWTFILTER,
			(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE),
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, opt_kind, sizeof(opt_kind));

	/* [filter] options filling */
	opts = nl_attr_nest_start(&tc->req.hdr, TCA_OPTIONS);
	{
		struct rtattr *opts_action = NULL;

		/* [action] options filling */
		opts_action = nl_attr_nest_start(&tc->req.hdr, TCA_U32_ACT);
		{
			int prio = 0;
			char opt_act_kind[] = "mirred";
			struct rtattr *opts_action_prio = NULL;

			/* [mirred] options filling */
			opts_action_prio = nl_attr_nest_start(&tc->req.hdr, ++prio);
			nl_attr_add(&tc->req.hdr, TCA_ACT_KIND, opt_act_kind, sizeof(opt_act_kind));
			{
				struct rtattr *opts_action_prio_mirred = NULL;
				struct tc_mirred opt_mirred;

				opts_action_prio_mirred = nl_attr_nest_start(&tc->req.hdr, TCA_ACT_OPTIONS);
				memset(&opt_mirred, 0, sizeof(opt_mirred));
				opt_mirred.eaction = TCA_EGRESS_REDIR;
				opt_mirred.action = TC_ACT_STOLEN;
				opt_mirred.ifindex = ifindex_to;
				nl_attr_add(&tc->req.hdr, TCA_MIRRED_PARMS, &opt_mirred, sizeof(opt_mirred));

				nl_attr_nest_end(&tc->req.hdr, opts_action_prio_mirred);
			}

			nl_attr_nest_end(&tc->req.hdr, opts_action_prio);
		}

		nl_attr_nest_end(&tc->req.hdr, opts_action);
	}

	nl_attr_add(&tc->req.hdr, TCA_U32_HASH, &opt_ht, sizeof(opt_ht));
	memset(&opt_sel, 0, sizeof(opt_sel));
	/* match option for ip protocol:
	 * dst: 16
	 * addr/mask: ip/0xffffffff
	 */
	if (ip) {
		pack_key(&opt_sel.sel, ip, 0xffffffff, 16, 0);
	} else {
		pack_key(&opt_sel.sel, ip, 0, 0, 0);
	}
	opt_sel.sel.flags |= TC_U32_TERMINAL;
	nl_attr_add(&tc->req.hdr, TCA_U32_SEL, &opt_sel, sizeof(opt_sel.sel) + opt_sel.sel.nkeys * sizeof(opt_sel.sel.keys[0]));

	nl_attr_nest_end(&tc->req.hdr, opts);

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if (nl_recv(tc->nl, NULL, NULL) < 0) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];
	char tap_name[IF_NAMESIZE];

	UNREFERENCED_PARAMETER(tc);

	if (NULL == if_indextoname(ifindex_to, if_name)) {
		rc = -errno;
		goto err;
	}

	if (NULL == if_indextoname(ifindex, tap_name)) {
		rc = -errno;
		goto err;
	}

	if (ip) {
		out_buf = sys_exec("tc filter add dev %s protocol ip parent ffff: prio %d "
					"handle ::%d u32 ht 800:: "
					"match ip dst %s/32 action mirred egress redirect dev %s "
					"> /dev/null 2>&1 || echo $?",
					tap_name, prio, id, sys_ip2str(ip), if_name);
	} else {
		out_buf = sys_exec("tc filter add dev %s protocol ip parent ffff: prio %d "
					"handle ::%d u32 ht 800:: "
					"match u8 0 0 action mirred egress redirect dev %s "
					"> /dev/null 2>&1 || echo $?",
					tap_name, prio, id, if_name);
	}
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

int tc_del_filter(tc_t tc, int ifindex, int prio, int ht, int bkt, int id)
{
	int rc = 0;

	log_debug("remove filter for if_id: %d\n", ifindex);

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
	struct tc_qdisc qdisc = {HANDLE_SET(ht, bkt, id), 0xffff0000, prio};
	char opt_kind[] = "u32";

	tc_req(tc, ifindex, RTM_DELTFILTER ,
			0,
			qdisc);

	nl_attr_add(&tc->req.hdr, TCA_KIND, opt_kind, sizeof(opt_kind));

	if (nl_send(tc->nl, &tc->req.hdr) < 0) {
		rc = -1;
		goto err;
	}
	if (nl_recv(tc->nl, NULL, NULL) < 0) {
		rc = -1;
		goto err;
	}
#else
	char *out_buf = NULL;
	char if_name[IF_NAMESIZE];

	NOT_IN_USE(tc);

	if (NULL == if_indextoname(ifindex, if_name)) {
		rc = -errno;
		goto err;
	}

	out_buf = sys_exec("tc filter del dev %s parent ffff: protocol ip prio %d handle %x:%x:%x u32 "
			"> /dev/null 2>&1 || echo $?",
			if_name, prio, ht, bkt, id);
	if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
		rc = -1;
		goto err;
	}
#endif /* USE_NETLINK */

err:
	return rc;
}

#if defined(USE_NETLINK) && (USE_NETLINK == 1)
static int pack_key(struct tc_u32_sel *sel, uint32_t  key, uint32_t mask, int off, int offmask)
{
	int i;

	key &= mask;

	for (i = 0; i < sel->nkeys; i++) {
		if ((sel->keys[i].off == off) && (sel->keys[i].offmask == offmask)) {
			uint32_t intersect = mask & sel->keys[i].mask;

			if ((key ^ sel->keys[i].val) & intersect) {
				return -1;
			}
			sel->keys[i].val |= key;
			sel->keys[i].mask |= mask;
			return 0;
		}
	}

	if (off % 4) {
		return -1;
	}
	sel->keys[sel->nkeys].val = key;
	sel->keys[sel->nkeys].mask = mask;
	sel->keys[sel->nkeys].off = off;
	sel->keys[sel->nkeys].offmask = offmask;
	sel->nkeys++;

	return 0;
}
#endif /* USE_NETLINK */
