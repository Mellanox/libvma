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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <sys/time.h>
#include <ifaddrs.h>


#include "hash.h"
#include "bitmap.h"
#include "tc.h"
#include "daemon.h"


/**
 * @struct htid_node_t
 * @brief It is an object to be used for removal workaround.
 */
struct htid_node_t {
	struct list_head node;
	int htid;
	int prio;
};

/**
 * @struct flow_ctx
 * @brief It is an object described extra details for flow element
 */
struct flow_ctx {
	bitmap_t *ht;   /**< bitmap of used hash tables */
	struct list_head pending_list;
	struct {
		int prio;
		int id;
	} ht_prio[4];   /**< internal hash tables related priority (size should be set as number of possible priorities) */
};

/**
 * @struct flow_element
 * @brief It is an object described tc element
 */
struct flow_element {
	struct list_head item; /**< link sequence of elements in list */
	struct list_head list; /**< head of children list */
	int ref;               /**< reference counter */
	uint32_t value[2];     /**< data */
	union {
		struct flow_ctx *ctx;  /**< data related if */
		uint32_t ht_id;        /**< data related ip (16 bytes for internal ht id 16 bytes ht id) */
	};
};

int open_flow(void);
void close_flow(void);
int add_flow(struct store_pid *pid_value, struct store_flow *value);
int del_flow(struct store_pid *pid_value, struct store_flow *value);

static int add_flow_egress(struct store_pid *pid_value, struct store_flow *value);
static inline void get_htid(struct flow_ctx *ctx, int prio, int *ht_krn, int *ht_id);
static inline void free_htid(struct flow_ctx *ctx, int ht_id);
static inline void add_pending_list(pid_t pid, struct flow_ctx *ctx, int if_index, int ht_id, int prio, int *rc);
static inline void free_pending_list(pid_t pid, struct flow_ctx *ctx, int if_index);
static inline int get_prio(struct store_flow *value);
static inline int get_bkt(struct store_flow *value);
static inline int get_protocol(struct store_flow *value);
static inline int get_node(struct list_head **list);


int open_flow(void)
{
	int rc = 0;

	INIT_LIST_HEAD(&daemon_cfg.if_list);
	daemon_cfg.tc = tc_create();
	if (NULL == daemon_cfg.tc) {
		rc = -EFAULT;
		log_error("Failed to create TC object %d (%s)\n", errno,
				strerror(errno));
		goto err;
	}

err:
	return rc;
}

void close_flow(void)
{
	tc_destroy(daemon_cfg.tc);
	daemon_cfg.tc = NULL;
}

int add_flow(struct store_pid *pid_value, struct store_flow *value)
{
	int rc = 0;
	pid_t pid = pid_value->pid;
	struct list_head *cur_head = NULL;
	struct flow_element *cur_element = NULL;
	struct list_head *cur_entry = NULL;
	uint32_t ip = value->flow.dst_ip;
	int ht = HANDLE_HT(value->handle);
	int bkt = HANDLE_BKT(value->handle);
	int id = HANDLE_ID(value->handle);
	int ht_internal = KERNEL_HT;
	struct flow_ctx *ctx = NULL;

	/* Egress rules should be created for new tap device
	 */
	if (VMA_MSG_FLOW_EGRESS == value->type) {
		return add_flow_egress(pid_value, value);
	}

	errno = 0;

	/* interface list processing
	 * use interface index as unique identifier
	 * every network interface has qdisc
	 * so as first step let find if interface referenced in this flow exists
	 * in the if_list or allocate new element related one
	 */
	cur_head = &daemon_cfg.if_list;
	list_for_each(cur_entry, cur_head) {
		cur_element = list_entry(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == value->if_id) {
			break;
		}
	}
	if (cur_entry == cur_head) {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		/* Cleanup from possible failure during last daemon session */
		tc_del_qdisc(daemon_cfg.tc, value->if_id);

		/* Create filter to redirect traffic from netvsc device to tap device */
		if (tc_add_qdisc(daemon_cfg.tc, value->if_id) < 0) {
			log_error("[%d] failed tc_add_qdisc() errno = %d\n", pid, errno);
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = value->if_id;
		cur_element->ctx = (void *)calloc(1, sizeof(*cur_element->ctx));
		if (NULL == cur_element->ctx) {
			free(cur_element);
			rc = -ENOMEM;
			goto err;
		}
		/* tables from 0x800 are reserved by kernel */
		bitmap_create(&cur_element->ctx->ht, (KERNEL_HT - 1));
		if (NULL == cur_element->ctx->ht) {
			free(cur_element->ctx);
			free(cur_element);
			rc = -ENOMEM;
			goto err;
		}

		/* table id = 0 is not used */
		bitmap_set(cur_element->ctx->ht, 0);
		INIT_LIST_HEAD(&(cur_element->ctx->pending_list));
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;
	ctx = cur_element->ctx;

	log_debug("[%d] add flow (if): 0x%p value: %d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->ref);

	/* table list processing
	 * table id calculation is based on ip and type
	 * so as first step let find if hash table referenced in this flow exists
	 * in the list of tables related specific interface or allocate new element related one
	 */
	cur_head = &cur_element->list;
	list_for_each(cur_entry, cur_head) {
		cur_element = list_entry(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == (uint32_t)value->type &&
			cur_element->value[1] == ip) {
			ht = cur_element->ht_id & 0x0000FFFF;
			ht_internal = (cur_element->ht_id >> 16) & 0x0000FFFF;
			break;
		}
	}
	if (cur_entry == cur_head) {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		get_htid(ctx, get_prio(value), &ht_internal, &ht);

		if (tc_add_filter_divisor(daemon_cfg.tc, value->if_id, get_prio(value), ht) < 0) {
			log_error("[%d] failed tc_add_filter_divisor() errno = %d\n", pid, errno);
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}
		if (tc_add_filter_link(daemon_cfg.tc, value->if_id, get_prio(value), ht_internal, ht, ip) < 0) {
			log_error("[%d] failed tc_add_filter_link() errno = %d\n", pid, errno);
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = value->type;
		cur_element->value[1] = ip;
		cur_element->ht_id = ((ht_internal << 16) & 0xFFFF0000) | (ht & 0x0000FFFF);
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (ht): 0x%p value: %d:%d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);

	/* bucket list processing
	 * bucket number calculation can be different for flow types
	 * so as first step let find if bucket referenced in this flow exists
	 * in the list of buckets related specific hash table or allocate new element related one
	 */
	cur_head = &cur_element->list;
	bkt = get_bkt(value);
	if (bkt < 0) {
		log_warn("[%d] invalid flow bkt: %d\n",
				pid, bkt);
		goto err;
	}
	list_for_each(cur_entry, cur_head) {
		cur_element = list_entry(cur_entry, struct flow_element, item);
		if ((int)cur_element->value[0] == bkt) {
			break;
		}
	}
	if (cur_entry == cur_head) {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = bkt;
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (bkt): 0x%p value: %d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->ref);

	/* node list processing
	 * node number calculation can be different for flow types
	 * allocate new element related one
	 * cur_entry pointed by cur_head can depends on internal logic and
	 * direct a place in the list where new entry should be inserted
	 */
	cur_head = &cur_element->list;
	id = get_node(&cur_head);
	if (id <= 0) {
		log_warn("[%d] invalid flow id: %d\n",
				pid, id);
		goto err;
	} else {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		switch (value->type) {
		case VMA_MSG_FLOW_TCP_3T:
		case VMA_MSG_FLOW_UDP_3T:
			rc = tc_add_filter_dev2tap(daemon_cfg.tc, value->if_id,
					get_prio(value), ht, bkt, id,
					get_protocol(value), value->flow.dst_ip, value->flow.dst_port,
					0, 0, value->tap_id);
			break;
		case VMA_MSG_FLOW_TCP_5T:
		case VMA_MSG_FLOW_UDP_5T:
			rc = tc_add_filter_dev2tap(daemon_cfg.tc, value->if_id,
					get_prio(value), ht, bkt, id,
					get_protocol(value), value->flow.dst_ip, value->flow.dst_port,
					value->flow.t5.src_ip, value->flow.t5.src_port, value->tap_id);
			break;
		default:
			break;
		}
		if (rc < 0) {
			log_error("[%d] failed tc_add_filter_dev2tap() errno = %d\n", pid, errno);
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = id;
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (node): 0x%p value: %d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->ref);

	free_pending_list(pid, ctx, value->if_id);

err:

	value->handle = HANDLE_SET(ht, bkt, id);
	log_debug("[%d] add flow filter: %x:%x:%x rc=%d\n",
			pid, ht, bkt, id, rc);

	return rc;
}

int del_flow(struct store_pid *pid_value, struct store_flow *value)
{
	int rc = 0;
	pid_t pid = pid_value->pid;
	struct list_head *cur_head = NULL;
	struct flow_element *cur_element = NULL;
	struct list_head *cur_entry = NULL;
	struct flow_element *save_element[3];
	struct list_head *save_entry[3];
	uint32_t ip = value->flow.dst_ip;
	int ht = HANDLE_HT(value->handle);
	int bkt = HANDLE_BKT(value->handle);
	int id = HANDLE_ID(value->handle);
	int ht_internal = KERNEL_HT;
	struct flow_ctx *ctx = NULL;
	int found = 0;

	errno = 0;

	/* interface list processing */
	found = 0;
	cur_head = &daemon_cfg.if_list;
	list_for_each(cur_entry, cur_head) {
		cur_element = list_entry(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == value->if_id) {
			found = 1;
			break;
		}
	}
	if (found) {
		assert(cur_entry != cur_head);
		assert(cur_element);
		ctx = cur_element->ctx;
		save_element[0] = cur_element;
		save_entry[0] = cur_entry;

		/* table list processing */
		found = 0;
		cur_head = &cur_element->list;
		list_for_each(cur_entry, cur_head) {
			cur_element = list_entry(cur_entry, struct flow_element, item);
			if (cur_element->value[0] == (uint32_t)value->type &&
				cur_element->value[1] == ip) {
				ht = cur_element->ht_id & 0x0000FFFF;
				ht_internal = (cur_element->ht_id >> 16) & 0x0000FFFF;
				found = 1;
				break;
			}
		}
		if (found) {
			assert(cur_entry != cur_head);
			assert(cur_element);
			save_element[1] = cur_element;
			save_entry[1] = cur_entry;

			/* bucket list processing */
			found = 0;
			cur_head = &cur_element->list;
			list_for_each(cur_entry, cur_head) {
				cur_element = list_entry(cur_entry, struct flow_element, item);
				if ((int)cur_element->value[0] == bkt) {
					found = 1;
					break;
				}
			}
			if (found) {
				assert(cur_entry != cur_head);
				assert(cur_element);
				save_element[2] = cur_element;
				save_entry[2] = cur_entry;

				/* node list processing */
				found = 0;
				cur_head = &cur_element->list;
				list_for_each(cur_entry, cur_head) {
					cur_element = list_entry(cur_entry, struct flow_element, item);
					if ((int)cur_element->value[0] == id) {
						found = 1;
						break;
					}
				}
				if (found) {
					assert(cur_entry != cur_head);
					assert(cur_element);

					cur_element->ref--;

					log_debug("[%d] del flow (node): 0x%p value: %d:%d ref: %d\n",
							pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);
					if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {

						if (tc_del_filter(daemon_cfg.tc, value->if_id, get_prio(value), ht, bkt, id) < 0) {
							log_warn("[%d] failed tc_del_filter() errno = %d\n", pid, errno);
							rc = -EFAULT;
						}

						list_del_init(cur_entry);
						free(cur_element);
					}
				}

				cur_element = save_element[2];
				cur_entry = save_entry[2];
				cur_element->ref--;

				log_debug("[%d] del flow (bkt): 0x%p value: %d ref: %d\n",
						pid, cur_element, cur_element->value[0], cur_element->ref);
				if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {
					list_del_init(cur_entry);
					free(cur_element);
				}
			}

			cur_element = save_element[1];
			cur_entry = save_entry[1];
			cur_element->ref--;

			log_debug("[%d] del flow (ht): 0x%p value: %d:%d ref: %d\n",
					pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);
			if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {

				if (tc_del_filter(daemon_cfg.tc, value->if_id, get_prio(value), ht_internal, 0, ht) < 0) {
					log_warn("[%d] failed tc_del_filter() errno = %d\n", pid, errno);
					rc = -EFAULT;
				}

				/* Device busy error is returned while trying to remove table in this location */
				add_pending_list(pid, ctx, value->if_id, ht, get_prio(value), &rc);

				list_del_init(cur_entry);
				free(cur_element);
			}
		}

		cur_element = save_element[0];
		cur_entry = save_entry[0];
		cur_element->ref--;

		log_debug("[%d] del flow (if): 0x%p value: %d ref: %d\n",
				pid, cur_element, cur_element->value[0], cur_element->ref);
		if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {

			if (tc_del_qdisc(daemon_cfg.tc, value->if_id) < 0) {
				log_warn("[%d] failed tc_del_qdisc() errno = %d\n", pid, errno);
				rc = -EFAULT;
			}

			bitmap_destroy(cur_element->ctx->ht);
			assert(ctx == cur_element->ctx);
			free_pending_list(pid, cur_element->ctx, value->if_id);
			free(cur_element->ctx);
			ctx = NULL;
			list_del_init(cur_entry);
			free(cur_element);
		}
	}

	free_pending_list(pid, ctx, value->if_id);

	log_debug("[%d] del flow filter: %x:%x:%x rc=%d\n",
			pid, ht, bkt, id, rc);

	return rc;
}

static int add_flow_egress(struct store_pid *pid_value, struct store_flow *value)
{
	int rc = 0;
	pid_t pid = pid_value->pid;
	struct list_head *cur_entry = NULL;
	struct store_flow *cur_flow = NULL;

	errno = 0;

	/* Egress rules should be created for new tap device
	 */
	list_for_each(cur_entry, &pid_value->flow_list) {
		cur_flow = list_entry(cur_entry, struct store_flow, item);
		if (value->tap_id == cur_flow->tap_id) {
			break;
		}
	}
	if (cur_entry == &pid_value->flow_list) {
		struct ifaddrs *ifaddr, *ifa;
		int handle = 1;

		/* This cleanup is done just to support verification */
		tc_del_qdisc(daemon_cfg.tc, value->tap_id);

		/* Create rules to process ingress trafic on tap device */
		if (tc_add_qdisc(daemon_cfg.tc, value->tap_id) < 0) {
			log_error("[%d] failed tc_add_qdisc() errno = %d\n", pid, errno);
			rc = -EFAULT;
			goto err;
		}

		if (!getifaddrs(&ifaddr)) {
			for (ifa = ifaddr; NULL != ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr->sa_family == AF_INET &&
						!(ifa->ifa_flags & IFF_LOOPBACK) &&
						value->if_id == if_nametoindex(ifa->ifa_name)) {

					/* Create filter to redirect traffic from tap device to lo device
					 * in case destination address relates netvsc
					 */
					if (tc_add_filter_tap2dev(daemon_cfg.tc, value->tap_id, 1, handle,
							((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr, sys_lo_ifindex()) < 0) {
						log_error("[%d] failed tc_add_filter_tap2dev() errno = %d\n", pid, errno);
						rc = -EFAULT;
						goto err;
					}
					handle++;
				}
			}
			freeifaddrs(ifaddr);
		}

		/* Create filter to redirect traffic from tap device to netvsc device
		 * Use another prio value for common filter just to separate one
		 * actually the same value should work too
		 */
		if (tc_add_filter_tap2dev(daemon_cfg.tc, value->tap_id, 2, handle,
				0, value->if_id) < 0) {
			log_error("[%d] failed tc_add_filter_tap2dev() errno = %d\n", pid, errno);
			rc = -EFAULT;
			goto err;
		}
	}

err:

	return rc;
}

static inline void get_htid(struct flow_ctx *ctx, int prio, int *ht_krn, int *ht_id)
{
	if (ht_krn) {
		int i;
		int free_index = -1;
		int free_id = -1;

		*ht_krn = 0;
		for (i = 0; i < (int)(sizeof(ctx->ht_prio) / sizeof(ctx->ht_prio[0])); i++) {
			if (ctx->ht_prio[i].prio == prio) {
				*ht_krn = (KERNEL_HT + ctx->ht_prio[i].id);
				break;
			}
			if (ctx->ht_prio[i].prio == 0) {
				free_index = i;
			} else {
				free_id = (free_id < ctx->ht_prio[i].id ? ctx->ht_prio[i].id : free_id);
			}
		}

		if ((0 == *ht_krn) && (0 <= free_index)) {
			ctx->ht_prio[free_index].prio = prio;
			ctx->ht_prio[free_index].id = free_id + 1;

			*ht_krn = (KERNEL_HT + ctx->ht_prio[free_index].id);
		}
	}

	if (ht_id) {
		*ht_id = bitmap_find_first_zero(ctx->ht);
		if (*ht_id >= 0) {
			bitmap_set(ctx->ht, *ht_id);
		}
	}
}

static inline void free_pending_list(pid_t pid, struct flow_ctx *ctx, int if_index)
{
	struct htid_node_t *cur_element = NULL;
	struct list_head *cur_entry = NULL, *tmp_entry = NULL;

	if (ctx) {
		list_for_each_safe(cur_entry, tmp_entry, &ctx->pending_list) {
			cur_element = list_entry(cur_entry, struct htid_node_t, node);

			if (tc_del_filter(daemon_cfg.tc, if_index, cur_element->prio, cur_element->htid, 0, 0) < 0) {
				continue;
			}

			log_debug("[%d] del flow request was removed successfully: if %d htid %d prio %d\n",
									pid, if_index, cur_element->htid, cur_element->prio);

			list_del_init(&cur_element->node);
			free_htid(ctx, cur_element->htid);
			free(cur_element);
		}
	}
}

static inline void add_pending_list(pid_t pid, struct flow_ctx *ctx, int if_index, int ht_id, int prio, int *rc)
{
	struct htid_node_t *htid_node = (void *)calloc(1, sizeof(struct htid_node_t));
	if (NULL == htid_node) {
		*rc = -ENOMEM;
		return;
	}

	INIT_LIST_HEAD(&htid_node->node);
	htid_node->htid = ht_id;
	htid_node->prio = prio;

	list_add(&htid_node->node, &ctx->pending_list);

	log_debug("[%d] del flow request was added to the pending list: if %d htid %d prio %d\n",
							pid, if_index, ht_id, prio);
}

static inline void free_htid(struct flow_ctx *ctx, int ht_id)
{
	bitmap_clear(ctx->ht, ht_id);
}

static inline int get_prio(struct store_flow *value)
{
	return value->type;
}

static inline int get_bkt(struct store_flow *value)
{
	return ntohs(value->flow.dst_port) & 0xFF;
}

static inline int get_protocol(struct store_flow *value)
{
	switch (value->type) {
	case VMA_MSG_FLOW_UDP_3T:
	case VMA_MSG_FLOW_UDP_5T:
		return IPPROTO_UDP;

	case VMA_MSG_FLOW_TCP_3T:
	case VMA_MSG_FLOW_TCP_5T:
		return IPPROTO_TCP;

	default:
		return -EINVAL;
	}
}

static inline int get_node(struct list_head **cur_head)
{
	int id = 1;
	struct flow_element *cur_element = NULL;
	struct list_head *cur_entry = NULL;

	/* node id logic is smart (keep list entry in ascending order)
	 * there are two ways as
	 * 1 - simply take last entry in the list and increment id value until
	 * maximum value is not achieved
	 * 2 - if last entry has maximum possible value try look for first free
	 * entry from start in the list
	 */
	if (!list_empty((*cur_head))) {
		cur_entry = (*cur_head)->prev;
		cur_element = list_entry(cur_entry, struct flow_element, item);
		if (cur_element->value[0] < MAX_ID) {
			id = cur_element->value[0] + 1;
		} else {
			id = 1;
			list_for_each(cur_entry, (*cur_head)) {
				cur_element = list_entry(cur_entry, struct flow_element, item);
				if ((int)cur_element->value[0] > id) {
					*cur_head = cur_entry;
					break;
				}
				id++;
			}
		}
	}

	if ((0 >= id) || (id > MAX_ID)) {
		return -EINVAL;
	}

	return id;
}
