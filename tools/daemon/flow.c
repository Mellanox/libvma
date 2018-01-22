/*
 * Copyright (c) 2001-2017 Mellanox Technologies, Ltd. All rights reserved.
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
#include <sys/time.h>


#include "hash.h"
#include "daemon.h"


#define HANDLE_INVALID    (uint32_t)(-1)

#define HANDLE_SET(ht, bkt, id)  \
	(                                          \
	(((uint32_t)(ht)  << 20) & 0xFFF00000) |   \
	(((uint32_t)(bkt) << 12) & 0x000FF000) |   \
	(((uint32_t)(id)  << 0)  & 0x00000FFF)     \
	)

#define HANDLE_HT(value)          ((((uint32_t)(value)) & 0xFFF00000) >> 20)  /* 12bits by offset 20 */
#define HANDLE_BKT(value)         ((((uint32_t)(value)) & 0x000FF000) >> 12)  /* 8bits by offset 12 */
#define HANDLE_ID(value)          ((((uint32_t)(value)) & 0x00000FFF) >> 0)   /* 12bits by offset 0 */

/**
 * @struct flow_element
 * @brief It is an object described tc element
 */
struct flow_element {
	struct list_head item; /**< link sequence of elements in list */
	struct list_head list; /**< head of children list */
	int ref;               /**< reference counter */
	uint32_t value[2];     /**< data */
};

int open_flow(void);
void close_flow(void);
int add_flow(pid_t pid, struct store_flow *value);
int del_flow(pid_t pid, struct store_flow *value);

static int get_ht(struct store_flow *value);
static int get_prio(struct store_flow *value);


int open_flow(void)
{
	INIT_LIST_HEAD(&daemon_cfg.if_list);

	return 0;
}

void close_flow(void)
{
}

int add_flow(pid_t pid, struct store_flow *value)
{
	int rc = 0;
	struct list_head *cur_head = NULL;
	struct flow_element *cur_element = NULL;
	struct list_head *cur_entry = NULL;
	char if_name[IF_NAMESIZE];
	char tap_name[IF_NAMESIZE];
	char *out_buf = NULL;
	uint32_t ip = 0;
	uint32_t port = 0;
	int ht = HANDLE_HT(value->handle);
	int bkt = HANDLE_BKT(value->handle);
	int id = HANDLE_ID(value->handle);;
	char str_tmp[20];

	switch (value->type) {
	case VMA_MSG_FLOW_TCP_3T:
		ip = value->flow.t3.dst_ip;
		port = value->flow.t3.dst_port;
		break;
	case VMA_MSG_FLOW_TCP_5T:
		ip = value->flow.t5.dst_ip;
		port = value->flow.t5.dst_port;
		break;
	default:
		log_error("Invalid format %d (%s)\n", errno,
				strerror(errno));
		rc = -EPROTO;
		goto err;
	}

	errno = 0;
	if (NULL == if_indextoname(value->if_id, if_name)) {
		log_error("[%d] network interface is not found by index %d errno %d (%s)\n",
				pid, value->if_id, errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	if (NULL == if_indextoname(value->tap_id, tap_name)) {
		log_error("[%d] tap interface is not found by index %d errno %d (%s)\n",
				pid, value->tap_id, errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* if list processing */
	cur_head = &daemon_cfg.if_list;
	list_for_each(cur_entry, cur_head) {
		cur_element = container_of(cur_entry, struct flow_element, item);
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

		out_buf = sys_exec("tc qdisc add dev %s handle ffff: ingress > /dev/null 2>&1 || echo $?",
							if_name);
		if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
			log_error("[%d] failed tc qdisc add dev %s errno %d (%s)\n",
					pid, if_name, errno, strerror(errno));
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = value->if_id;
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (if): 0x%p value: %d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->ref);

	/* ip list processing */
	cur_head = &cur_element->list;
	list_for_each(cur_entry, cur_head) {
		cur_element = container_of(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == (uint32_t)value->type &&
			cur_element->value[1] == ip) {
			break;
		}
	}
	if (cur_entry == cur_head) {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		ht = get_ht(value);
		out_buf = sys_exec("tc filter add dev %s parent ffff: prio %d handle %x: protocol ip u32 divisor 256 > /dev/null 2>&1 || echo $?",
							if_name, get_prio(value), ht);
		if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
			log_error("[%d] failed add ht dev %s prio %d handle %x errno %d (%s)\n",
					pid, if_name, get_prio(value), ht, errno, strerror(errno));
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}
		out_buf = sys_exec("tc filter add dev %s protocol ip parent ffff: prio %d handle ::%x u32 ht 800:: match ip dst %s/32 hashkey mask 0x000000ff at 20 link %x: > /dev/null 2>&1 || echo $?",
							if_name, get_prio(value), ht, sys_ip2str(ip), ht);
		if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
			log_error("[%d] failed link ht dev %s prio %d handle %x:: dst %s errno %d (%s)\n",
					pid, if_name, get_prio(value), ht, sys_ip2str(ip), errno, strerror(errno));
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = value->type;
		cur_element->value[1] = ip;
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (ip): 0x%p value: %d:%d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);

	/* port list processing */
	cur_head = &cur_element->list;
	list_for_each(cur_entry, cur_head) {
		cur_element = container_of(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == port) {
			break;
		}
	}
	if (cur_entry == cur_head) {
		cur_element = (void *)calloc(1, sizeof(*cur_element));
		if (NULL == cur_element) {
			rc = -ENOMEM;
			goto err;
		}

		bkt = port % 0xFF;
		id = port / 0xFF;
		switch (value->type) {
		case VMA_MSG_FLOW_TCP_3T:
			out_buf = sys_exec("tc filter add dev %s parent ffff: protocol ip "
								"prio %d handle ::%x u32 ht %x:%x: match ip protocol 6 0xff "
								"match ip dst %s/32 match ip dport %d 0xffff "
								"action mirred egress redirect dev %s > /dev/null 2>&1 || echo $?",
								if_name, get_prio(value), id, ht, bkt,
								sys_ip2str(value->flow.t3.dst_ip), ntohs(value->flow.t3.dst_port), tap_name);
			break;
		case VMA_MSG_FLOW_TCP_5T:
			strcpy(str_tmp, sys_ip2str(value->flow.t5.src_ip));
			out_buf = sys_exec("tc filter add dev %s parent ffff: protocol ip "
								"prio %d handle ::%x u32 ht %x:%x: match ip protocol 6 0xff "
								"match ip src %s/32 match ip sport %d 0xffff "
								"match ip dst %s/32 match ip dport %d 0xffff "
								"action mirred egress redirect dev %s > /dev/null 2>&1 || echo $?",
								if_name, get_prio(value), id, ht, bkt,
								str_tmp, value->flow.t5.src_port,
								sys_ip2str(value->flow.t5.dst_ip), ntohs(value->flow.t5.dst_port), tap_name);
			break;
		default:
			break;
		}
		if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
			log_error("[%d] failed add filter dev %s prio %d handle %x:%x:%x errno %d (%s)\n",
					pid, if_name, get_prio(value), ht, bkt, id, errno, strerror(errno));
			free(cur_element);
			rc = -EFAULT;
			goto err;
		}

		INIT_LIST_HEAD(&cur_element->list);
		cur_element->ref = 0;
		cur_element->value[0] = port;
		list_add_tail(&cur_element->item, cur_head);
	}
	assert(cur_element);
	cur_element->ref++;

	log_debug("[%d] add flow (port): 0x%p value: %d ref: %d\n",
			pid, cur_element, cur_element->value[0], cur_element->ref);

	value->handle = HANDLE_SET(ht, bkt, id);
	log_debug("[%d] add flow filter: %x:%x:%x\n",
			pid, ht, bkt, id);

err:
	return rc;
}

int del_flow(pid_t pid, struct store_flow *value)
{
	int rc = 0;
	struct list_head *cur_head = NULL;
	struct flow_element *cur_element = NULL;
	struct list_head *cur_entry = NULL;
	struct flow_element *save_element[2];
	struct list_head *save_entry[2];
	char if_name[IF_NAMESIZE];
	char *out_buf = NULL;
	uint32_t ip = 0;
	uint32_t port = 0;
	int ht = HANDLE_HT(value->handle);
	int bkt = HANDLE_BKT(value->handle);
	int id = HANDLE_ID(value->handle);;

	switch (value->type) {
	case VMA_MSG_FLOW_TCP_3T:
		ip = value->flow.t3.dst_ip;
		port = value->flow.t3.dst_port;
		break;
	case VMA_MSG_FLOW_TCP_5T:
		ip = value->flow.t5.dst_ip;
		port = value->flow.t5.dst_port;
		break;
	default:
		log_error("Invalid format %d (%s)\n", errno,
				strerror(errno));
		rc = -EPROTO;
		goto err;
	}

	errno = 0;
	if (NULL == if_indextoname(value->if_id, if_name)) {
		log_error("[%d] network interface is not found by index %d errno %d (%s)\n",
				pid, value->if_id, errno, strerror(errno));
		rc = -errno;
		goto err;
	}

	/* if list processing */
	cur_head = &daemon_cfg.if_list;
	list_for_each(cur_entry, cur_head) {
		cur_element = container_of(cur_entry, struct flow_element, item);
		if (cur_element->value[0] == value->if_id) {
			break;
		}
	}
	if (cur_entry != cur_head) {
		assert(cur_element);
		save_element[0] = cur_element;
		save_entry[0] = cur_entry;

		/* ip list processing */
		cur_head = &cur_element->list;
		list_for_each(cur_entry, cur_head) {
			cur_element = container_of(cur_entry, struct flow_element, item);
			if (cur_element->value[0] == (uint32_t)value->type &&
				cur_element->value[1] == ip) {
				break;
			}
		}
		if (cur_entry != cur_head) {
			assert(cur_element);
			save_element[1] = cur_element;
			save_entry[1] = cur_entry;

			/* port list processing */
			cur_head = &cur_element->list;
			list_for_each(cur_entry, cur_head) {
				cur_element = container_of(cur_entry, struct flow_element, item);
				if (cur_element->value[0] == port) {
					break;
				}
			}
			if (cur_entry != cur_head) {
				assert(cur_element);

				cur_element->ref--;

				log_debug("[%d] del flow (port): 0x%p value: %d ref: %d\n",
						pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);
				if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {

					out_buf = sys_exec("tc filter del dev %s parent ffff: protocol ip prio %d handle %x:%x:%x u32 > /dev/null 2>&1 || echo $?",
										if_name, get_prio(value), ht, bkt, id);
					if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
						log_error("[%d] tc filter del dev %s prio %d handle %x:%x:%x errno %d (%s)\n",
								pid, if_name, get_prio(value), ht, bkt, id, errno, strerror(errno));
						rc = -EFAULT;
					}

					list_del_init(cur_entry);
					free(cur_element);
				}
			}

			cur_element = save_element[1];
			cur_entry = save_entry[1];
			cur_element->ref--;

			log_debug("[%d] del flow (ip): 0x%p value: %d:%d ref: %d\n",
					pid, cur_element, cur_element->value[0], cur_element->value[1], cur_element->ref);
			if (list_empty(&cur_element->list) && (cur_element->ref <=0 )) {

				out_buf = sys_exec("tc filter del dev %s parent ffff: protocol ip prio %d handle 800::%x u32 > /dev/null 2>&1 || echo $?",
									if_name, get_prio(value), ht);
				if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
					log_error("[%d] tc filter del dev %s prio %d handle 800::%x errno %d (%s)\n",
							pid, if_name, get_prio(value), ht, errno, strerror(errno));
					rc = -EFAULT;
				}

				out_buf = sys_exec("tc filter del dev %s parent ffff: protocol ip prio %d handle %x: u32 > /dev/null 2>&1 || echo $?",
									if_name, get_prio(value), ht);
#if 0 /* Device busy error is returned (There is no issue if insert sleep(1) before execution */
				if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
					log_error("[%d] tc filter del dev %s prio %d handle %x errno %d (%s)\n",
							pid, if_name, get_prio(value), ht, errno, strerror(errno));
					rc = -EFAULT;
				}
#endif

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

			out_buf = sys_exec("tc qdisc del dev %s handle ffff: ingress > /dev/null 2>&1 || echo $?", if_name);
			if (NULL == out_buf || (out_buf[0] != '\0' && out_buf[0] != '0')) {
				log_error("[%d] failed tc qdisc del dev %s errno %d (%s)\n",
						pid, if_name, errno, strerror(errno));
				rc = -EFAULT;
			}

			list_del_init(cur_entry);
			free(cur_element);
		}
	}

	log_debug("[%d] del flow filter: %x:%x:%x\n",
			pid, ht, bkt, id);

err:
	return rc;
}


static int get_ht(struct store_flow *value)
{
	static int ht_id = 0;
	return (HANDLE_HT(value->handle) ? (int)HANDLE_HT(value->handle) : (++ht_id) % 0x7FF);
}

static int get_prio(struct store_flow *value)
{
	return value->type;
}
