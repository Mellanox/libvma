/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif
#ifdef HAVE_SYS_FANOTIFY_H
#include <sys/fanotify.h>
#endif


#include "hash.h"
#include "tc.h"
#include "daemon.h"

#ifndef KERNEL_O_LARGEFILE
#if defined(__aarch64__) || defined(__powerpc__)
/* Check architecture: if we are running on ARM,
 * omit KERNEL_O_LARGEFILE from fanotify_init invocation because
 * KERNEL_O_LARGEFILE breaks program on armv running at least kernel 4.4+
 */
#define KERNEL_O_LARGEFILE O_LARGEFILE
#else
/* work around kernels which do not have this fix yet:
 * http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1e2ee49f7
 * O_LARGEFILE is usually 0, so hardcode it here
 */
#define KERNEL_O_LARGEFILE 00100000
#endif
#endif


struct rst_info {
	struct sockaddr_in local_addr;
	struct sockaddr_in remote_addr;
	uint32_t seqno;
};

#pragma pack(push, 1)
struct tcp_msg {
	struct iphdr  ip;
	struct tcphdr tcp;
	uint8_t       data[8192];
};
#pragma pack( pop )

#pragma pack(push, 1)
struct pseudo_header {
	uint32_t      source_address;
	uint32_t      dest_address;
	uint8_t       placeholder;
	uint8_t       protocol;
	uint16_t      tcp_length;
	struct tcphdr tcp;
} pseudo_header;
#pragma pack( pop )


int open_notify(void);
void close_notify(void);
int proc_notify(void);

extern int add_flow(struct store_pid *pid_value, struct store_flow *value);
extern int del_flow(struct store_pid *pid_value, struct store_flow *value);

static int setup_notify(void);
static int create_raw_socket(void);
static int clean_process(pid_t pid);
static int check_process(pid_t pid);
static unsigned short calc_csum(unsigned short *ptr, int nbytes);
static int get_seqno(struct rst_info *rst);
static int send_rst(struct rst_info *rst);

#ifdef HAVE_SYS_INOTIFY_H
static int open_inotify(void);
static int proc_inotify(void *buf, int size);
#endif

#ifdef HAVE_SYS_FANOTIFY_H
static int open_fanotify(void);
static int proc_fanotify(void *buf, int size);
#endif

#if !defined(HAVE_SYS_FANOTIFY_H) && !defined(HAVE_SYS_INOTIFY_H)
#error neither inotify nor fanotify is supported
#endif

static int (*do_open_notify)(void) = NULL;
static int (*do_proc_notify)(void*, int) = NULL;


int open_notify(void)
{
	int rc = 0;

	rc = setup_notify();
	if (rc < 0) {
		goto err;
	}

	rc = create_raw_socket();
	if (rc < 0) {
		goto err;
	}
	log_debug("setting raw socket ...\n");

	rc = do_open_notify();
	if (rc < 0) {
		goto err;
	}

err:
	return rc;
}

void close_notify(void)
{
	log_debug("closing raw socket ...\n");

	if (daemon_cfg.notify_fd > 0) {
		close(daemon_cfg.notify_fd);
	}

	if (daemon_cfg.raw_fd > 0) {
		close(daemon_cfg.raw_fd);
	}
}

int proc_notify(void)
{
	int rc = 0;
	int len = 0;
	char msg_recv[4096];

	memset((void *)&msg_recv, 0, sizeof(msg_recv));
again:
	/* coverity[tainted_string_argument] */
	len = read(daemon_cfg.notify_fd, msg_recv, sizeof(msg_recv));
	if (len <= 0) {
		if (errno == EINTR) {
			goto again;
		}
		rc = -errno;
		log_error("Failed read events() errno %d (%s)\n", errno,
				strerror(errno));
		goto err;
	}

	rc = do_proc_notify((void *)msg_recv, len);
	if (rc < 0) {
		goto err;
	}

err:
	return rc;
}

static int setup_notify(void)
{
	int fd = -1;

	/* Set method for processing
	 * fanotify has the highest priority because it has better
	 * performance
	 */
	errno = 0;
#if defined(HAVE_SYS_FANOTIFY_H)
	fd = fanotify_init(0, KERNEL_O_LARGEFILE);
	if (fd >= 0) {
		do_open_notify = open_fanotify;
		do_proc_notify = proc_fanotify;
		close(fd);
		return 0;
	} else {
		log_debug("fanotify_init() errno %d (%s)\n", errno,
			(ENOSYS == errno ? "missing support for fanotify (check CONFIG_FANOTIFY=y)\n" : strerror(errno)));
	}
#endif

#if defined(HAVE_SYS_INOTIFY_H)
	fd = inotify_init();
	if (fd >= 0) {
		do_open_notify = open_inotify;
		do_proc_notify = proc_inotify;
		close(fd);
		return 0;
	} else {
		log_debug("inotify_init() errno %d (%s)\n", errno,
			(ENOSYS == errno ? "missing support for inotify (check CONFIG_INOTIFY_USER=y)\n" : strerror(errno)));
	}
#endif

	log_error("Failed notify way selection, check kernel configuration errno %d (%s)\n", errno,
			strerror(errno));
	return -ENOSYS;
}

static int create_raw_socket(void)
{
	int rc = 0;
	int optval = 1;

	/* Create RAW socket to use for sending RST to peers */
	daemon_cfg.raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (daemon_cfg.raw_fd < 0) {
		/* socket creation failed, may be because of non-root privileges */
		log_error("Failed to call socket() errno %d (%s)\n", errno,
				strerror(errno));
		rc = -errno;
		goto err;
	}

	optval = 1;
	rc = setsockopt(daemon_cfg.raw_fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
	if (rc < 0) {
		log_error("Failed to call setsockopt() errno %d (%s)\n", errno,
				strerror(errno));
		rc = -errno;
		goto err;
	}

err:
	return rc;
}

static int clean_process(pid_t pid)
{
	int rc = -ESRCH;
	int wait = 0;

	wait = 100;
	do {
		/* Wait for parent process completion */
		if (!check_process(pid)) {
			struct store_pid *pid_value = NULL;

			log_debug("[%d] detect abnormal termination\n", pid);
			pid_value = hash_get(daemon_cfg.ht, pid);
			if (pid_value) {
				struct rst_info rst;
				struct store_fid *fid_value = NULL;
				struct store_flow *flow_value = NULL;
				struct list_head *cur_entry = NULL;
				struct list_head *tmp_entry = NULL;
				int i, j;

				/* Cleanup flow store */
				j = 0;
				list_for_each_safe(cur_entry, tmp_entry, &pid_value->flow_list) {
					flow_value = list_entry(cur_entry, struct store_flow, item);
					j++;
					log_debug("[%d] #%d found handle: 0x%08X type: %d if_id: %d tap_id: %d\n",
							pid_value->pid, j,
							flow_value->handle, flow_value->type, flow_value->if_id, flow_value->tap_id);
					list_del_init(&flow_value->item);
					del_flow(pid_value, flow_value);
					free(flow_value);
				}

				/* Cleanup fid store */
				j = 0;
				for (i = 0; (i < hash_size(pid_value->ht)) &&
							(j < hash_count(pid_value->ht)); i++) {
					fid_value = hash_enum(pid_value->ht, i);
					if (NULL == fid_value) {
						continue;
					}

					j++;
					log_debug("[%d] #%d found fid: %d type: %d state: %d\n",
							pid_value->pid, j,
							fid_value->fid, fid_value->type, fid_value->state);

					if (STATE_ESTABLISHED != fid_value->state) {
						log_debug("[%d] #%d skip fid: %d\n",
								pid_value->pid, j, fid_value->fid);
						continue;
					}

					log_debug("[%d] #%d process fid: %d\n",
							pid_value->pid, j, fid_value->fid);

					/* Notification is based on sending RST packet to all peers
					 * and looks as spoofing attacks that uses a technique
					 * called Sequence Number Prediction.
					 * This actively sends spoofed SYN packets and learns the
					 *  SeqNo number from the answer. It then sends RST packets.
					 * P1 - terminated process
					 * P2 - peer of terminated process
					 * H  - host (kernel) of terminated process
					 * 1. [P1] sends SYN to [P2] with source IP of [H].
					 * 2. [P2] replies to [H] by SYN/ACK.
					 * 3. There is a possibility of:
					 *    3.1 [H] should reply to an unknown SYN/ACK by RST.
					 *    3.2 [P1] sends RST using SeqNo from SYN/ACK.
					 */
					rst.local_addr.sin_family = AF_INET;
					rst.local_addr.sin_port = fid_value->src_port;
					rst.local_addr.sin_addr.s_addr = fid_value->src_ip;
					rst.remote_addr.sin_family = AF_INET;
					rst.remote_addr.sin_port = fid_value->dst_port;
					rst.remote_addr.sin_addr.s_addr = fid_value->dst_ip;
					rst.seqno = 1;

					if (0 == get_seqno(&rst) && daemon_cfg.opt.force_rst) {
						send_rst(&rst);
					}
				}

				hash_del(daemon_cfg.ht, pid);
				log_debug("[%d] remove from the storage\n", pid);

				/* Set OK */
				rc = 0;
			}
			break;
		}
		usleep(10000);
	} while (wait--);

	return rc;
}

static int check_process(pid_t pid)
{
	char process_file[PATH_MAX];
	int rc = 0;

	rc = snprintf(process_file, sizeof(process_file), "/proc/%d/stat", pid);
	if ((0 < rc) && (rc < (int)sizeof(process_file))) {
		FILE* fd = fopen(process_file, "r");
		if (fd) {
			int pid_v = 0;
			char name_v[32];
			char stat_v = 0;

			rc = fscanf(fd, "%d %30s %c", &pid_v, name_v, &stat_v);
			fclose(fd);
			if (rc == 3 && stat_v != 'Z') {
				return 1;
			}
		}
	}

	return 0;
}

static unsigned short calc_csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*) &oddbyte) = *(u_char*) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short) ~sum;

	return (answer);
}

static int get_seqno(struct rst_info *rst)
{
	int rc = 0;
	struct tcp_msg msg;
	struct pseudo_header pheader;
	int attempt = 3; /* Do maximum number of attempts */
	struct timeval t_end = TIMEVAL_INITIALIZER;
	struct timeval t_now = TIMEVAL_INITIALIZER;
	struct timeval t_wait = TIMEVAL_INITIALIZER; /* Defines wait interval, holds difference between t_now and t_end */

	/* zero out the packet */
	memset(&msg, 0, sizeof(msg));

	/* IP Header */
	msg.ip.version = 4;
	msg.ip.ihl = 5;
	msg.ip.tos = 0;
	msg.ip.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	msg.ip.id = 0;
	msg.ip.frag_off = htons(0x4000);         /* Flag: "Don't Fragment" */
	msg.ip.ttl = 0x40;
	msg.ip.protocol = IPPROTO_TCP;
	msg.ip.check = 0;
	msg.ip.saddr = rst->local_addr.sin_addr.s_addr;
	msg.ip.daddr = rst->remote_addr.sin_addr.s_addr;

	/* Calculate IP header checksum */
	msg.ip.check = calc_csum((unsigned short *)&msg.ip, sizeof(msg.ip));

	/* TCP Header */
	msg.tcp.source = rst->local_addr.sin_port;
	msg.tcp.dest = rst->remote_addr.sin_port;
	msg.tcp.seq = rst->seqno;
	msg.tcp.ack_seq = 0;
	msg.tcp.doff = 5;
	msg.tcp.fin = 0;
	msg.tcp.syn = 1;
	msg.tcp.rst = 0;
	msg.tcp.psh = 0;
	msg.tcp.ack = 0;
	msg.tcp.urg = 0;
	msg.tcp.window = 0;
	msg.tcp.check = 0;
	msg.tcp.urg_ptr = 0;

	/* Calculate TCP header checksum */
	pheader.source_address = msg.ip.saddr;
	pheader.dest_address = msg.ip.daddr;
	pheader.placeholder = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.tcp_length = htons(sizeof(struct tcphdr));
	bcopy((const void *)&msg.tcp, (void *)&pheader.tcp, sizeof(struct tcphdr));
	msg.tcp.check = calc_csum((unsigned short *)&pheader, sizeof(pheader));

	do {
		/* Send invalid SYN packet */
		rc = sys_sendto(daemon_cfg.raw_fd, &msg, sizeof(msg) - sizeof(msg.data), 0,
				(struct sockaddr *) &rst->remote_addr, sizeof(rst->remote_addr));
		if (rc < 0) {
			goto out;
		}
		log_debug("send SYN to: %s\n", sys_addr2str(&rst->remote_addr));
		t_wait.tv_sec = daemon_cfg.opt.retry_interval / 1000;
		t_wait.tv_usec = (daemon_cfg.opt.retry_interval % 1000) * 1000;
		gettimeofday(&t_end, NULL);

		/* Account for wrapping of tv_usec, use libvma utils macro for timeradd() */
		tv_add(&t_end, &t_wait, &t_end);

		do {
			struct tcp_msg msg_recv;
			struct sockaddr_in gotaddr;
			socklen_t addrlen = sizeof(gotaddr);
			fd_set readfds;

			FD_ZERO(&readfds);
			FD_SET(daemon_cfg.raw_fd, &readfds);

			/* Use t_difference to determine timeout for select so we don't wait longer than t_wait */
			rc = select(daemon_cfg.raw_fd + 1, &readfds, NULL, NULL, &t_wait);
			gettimeofday(&t_now, NULL);

			/**
			 * Determine and save difference between t_now and t_end for select on next iteration.
			 */
			tv_sub(&t_end, &t_now, &t_wait);

			if (rc == 0) {
				continue;
			}

			memcpy(&gotaddr, &rst->remote_addr, addrlen);
			memset(&msg_recv, 0, sizeof(msg_recv));
			rc = recvfrom(daemon_cfg.raw_fd, &msg_recv, sizeof(msg_recv), 0, (struct sockaddr *)&gotaddr, &addrlen);
			if (rc < 0) {
				goto out;
			}
			if (msg_recv.ip.version == 4 &&
					msg_recv.ip.ihl == 5 &&
					msg_recv.ip.protocol == IPPROTO_TCP &&
					msg_recv.ip.saddr == msg.ip.daddr &&
					msg_recv.ip.daddr == msg.ip.saddr &&
					msg_recv.tcp.source == msg.tcp.dest &&
					msg_recv.tcp.dest == msg.tcp.source &&
					msg_recv.tcp.ack == 1) {
				rst->seqno = msg_recv.tcp.ack_seq;
				log_debug("recv SYN|ACK from: %s with SegNo: %d\n",
						sys_addr2str(&gotaddr), ntohl(rst->seqno));
				return 0;
			}
		} while (tv_cmp(&t_now, &t_end, <));
	} while (--attempt);

out:
	return -EAGAIN;
}

static int send_rst(struct rst_info *rst) {
	int rc = 0;
	struct tcp_msg msg;
	struct pseudo_header pheader;

	/* zero out the packet */
	memset(&msg, 0, sizeof(msg));

	/* IP Header */
	msg.ip.version = 4;
	msg.ip.ihl = 5;
	msg.ip.tos = 0;
	msg.ip.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	msg.ip.id = 0;
	msg.ip.frag_off = htons(0x4000);         /* Flag: "Don't Fragment" */
	msg.ip.ttl = 0x40;
	msg.ip.protocol = IPPROTO_TCP;
	msg.ip.check = 0;
	msg.ip.saddr = rst->local_addr.sin_addr.s_addr;
	msg.ip.daddr = rst->remote_addr.sin_addr.s_addr;

	/* Calculate IP header checksum */
	msg.ip.check = calc_csum((unsigned short *)&msg.ip, sizeof(msg.ip));

	/* TCP Header */
	msg.tcp.source = rst->local_addr.sin_port;
	msg.tcp.dest = rst->remote_addr.sin_port;
	msg.tcp.seq = rst->seqno;
	msg.tcp.ack_seq = 0;
	msg.tcp.doff = 5;
	msg.tcp.fin = 0;
	msg.tcp.syn = 0;
	msg.tcp.rst = 1;
	msg.tcp.psh = 0;
	msg.tcp.ack = 0;
	msg.tcp.urg = 0;
	msg.tcp.window = 0;
	msg.tcp.check = 0;
	msg.tcp.urg_ptr = 0;

	/* Calculate TCP header checksum */
	pheader.source_address = msg.ip.saddr;
	pheader.dest_address = msg.ip.daddr;
	pheader.placeholder = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.tcp_length = htons(sizeof(struct tcphdr));
	bcopy((const void *)&msg.tcp, (void *)&pheader.tcp, sizeof(struct tcphdr));
	msg.tcp.check = calc_csum((unsigned short *)&pheader, sizeof(pheader));

	rc = sys_sendto(daemon_cfg.raw_fd, &msg, sizeof(msg) - sizeof(msg.data), 0,
			(struct sockaddr *) &rst->remote_addr, sizeof(rst->remote_addr));
	if (rc < 0) {
		goto out;
	}
	log_debug("send RST to: %s\n", sys_addr2str(&rst->remote_addr));

	rc = 0;

out:
	return rc;
}

#ifdef HAVE_SYS_FANOTIFY_H
static int open_fanotify(void)
{
	int rc = 0;

	log_debug("selected fanotify ...\n");

	if ((daemon_cfg.notify_fd = fanotify_init(0, KERNEL_O_LARGEFILE)) < 0) {
		log_error("Cannot initialize fanotify_init() errno %d (%s)\n", errno,
				strerror(errno));
		rc = -errno;
		goto err;
	}

	rc = fanotify_mark(daemon_cfg.notify_fd, FAN_MARK_ADD,
			FAN_CLOSE | FAN_EVENT_ON_CHILD, AT_FDCWD,
			daemon_cfg.notify_dir);
	if (rc < 0) {
		rc = -errno;
		log_error("Failed to add watch for directory %s errno %d (%s)\n",
				daemon_cfg.notify_dir, errno, strerror(errno));
		goto err;
	}

err:
	return rc;
}

static int proc_fanotify(void *buffer, int nbyte)
{
	int rc = 0;
	int len = nbyte;
	struct fanotify_event_metadata *data = (struct fanotify_event_metadata *)buffer;

	while (FAN_EVENT_OK(data, len)) {

		/* Check that run-time and compile-time structures match */
		if (data->vers != FANOTIFY_METADATA_VERSION) {
			rc = -EPROTO;
			log_error("Mismatch of fanotify metadata version\n");
			goto err;
		}
		/* Current check is based on monitoring special pid file events
		 * This file is created on library startup
		 * Event about closing this file should come if process exits
		 * either after work completion or as result of unexpected termination
		 */
		if ((data->mask & FAN_CLOSE_WRITE || data->mask & FAN_CLOSE_NOWRITE) &&
				hash_get(daemon_cfg.ht, data->pid)) {
			char buf[PATH_MAX];
			char pathname[PATH_MAX];

			memset(buf, 0, sizeof(buf));
			memset(pathname, 0, sizeof(pathname));

			rc = snprintf(buf, sizeof(buf) - 1, "/proc/self/fd/%d", data->fd);
			if ((rc < 0 ) || (rc == (sizeof(buf) - 1) )) {
				rc = -ENOMEM;
				log_error("Cannot read process name errno %d (%s)\n", errno,
					strerror(errno));
				goto err;
			}
			rc = readlink(buf, pathname, sizeof(pathname) - 1);
			if (rc < 0) {
				rc = -ENOMEM;
				log_error("Cannot read process name errno %d (%s)\n", errno,
					strerror(errno));
				goto err;
			}

			log_debug("getting event ([0x%x] pid: %d fd: %d name: %s)\n",
					data->mask, data->pid, data->fd, pathname);

			rc = snprintf(buf, sizeof(buf) - 1, "%s/%s.%d.pid",
					daemon_cfg.notify_dir, VMA_AGENT_BASE_NAME, data->pid);
			if ((rc < 0 ) || (rc == (sizeof(buf) - 1) )) {
				rc = -ENOMEM;
				log_error("failed allocate pid file errno %d (%s)\n", errno,
					strerror(errno));
				goto err;
			}

			/* Process event related pid file only */
			rc = 0;
			if (!strncmp(buf, pathname, strlen(buf))) {
				log_debug("[%d] check the event\n", data->pid);

				/* Check if termination is unexpected and send RST to peers
				 * Return status should be 0 in case we send RST and
				 * nonzero in case we decide that processes exited accurately
				 * or some internal error happens during RST send
				 */
				rc = clean_process(data->pid);
				if (0 == rc) {
					/* Cleanup unexpected termination */
					log_debug("[%d] cleanup after unexpected termination\n", data->pid);
					/* To suppress TOCTOU (time-of-check, time-of-use race condition) */
					strcpy(pathname, buf);
					unlink(pathname);
					if (snprintf(pathname, sizeof(pathname) - 1, "%s/%s.%d.sock",
							daemon_cfg.notify_dir, VMA_AGENT_BASE_NAME, data->pid) > 0) {
						unlink(pathname);
					}
				} else if (-ESRCH == rc) {
					/* No need in peer notification */
					log_debug("[%d] no need in peer notification\n", data->pid);
					rc = 0;
				}
			} else {
				log_debug("[%d] skip the event\n", data->pid);
			}
		}

		/* Close the file descriptor of the event */
		close(data->fd);
		data = FAN_EVENT_NEXT(data, len);
	}

err:
	return rc;
}
#endif

#ifdef HAVE_SYS_INOTIFY_H
static int open_inotify(void)
{
	int rc = 0;

	log_debug("selected inotify ...\n");

	if ((daemon_cfg.notify_fd = inotify_init()) < 0) {
		log_error("Cannot initialize inotify_init() errno %d (%s)\n", errno,
				strerror(errno));
		rc = -errno;
		goto err;
	}

	rc = inotify_add_watch(daemon_cfg.notify_fd,
			daemon_cfg.notify_dir,
			IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_DELETE);
	if (rc < 0) {
		rc = -errno;
		log_error("Failed to add watch for directory %s errno %d (%s)\n",
				daemon_cfg.notify_dir, errno, strerror(errno));
		goto err;
	}

err:
	return rc;
}

static int proc_inotify(void *buffer, int nbyte)
{
	int rc = 0;
	struct inotify_event *data = (struct inotify_event *)buffer;

	while ((uintptr_t)data < ((uintptr_t)buffer + nbyte)) {
		pid_t pid;

		/* Monitor only events from files */
		if ((data->len > 0) &&
				!(data->mask & IN_ISDIR ) &&
				(1 == sscanf(data->name, VMA_AGENT_BASE_NAME ".%d.pid", &pid)) &&
				hash_get(daemon_cfg.ht, pid)) {

			char buf[PATH_MAX];
			char pathname[PATH_MAX];

			memset(buf, 0, sizeof(buf));
			memset(pathname, 0, sizeof(pathname));

			rc = snprintf(pathname, sizeof(pathname) - 1, "%s/%s",
					daemon_cfg.notify_dir, data->name);
			if ((rc < 0 ) || (rc == (sizeof(pathname) - 1) )) {
				rc = -ENOMEM;
				log_error("failed allocate pid file errno %d (%s)\n", errno,
					strerror(errno));
				goto err;
			}

			log_debug("getting event ([0x%x] pid: %d name: %s)\n",
					data->mask, pid, pathname);

			rc = snprintf(buf, sizeof(buf) - 1, "%s/%s.%d.pid",
					daemon_cfg.notify_dir, VMA_AGENT_BASE_NAME, pid);
			if ((rc < 0 ) || (rc == (sizeof(buf) - 1) )) {
				rc = -ENOMEM;
				log_error("failed allocate pid file errno %d (%s)\n", errno,
					strerror(errno));
				goto err;
			}

			/* Process event related pid file only */
			rc = 0;
			if (!strncmp(buf, pathname, strlen(buf))) {
				log_debug("[%d] check the event\n", pid);

				/* Check if termination is unexpected and send RST to peers
				 * Return status should be 0 in case we send RST and
				 * nonzero in case we decide that processes exited accurately
				 * or some internal error happens during RST send
				 */
				rc = clean_process(pid);
				if (0 == rc) {
					/* Cleanup unexpected termination */
					log_debug("[%d] cleanup after unexpected termination\n", pid);
					unlink(buf);
					if (snprintf(buf, sizeof(buf) - 1, "%s/%s.%d.sock",
							daemon_cfg.notify_dir, VMA_AGENT_BASE_NAME, pid) > 0) {
						unlink(buf);
					}
				} else if (-ESRCH == rc) {
					/* No need in peer notification */
					log_debug("[%d] no need in peer notification\n", pid);
					rc = 0;
				}
			} else {
				log_debug("[%d] skip the event\n", pid);
			}
		}

		/* Move to the next event */
		data =  (struct inotify_event *)((uintptr_t)data + sizeof(*data) + data->len);
	}

err:
	return rc;
}
#endif
