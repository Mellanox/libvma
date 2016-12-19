/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd. All rights reserved.
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

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<errno.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include <signal.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#ifdef HAVE_LINUX_LIMITS_H
#include <linux/limits.h>
#endif

#include "vlogger/vlogger.h"
#include "vma/util/vma_stats.h"
#include "vma/sock/sock-redirect.h"


#define MODULE_NAME             "abort"

#define STATE_ESTABLISHED	4

#ifndef HAVE_LINUX_LIMITS_H
#define NAME_MAX         255    /* chars in a file name */
#define PATH_MAX        4096    /* chars in a path name including null */
#endif

#define _sys_call(_result, _func, ...) \
	do {                                              \
		if (orig_os_api._func)                        \
			_result = orig_os_api._func(__VA_ARGS__); \
		else                                          \
			_result = _func(__VA_ARGS__);             \
	} while (0)

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

static volatile sig_atomic_t _sig;
static int _raw_fd;

static void _handle_signal(int signo, siginfo_t *info, void *context);
static int _check_version(version_info_t* p_stat_ver_info);
static bool _check_process(pid_t pid);
static unsigned short _calc_csum(unsigned short *ptr, int nbytes);
static int _get_seqno(struct rst_info *rst);
static int _send_rst(struct rst_info *rst);
static void _proc_peer_notification(pid_t pid);

int proc_abort(void)
{
	int rc = 0;
	pid_t pid;
	pid_t parent_pid = getpid();

	_sys_call(pid, fork);
	if (pid < 0) {
		__log_err("fork() call failed (errno = %d)\n", errno);
		rc = -errno;
		return rc;
	} else if (pid == 0) {
		struct sigaction sa;
		sigset_t mask, oldmask;
		int wait;
		int optval = 1;
		uid_t cur_uid = getuid();

		_raw_fd = -1;
		if (setuid(0) < 0) {
			goto err;
		}
		_sys_call(_raw_fd, socket, PF_INET, SOCK_RAW, IPPROTO_TCP);
		if (_raw_fd < 0) {
			/* socket creation failed, may be because of non-root privileges */
			__log_err("Failed to create socket (errno = %d)\n", errno);
			rc = -errno;
			goto err;
		}

		optval = 1;
		_sys_call(rc, setsockopt, _raw_fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
		if (rc < 0) {
			__log_err("Error setting IP_HDRINCL (errno = %d)\n", errno);
			goto err;
		}
		if (setuid(cur_uid) < 0) {
			goto err;
		}

		sa.sa_sigaction = &_handle_signal;
		sa.sa_flags = SA_SIGINFO;
		sigfillset(&sa.sa_mask);
		if (sigaction(SIGUSR1, &sa, NULL) < 0) {
			__log_err("cannot register SIGUSR1 signal handler (errno = %d)\n", errno);
			rc = -errno;
			goto err;
		}
#ifdef HAVE_SYS_PRCTL_H
		if (prctl(PR_SET_PDEATHSIG, SIGUSR1) < 0) {
			__log_err("cannot register PR_SET_PDEATHSIG event (errno = %d)\n", errno);
			rc = -errno;
			goto err;
		}
#else
		goto err;
#endif
		/* Set up the mask of signals to temporarily block. */
		_sig = 0;
		sigemptyset(&mask);
		sigaddset(&mask, SIGUSR1);

		/* Wait for a signal to arrive. */
		sigprocmask(SIG_BLOCK, &mask, &oldmask);
		while (!_sig) {
			sigsuspend(&oldmask);
		}
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		_sig = 0;

		/* Wait for parent process completion and run cleanup */
		wait = 100;
		do {
			if (!_check_process(parent_pid)) {
				_proc_peer_notification(parent_pid);
				break;
			}
			usleep(10000);
		} while (wait--);

		_exit(0);
err:
		vlog_printf(VLOG_WARNING,"Peer notification functionality is not supported\n");
		if (_raw_fd >0) {
			_sys_call(rc, close, _raw_fd);
		}
		_exit(0);
	}

	return rc;
}

static void _handle_signal(int signo, siginfo_t *info, void *context)
{
	NOT_IN_USE(info);
	NOT_IN_USE(context);

	__log_dbg("Child process (%d) is processing signal (%d)\n", getpid(), signo);
	switch (signo) {
	case SIGUSR1:
		_sig++;
		break;
	default:
		return;
	}
}

static int _check_version(version_info_t* p_stat_ver_info)
{
	return (p_stat_ver_info->vma_lib_maj == VMA_LIBRARY_MAJOR &&
		p_stat_ver_info->vma_lib_min == VMA_LIBRARY_MINOR &&
		p_stat_ver_info->vma_lib_rel == VMA_LIBRARY_RELEASE &&
		p_stat_ver_info->vma_lib_rev == VMA_LIBRARY_REVISION);
}

static bool _check_process(pid_t pid)
{
	char pid_str[NAME_MAX];
	char proccess_proc_dir[PATH_MAX];
	struct stat st;

	sprintf(pid_str, "%d", pid);
	memset((void*)proccess_proc_dir, 0, sizeof(PATH_MAX));
	strcat(strcpy(proccess_proc_dir, "/proc/"), pid_str);
	return stat(proccess_proc_dir, &st) == 0;

}

static unsigned short _calc_csum(unsigned short *ptr, int nbytes)
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

static int _get_seqno(struct rst_info *rst)
{
	int rc = 0;
	time_t wait;
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
	msg.ip.check = _calc_csum((unsigned short *)&msg.ip, sizeof(msg.ip));

	/* TCP Header */
	msg.tcp.source = rst->local_addr.sin_port;
	msg.tcp.dest = rst->remote_addr.sin_port;
	msg.tcp.seq = rst->seqno;
	msg.tcp.ack_seq = 0;
	msg.tcp.doff = 5;
	msg.tcp.fin = 1;
	msg.tcp.syn = 0;
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
	msg.tcp.check = _calc_csum((unsigned short *)&pheader, sizeof(pheader));

	/* Send invalid FIN packet */
	_sys_call(rc, sendto, _raw_fd, &msg, sizeof(msg) - sizeof(msg.data), 0,
			(struct sockaddr *) &rst->remote_addr, sizeof(rst->remote_addr));
	if (rc < 0) {
		__log_err("sendto failed (errno = %d)\n", errno);
		goto out;
	}
	rc = 0;

	/* Wait for 10s */
	wait = time(0) + 10;
	do {
		struct tcp_msg msg_recv;
		struct sockaddr_in gotaddr;
		socklen_t addrlen = sizeof(gotaddr);
		fd_set readfds;
		struct timeval tv;

		FD_ZERO(&readfds);
		FD_SET(_raw_fd, &readfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		_sys_call(rc, select, _raw_fd + 1, &readfds, NULL, NULL, &tv);
		if (rc == 0) {
			continue;
		}
		memcpy(&gotaddr, &rst->remote_addr, addrlen);
		memset(&msg_recv, 0, sizeof(msg_recv));
		_sys_call(rc, recvfrom, _raw_fd, &msg_recv, sizeof(msg_recv), 0, (struct sockaddr *)&gotaddr, &addrlen);
		if (rc < 0) {
			__log_err("recvfrom failed (errno = %d)\n", errno);
			goto out;
		}

		if ( msg_recv.ip.version == 4 &&
				msg_recv.ip.ihl == 5 &&
				msg_recv.ip.protocol == IPPROTO_TCP &&
				msg_recv.ip.saddr == msg.ip.daddr &&
				msg_recv.ip.daddr == msg.ip.saddr &&
				msg_recv.tcp.source == msg.tcp.dest &&
				msg_recv.tcp.dest == msg.tcp.source &&
				msg_recv.tcp.ack == 1 ) {
			rst->seqno = msg_recv.tcp.ack_seq;
			rc = 0;
			break;
		}
	} while (time(0) < wait);

out:
	return rc;
}

static int _send_rst(struct rst_info *rst) {
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
	msg.ip.check = _calc_csum((unsigned short *)&msg.ip, sizeof(msg.ip));

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
	msg.tcp.check = _calc_csum((unsigned short *)&pheader, sizeof(pheader));

	_sys_call(rc, sendto, _raw_fd, &msg, sizeof(msg) - sizeof(msg.data), 0,
			(struct sockaddr *) &rst->remote_addr, sizeof(rst->remote_addr));
	if (rc < 0) {
		__log_err("sendto failed (errno = %d)\n", errno);
		goto out;
	}
	rc = 0;

out:
	return rc;
}

static void _proc_peer_notification(pid_t pid)
{
	int rc = 0;
	sh_mem_t* sh_mem;
	sh_mem_info_t sh_mem_info;

	__log_dbg("Start peer notification\n");

	/* Form shared file name */
	memset(&sh_mem_info, 0, sizeof(sh_mem_info));
	sh_mem_info.pid = pid;
	sprintf(sh_mem_info.filename_sh_stats, "%s/vmastat.%d", MCE_DEFAULT_STATS_SHMEM_DIR, pid);

	/* Open shared file:
	 * If errno=ENOENT then file is closed during normal parent process exit.
	 * So skip peer notification in this case
	 */
	sh_mem_info.fd_sh_stats = open(sh_mem_info.filename_sh_stats,  O_RDONLY);
	if (sh_mem_info.fd_sh_stats < 0) {
		if (errno != ENOENT) {
			__log_err("VMA statistics data for process id %d not found errno=%d\n", pid, errno);
			rc = -errno;
		}
		return ;
	}

	sh_mem_info.p_sh_stats = mmap(0, sizeof(sh_mem_t), PROT_READ, MAP_SHARED, sh_mem_info.fd_sh_stats, 0);
	MAP_SH_MEM(sh_mem, sh_mem_info.p_sh_stats);
	if (sh_mem_info.p_sh_stats == MAP_FAILED) {
		__log_err("mmap failed (errno = %d)\n", errno);
		rc = -errno;
		goto out;
	}

	/* Validate data layout */
	if (sizeof(STATS_PROTOCOL_VER) > 1) {
		if (memcmp(sh_mem->stats_protocol_ver, STATS_PROTOCOL_VER, min(sizeof(sh_mem->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER)))) {
			__log_err("Version %s is not compatible with stats protocol version %s\n",
					STATS_PROTOCOL_VER, sh_mem->stats_protocol_ver);
			rc = -EPROTO;
		}
	} else {
		if (!_check_version(&sh_mem->ver_info)) {
			__log_err("Version %d.%d.%d.%d is not compatible with VMA version %d.%d.%d.%d\n",
					VMA_LIBRARY_MAJOR, VMA_LIBRARY_MINOR,
					VMA_LIBRARY_REVISION, VMA_LIBRARY_RELEASE,
					sh_mem->ver_info.vma_lib_maj, sh_mem->ver_info.vma_lib_min,
					sh_mem->ver_info.vma_lib_rev, sh_mem->ver_info.vma_lib_rel);
			rc = -EPROTO;
		}
	}
	if (rc != 0) {
		goto out;
	}

	sh_mem_info.shmem_size = SHMEM_STATS_SIZE(sh_mem->max_skt_inst_num);
	if (munmap(sh_mem_info.p_sh_stats, sizeof(sh_mem_t)) != 0) {
		rc = -errno;
		goto out;
	}

	sh_mem_info.p_sh_stats = mmap(0, sh_mem_info.shmem_size, PROT_READ, MAP_SHARED, sh_mem_info.fd_sh_stats, 0);
	MAP_SH_MEM(sh_mem, sh_mem_info.p_sh_stats);
	if (sh_mem_info.p_sh_stats == MAP_FAILED) {
		__log_err("mmap failed (errno = %d)\n", errno);
		rc = -errno;
		goto out;
	}

	/* Load data from shared memory */
	{
		socket_instance_block_t *curr_instance_blocks;
		struct rst_info rst;
		int i = 0;

		curr_instance_blocks = (socket_instance_block_t *)malloc(sizeof(*curr_instance_blocks) * sh_mem->max_skt_inst_num);
		if (NULL == curr_instance_blocks) {
			rc = -ENOMEM;
			goto out;
		}
		memcpy((void*)curr_instance_blocks, (void*)sh_mem->skt_inst_arr, sizeof(*curr_instance_blocks) * sh_mem->max_skt_inst_num);

		for (i = 0; (i < (int)sh_mem->max_skt_inst_num) && (0 == rc); i++) {
			/* Process only offloaded TCP sockets in ESTABLISHED state */
			if (curr_instance_blocks[i].b_enabled &&
					curr_instance_blocks[i].skt_stats.b_is_offloaded &&
					curr_instance_blocks[i].skt_stats.socket_type == SOCK_STREAM &&
					curr_instance_blocks[i].skt_stats.tcp_state == STATE_ESTABLISHED) {
				rst.local_addr.sin_family = AF_INET;
				rst.local_addr.sin_port = curr_instance_blocks[i].skt_stats.bound_port;
				rst.local_addr.sin_addr.s_addr = curr_instance_blocks[i].skt_stats.bound_if;
				rst.remote_addr.sin_family = AF_INET;
				rst.remote_addr.sin_port = curr_instance_blocks[i].skt_stats.connected_port;
				rst.remote_addr.sin_addr.s_addr = curr_instance_blocks[i].skt_stats.connected_ip;
				rst.seqno = 1;

				/* Notification is based on sending RST packet to all peers
				 * and looks as spoofing attacks that uses a technique called
				 * Sequence Number Prediction.
				 * This actively sends spoofed FIN packets and learns the SeqNo
				 * number from the answer. It then sends RST packets.
				 * P1 - terminated process
				 * P2 - peer of terminated process
				 * H  - host (kernel) of terminated process
				 * 1. [P1] sends SYN to [P2] with source IP of [H].
				 * 2. [P2] replies to [H] by SYN/ACK.
				 * 3. There is a possibility of:
				 *    3.1 [H] should reply to an unknown SYN/ACK by RST.
				 *    3.2 [P1] sends RST using SeqNo from SYN/ACK.
				 */
				rc = _get_seqno(&rst);
				if (0 == rc) {
					rc = _send_rst(&rst);
				}
			}
		}

		free(curr_instance_blocks);
	}

out:
	/* Free used resources */
	if (sh_mem_info.p_sh_stats != MAP_FAILED)
	{
		if (munmap(sh_mem_info.p_sh_stats, sh_mem_info.shmem_size) != 0) {
			__log_err("file='%s' sh_mem_info.fd_sh_stats=%d; error while munmap shared memory at [%p]\n", sh_mem_info.filename_sh_stats, sh_mem_info.fd_sh_stats, sh_mem_info.p_sh_stats);
		}
	}
	close(sh_mem_info.fd_sh_stats);

	unlink(sh_mem_info.filename_sh_stats);

	return ;
}
