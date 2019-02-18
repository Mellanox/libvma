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


#include "sock-redirect.h"

#include <sys/time.h>
#include <dlfcn.h>
#include <iostream>

#include "utils/lock_wrapper.h"
#include <vma/proto/ip_frag.h>
#include <vma/dev/buffer_pool.h>
#include <vma/dev/ring_eth_cb.h>
#include <vma/dev/ring_profile.h>
#include <vma/event/event_handler_manager.h>
#include <vma/event/vlogger_timer_handler.h>
#include <vma/iomux/poll_call.h>
#include <vma/iomux/select_call.h>
#include <vma/iomux/epfd_info.h>
#include <vma/iomux/epoll_wait_call.h>
#include <vma/util/sys_vars.h>
#include <vma/proto/route_table_mgr.h>
#include <vma/proto/vma_lwip.h>
#include <vma/main.h>
#include "vma/vma_extra.h"

#include <vma/sock/sockinfo_tcp.h>

#include "fd_collection.h"
#include "vma/util/instrumentation.h"

using namespace std;


#define MODULE_NAME 		"srdr:"

#define srdr_logpanic		__log_panic
#define srdr_logerr		__log_err
#define srdr_logwarn		__log_warn
#define srdr_loginfo		__log_info
#define srdr_logdbg		__log_dbg
#define srdr_logfunc		__log_func
#define srdr_logfuncall		__log_funcall

#define srdr_logdbg_entry	__log_entry_dbg
#define srdr_logfunc_entry	__log_entry_func
#define srdr_logfuncall_entry	__log_entry_funcall

#define srdr_logdbg_exit	__log_exit_dbg
#define srdr_logfunc_exit	__log_exit_func

#define EP_MAX_EVENTS (int)((INT_MAX / sizeof(struct epoll_event)))
#define SENDFILE_BUFFER_SIZE 1460

struct os_api orig_os_api;
struct sigaction g_act_prev;
sighandler_t g_sighandler = NULL;
class ring_simple;
class ring_eth_cb;
class ring_eth_direct;

template<typename T>
void assign_dlsym(T &ptr, const char *name) {
	ptr = reinterpret_cast<T>(dlsym(RTLD_NEXT, name));
}

#define FD_MAP_SIZE 		(g_p_fd_collection ? g_p_fd_collection->get_fd_map_size() : 1024)

#define DO_GLOBAL_CTORS() do { \
	int __res = do_global_ctors(); \
	if (__res) { \
		vlog_printf(VLOG_ERROR, "%s vma failed to start errno: %m\n", \
			__FUNCTION__, errno); \
		if (safe_mce_sys().exception_handling == vma_exception_handling::MODE_EXIT) { \
			exit(-1); \
		} \
		return -1; \
	} \
} while (0)

#define GET_ORIG_FUNC(__name) \
	if (!orig_os_api.__name) { \
		dlerror(); \
		assign_dlsym(orig_os_api.__name, #__name); \
		char *dlerror_str = dlerror(); \
		if (dlerror_str) { \
			__log_warn("dlsym returned with error '%s' when looking for '%s'", \
			           dlerror_str, #__name); \
		} else { \
			__log_dbg("dlsym found %p for '%s()'", orig_os_api.__name , #__name); \
		} \
	}

#define SET_EXTRA_API(dst, func, mask) do { \
		vma_api->dst = func; \
		vma_api->vma_extra_supported_mask |= mask; \
} while(0);

#define VERIFY_PASSTROUGH_CHANGED(__ret, __func_and_params__) do { \
		bool passthrough = p_socket_object->isPassthrough(); \
		__ret = __func_and_params__; \
		if (!passthrough && p_socket_object->isPassthrough()) { \
			handle_close(__fd, false, true); \
		} \
} while(0);

void get_orig_funcs()
{
	// Save pointer to original functions
	GET_ORIG_FUNC(socket);
	GET_ORIG_FUNC(close);
	GET_ORIG_FUNC(close);
	GET_ORIG_FUNC(__res_iclose);
	GET_ORIG_FUNC(shutdown);
	GET_ORIG_FUNC(listen);
	GET_ORIG_FUNC(accept);
	GET_ORIG_FUNC(accept4);
	GET_ORIG_FUNC(bind);
	GET_ORIG_FUNC(connect);
	GET_ORIG_FUNC(setsockopt);
	GET_ORIG_FUNC(getsockopt);
	GET_ORIG_FUNC(fcntl);
	GET_ORIG_FUNC(ioctl);
	GET_ORIG_FUNC(getsockname);
	GET_ORIG_FUNC(getpeername);
	GET_ORIG_FUNC(read);
	GET_ORIG_FUNC(__read_chk);
	GET_ORIG_FUNC(readv);
	GET_ORIG_FUNC(recv);
	GET_ORIG_FUNC(__recv_chk);
	GET_ORIG_FUNC(recvmsg);
	GET_ORIG_FUNC(recvmmsg);
	GET_ORIG_FUNC(recvfrom);
	GET_ORIG_FUNC(__recvfrom_chk);
	GET_ORIG_FUNC(write);
	GET_ORIG_FUNC(writev);
	GET_ORIG_FUNC(send);
	GET_ORIG_FUNC(sendmsg);
	GET_ORIG_FUNC(sendmmsg);
	GET_ORIG_FUNC(sendto);
	GET_ORIG_FUNC(sendfile);
	GET_ORIG_FUNC(sendfile64);
	GET_ORIG_FUNC(select);
	GET_ORIG_FUNC(pselect);
	GET_ORIG_FUNC(poll);
	GET_ORIG_FUNC(ppoll);
	GET_ORIG_FUNC(epoll_create);
	GET_ORIG_FUNC(epoll_create1);
	GET_ORIG_FUNC(epoll_ctl);
	GET_ORIG_FUNC(epoll_wait);
	GET_ORIG_FUNC(epoll_pwait);
	GET_ORIG_FUNC(socketpair);
	GET_ORIG_FUNC(pipe);
	GET_ORIG_FUNC(open);
	GET_ORIG_FUNC(creat);
	GET_ORIG_FUNC(dup);
	GET_ORIG_FUNC(dup2);
	GET_ORIG_FUNC(clone);
	GET_ORIG_FUNC(fork);
	GET_ORIG_FUNC(vfork);
	GET_ORIG_FUNC(daemon);
	GET_ORIG_FUNC(sigaction);
	GET_ORIG_FUNC(signal);
}

const char* socket_get_domain_str(int domain)
{
	switch (domain) {
	case AF_INET:		return "AF_INET";
	case AF_INET6:		return "AF_INET6";
	case AF_UNSPEC:		return "AF_UNSPEC";
	case AF_LOCAL:		return "AF_LOCAL";
	default:
		break;
	}
	return "";
}

const char* socket_get_type_str(int type)
{
	switch (type) {
	case SOCK_STREAM:	return "SOCK_STREAM";
	case SOCK_DGRAM:	return "SOCK_DGRAM";
	case SOCK_RAW:		return "SOCK_RAW";
	default:
		break;
	}
	return "";
}

// Format a sockaddr into a string for logging
char* sprintf_sockaddr(char* buf, int buflen, const struct sockaddr* _addr, socklen_t _addrlen)
{
	if ((_addrlen >= sizeof(struct sockaddr_in)) && (get_sa_family(_addr) == AF_INET)) {
		in_addr_t in_addr = get_sa_ipv4_addr(_addr);
		in_port_t in_port = get_sa_port(_addr);
		/* cppcheck-suppress wrongPrintfScanfArgNum */
		snprintf(buf, buflen, "AF_INET, addr=%d.%d.%d.%d, port=%d", NIPQUAD(in_addr), ntohs(in_port));
	}
	else {
		snprintf(buf, buflen, "sa_family=%d", get_sa_family(_addr));
	}
	return buf;
}

#define VMA_DBG_SEND_MCPKT_COUNTER_STR "VMA_DBG_SEND_MCPKT_COUNTER"
#define VMA_DBG_SEND_MCPKT_MCGROUP_STR "VMA_DBG_SEND_MCPKT_MCGROUP"
static int dbg_check_if_need_to_send_mcpkt_setting = -1; // 1-Init, 0-Disabled,  N>0-send mc packet on the Nth socket() call
static int dbg_check_if_need_to_send_mcpkt_counter = 1;
static int dbg_check_if_need_to_send_mcpkt_prevent_nested_calls = 0;

void dbg_send_mcpkt()
{
	int fd = 0;
	char *env_ptr = NULL;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		vlog_printf(VLOG_WARNING, "send_mc_packet_test:%d: socket() errno %d %m", __LINE__, errno);
		exit(1);
	}

	struct sockaddr_in addr_in;
	struct sockaddr* p_addr = (struct sockaddr*)&addr_in;

	addr_in.sin_family = AF_INET;
	addr_in.sin_port = INPORT_ANY;
	addr_in.sin_addr.s_addr = INADDR_ANY;
	if ((env_ptr = getenv(VMA_DBG_SEND_MCPKT_MCGROUP_STR)) == NULL) {
		vlog_printf(VLOG_WARNING, "send_mc_packet_test:%d: Need to set '%s' parameter to dest ip (dot format)\n", __LINE__, VMA_DBG_SEND_MCPKT_MCGROUP_STR);
		exit(2);
	}
	if (1 != inet_pton(AF_INET, env_ptr, &addr_in.sin_addr)) {
		vlog_printf(VLOG_WARNING, "send_mc_packet_test:%d: Invalid input IP address: '%s' errno %d %m\n", __LINE__, env_ptr, errno);
		exit(3);
	}

	const char msgbuf[256] = "Hello Alex";

	vlog_printf(VLOG_WARNING, "send_mc_packet_test:%d: Sending MC test packet to address: %d.%d.%d.%d [%s]\n", __LINE__, NIPQUAD(get_sa_ipv4_addr(p_addr)), VMA_DBG_SEND_MCPKT_MCGROUP_STR);
	if (sendto(fd, msgbuf, strlen(msgbuf), 0, p_addr, sizeof(struct sockaddr)) < 0)
		vlog_printf(VLOG_ERROR, "sendto mc_packet failed! errno %m\n", errno);
	close(fd);
}

void dbg_check_if_need_to_send_mcpkt()
{
	if (dbg_check_if_need_to_send_mcpkt_prevent_nested_calls)
		return;
	dbg_check_if_need_to_send_mcpkt_prevent_nested_calls = 1;

	// Read user setting
	if (dbg_check_if_need_to_send_mcpkt_setting == -1) {
		// Default will be 'Disbaled'
		dbg_check_if_need_to_send_mcpkt_setting++;

		// Then we will read the user settings
		char *env_ptr = NULL;
		if ((env_ptr = getenv(VMA_DBG_SEND_MCPKT_COUNTER_STR)) != NULL) {
			dbg_check_if_need_to_send_mcpkt_setting = atoi(env_ptr);
		}
		if (dbg_check_if_need_to_send_mcpkt_setting > 0) {
			vlog_printf(VLOG_WARNING, "send_mc_packet_test: *************************************************************\n");
			vlog_printf(VLOG_WARNING, "send_mc_packet_test: Send test MC packet setting is: %d [%s]\n", dbg_check_if_need_to_send_mcpkt_setting, VMA_DBG_SEND_MCPKT_COUNTER_STR);
			vlog_printf(VLOG_WARNING, "send_mc_packet_test: If you don't know what this means don't use '%s' VMA configuration parameter!\n", VMA_DBG_SEND_MCPKT_COUNTER_STR);
			vlog_printf(VLOG_WARNING, "send_mc_packet_test: *************************************************************\n");
		}
	}

	// Test for action
	if (dbg_check_if_need_to_send_mcpkt_setting > 0) {
		if (dbg_check_if_need_to_send_mcpkt_counter == dbg_check_if_need_to_send_mcpkt_setting)
		{
			// Actual send mc packet
			dbg_send_mcpkt();
		}
		else {
			vlog_printf(VLOG_WARNING, "send_mc_packet_test:%d: Skipping this socket() call\n", __LINE__);
		}
		dbg_check_if_need_to_send_mcpkt_counter++;
	}
	dbg_check_if_need_to_send_mcpkt_prevent_nested_calls--;
}

void handle_close(int fd, bool cleanup, bool passthrough)
{
	
	srdr_logfunc("Cleanup fd=%d", fd);

	if (g_p_fd_collection) {
		// Remove fd from all existing epoll sets
		g_p_fd_collection->remove_from_all_epfds(fd, passthrough);

		if (fd_collection_get_sockfd(fd)) {
			g_p_fd_collection->del_sockfd(fd, cleanup);
		}
		if (fd_collection_get_epfd(fd)) {
			g_p_fd_collection->del_epfd(fd, cleanup);
		}

	}
}


//-----------------------------------------------------------------------------
// extended API functions
//-----------------------------------------------------------------------------

extern "C"
int vma_register_recv_callback(int __fd, vma_recv_callback_t __callback, void *__context)
{
	srdr_logfunc_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		p_socket_object->register_callback(__callback, __context);
		return 0;
	}
	errno = EINVAL;
	return -1;
}

extern "C"
int vma_recvfrom_zcopy(int __fd, void *__buf, size_t __nbytes, int *__flags,
	               struct sockaddr *__from, socklen_t *__fromlen)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		*__flags |= MSG_VMA_ZCOPY;
		return p_socket_object->rx(RX_RECVFROM, piov, 1, __flags, __from, __fromlen);

	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.recvfrom) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END
	return orig_os_api.recvfrom(__fd, __buf, __nbytes, *__flags, __from, __fromlen);
}

extern "C"
int vma_free_packets(int __fd, struct vma_packet_t *pkts, size_t count)
{
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		return p_socket_object->free_packets(pkts, count);
	}

	errno = EINVAL;
	return -1;
}

static int dummy_vma_socketxtreme_poll(int fd, struct vma_completion_t* completions, unsigned int ncompletions, int flags)
{
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG,
			"socketXtreme was not enabled during runtime. Set %s to use. Ignoring...", SYS_VAR_SOCKETXTREME,
			fd, completions, ncompletions, flags);
	errno = EOPNOTSUPP;
	return -1;
}

extern "C"
int vma_socketxtreme_poll(int fd, struct vma_completion_t* completions, unsigned int ncompletions, int flags)
{
	int ret_val = -1;
	cq_channel_info* cq_ch_info = NULL;

	cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);

	if (likely(cq_ch_info)) {
		ring* p_ring = cq_ch_info->get_ring();

		ret_val = p_ring->socketxtreme_poll(completions, ncompletions, flags);
#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM]);
#endif //RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM]);
#endif //RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif //RDTSC_MEASURE_RX_CQE_RECEIVEFROM

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif //RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
	return ret_val;
	}
	else {
		errno = EBADFD;
		return ret_val;
	}
}

static int dummy_vma_socketxtreme_free_vma_packets(struct vma_packet_desc_t *packets, int num)
{
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG,
			"socketXtreme was not enabled during runtime. Set %s to use. Ignoring...", SYS_VAR_SOCKETXTREME,
			packets, num);
	errno = EOPNOTSUPP;
	return -1;
}

extern "C"
int vma_socketxtreme_free_vma_packets(struct vma_packet_desc_t *packets, int num)
{
	mem_buf_desc_t* desc = NULL;
	socket_fd_api* p_socket_object = NULL;

	if (likely(packets)) {
		for (int i = 0; i < num; i++) {
			desc = (mem_buf_desc_t*)packets[i].buff_lst;
			if (desc) {
				p_socket_object = (socket_fd_api*)desc->rx.context;
				ring_slave* rng = desc->p_desc_owner;
				if (p_socket_object) {
					p_socket_object->free_buffs(packets[i].total_len);
				}
				if (rng) {
					rng->reclaim_recv_buffers(desc);
				} else {
					goto err;
				}
			} else {
				goto err;
			}
		}
	}
	else {
		goto err;
	}

	return 0;

err:
	errno = EINVAL;
	return -1;
}

static int dummy_vma_socketxtreme_ref_vma_buff(vma_buff_t *buff)
{
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG,
			"socketXtreme was not enabled during runtime. Set %s to use. Ignoring...", SYS_VAR_SOCKETXTREME,
			buff);
	errno = EOPNOTSUPP;
	return -1;
}

extern "C"
int vma_socketxtreme_ref_vma_buff(vma_buff_t *buff)
{
	int ret_val = 0;
	mem_buf_desc_t* desc = NULL;

	if (likely(buff)) {
		desc = (mem_buf_desc_t*)buff;
		ret_val = desc->lwip_pbuf_inc_ref_count();
	}
	else {
		errno = EINVAL;
		ret_val = -1;
	}
	return ret_val;
}

static int dummy_vma_socketxtreme_free_vma_buff(vma_buff_t *buff)
{
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG,
			"socketXtreme was not enabled during runtime. Set %s to use. Ignoring...", SYS_VAR_SOCKETXTREME,
			buff);
	errno = EOPNOTSUPP;
	return -1;
}

extern "C"
int vma_socketxtreme_free_vma_buff(vma_buff_t *buff)
{
	int ret_val = 0;
	mem_buf_desc_t* desc = NULL;

	if (likely(buff)) {
		desc = (mem_buf_desc_t*)buff;
		ring_slave* rng = desc->p_desc_owner;
		ret_val = rng->reclaim_recv_single_buffer(desc);
	}
	else {
		errno = EINVAL;
		ret_val = -1;
	}
	return ret_val;
}

extern "C"
int vma_get_socket_rings_num(int fd)
{
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(fd);
	if (p_socket_object && p_socket_object->check_rings()) {
		return p_socket_object->get_rings_num();
	}

	return 0;
}

extern "C"
int vma_get_socket_rings_fds(int fd, int *ring_fds, int ring_fds_sz)
{
	int* p_rings_fds = NULL;
	socket_fd_api* p_socket_object = NULL;
	int rings_num = 0;
	
	if (ring_fds_sz <= 0 || ring_fds == NULL) {
        	errno = EINVAL;
        	return -1;
	}
	p_socket_object = fd_collection_get_sockfd(fd);
	if (p_socket_object && p_socket_object->check_rings()) {
		p_rings_fds = p_socket_object->get_rings_fds(rings_num);
		for (int i = 0; i < min(ring_fds_sz, rings_num); i++) {
			ring_fds[i] = p_rings_fds[i];
		}
	}

	return min(ring_fds_sz, rings_num);
}

extern "C"
int vma_get_socket_tx_ring_fd(int sock_fd, struct sockaddr *to, socklen_t tolen)
{
	socket_fd_api* p_socket_object = fd_collection_get_sockfd(sock_fd);

	if (!p_socket_object) {
		errno = EINVAL;
		return -1;
	}
	return p_socket_object->get_socket_tx_ring_fd(to, tolen);
}

extern "C"
int vma_add_conf_rule(const char *config_line)
{
	srdr_logdbg("adding conf rule: %s", config_line);

	int ret = __vma_parse_config_line(config_line);

	if (*g_p_vlogger_level >= VLOG_DEBUG)
		__vma_print_conf_file(__instance_list);

	return ret;
}

extern "C"
int vma_thread_offload(int offload, pthread_t tid)
{
	if (g_p_fd_collection) {
		g_p_fd_collection->offloading_rule_change_thread(offload, tid);
	} else {
		return -1;
	}

	return 0;
}

extern "C"
int vma_dump_fd_stats(int fd, int log_level)
{
	if (g_p_fd_collection) {
		g_p_fd_collection->statistics_print(fd, log_level::from_int(log_level));
		return 0;
	}
	return -1;
}

/* Multi Packet Receive Queue functionality is deprecated
 * and is not going to be supported in the future releases
 */
extern "C"
int vma_cyclic_buffer_read(int fd, struct vma_completion_cb_t *completion,
			   size_t min, size_t max, int flags)
{
#ifdef HAVE_MP_RQ
	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
	if (p_cq_ch_info) {
		ring_eth_cb* p_ring = (ring_eth_cb *)p_cq_ch_info->get_ring();
		if (likely(p_ring && p_ring->is_mp_ring())) {
			return p_ring->cyclic_buffer_read(*completion, min, max,
					flags);
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring, got fd "
					"%d\n", fd);
			return -1;
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", fd);
		return -1;
	}
#else
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG, "Striding RQ is no supported. ignoring...", fd, completion, min, max, flags);
	errno = EOPNOTSUPP;
	return -1;
#endif // HAVE_MP_RQ
}

/* Multi Packet Receive Queue functionality is deprecated
 * and is not going to be supported in the future releases
 */
extern "C"
int vma_get_mem_info(int fd, void **addr, size_t *length, uint32_t *lkey)
{
#ifdef HAVE_MP_RQ
	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(fd);
	if (!length || !lkey || !addr) {
		vlog_printf(VLOG_ERROR, "invalid pointers given. fd: %d, addr "
			    "%p length %p lkey %p\n", fd, addr, length, lkey);
		return -1;
	}
	if (p_cq_ch_info) {
		ring_eth_cb *p_ring = dynamic_cast<ring_eth_cb*>(p_cq_ch_info->get_ring());
		ibv_sge mem_info;
		if (likely(p_ring && p_ring->get_mem_info(mem_info) == 0)) {
			*addr = (void*)mem_info.addr;
			*length = mem_info.length;
			*lkey = mem_info.lkey;
			return 0;
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring_eth_cb, "
					"got fd %d\n", fd);
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", fd);
	}
	return -1;
#else
	NOT_IN_USE(addr);
	NOT_IN_USE(length);
	NOT_IN_USE(lkey);
	VLOG_PRINTF_ONCE_THEN_ALWAYS(VLOG_WARNING, VLOG_DEBUG,
			"vma_get_mem_info is no supported with this ring", fd);
	errno = EOPNOTSUPP;
	return -1;
#endif // HAVE_MP_RQ
}

extern "C"
int vma_add_ring_profile(vma_ring_type_attr *profile, vma_ring_profile_key *res)
{
	if (!g_p_ring_profile) {
		vlog_printf(VLOG_DEBUG, "%s g_p_ring_profile is null\n",__func__);
		return -1;
	}
	*res = g_p_ring_profile->add_profile(profile);
	return 0;
}

extern "C"
int vma_modify_ring(struct vma_modify_ring_attr *mr_data)
{
	srdr_logfunc_entry("ring_fd=%d, mr_data=%p ", mr_data->ring_fd, mr_data);
	int ret = -1;
	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(mr_data->ring_fd);
	if (likely(p_cq_ch_info)) {
		ring_simple* p_ring = dynamic_cast<ring_simple*>(p_cq_ch_info->get_ring());
		if (likely(p_ring)) {
			if (VMA_MODIFY_RING_CQ_ARM & mr_data->comp_bit_mask) {
				if (RING_ETH_CB == p_ring->get_type()) {
					ret = p_ring->ack_and_arm_cq(CQT_RX);
				} else if (RING_ETH_DIRECT == p_ring->get_type()) {
					ret = p_ring->ack_and_arm_cq(CQT_TX);
				} else {
					vlog_printf(VLOG_ERROR, "Ring type [%d] is not supported\n",
							p_ring->get_type());
				}
			} else if (VMA_MODIFY_RING_CQ_MODERATION & mr_data->comp_bit_mask) {
				p_ring->modify_cq_moderation(mr_data->cq_moderation.cq_moderation_period_usec,
						mr_data->cq_moderation.cq_moderation_count);
				ret = 0;
			} else {
				vlog_printf(VLOG_ERROR, "comp_mask [0x%x] is not supported\n",
						mr_data->comp_bit_mask);
			}
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring_simple,"
					" got fd %d\n", mr_data->ring_fd);
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", mr_data->ring_fd);
	}

	return ret;
}

extern "C"
int vma_get_socket_netowrk_header(int __fd, void *ptr, uint16_t *len)
{
	srdr_logdbg_entry("fd=%d, ptr=%p len=%d", __fd, ptr, len);

	socket_fd_api* p_socket_object = fd_collection_get_sockfd(__fd);

	if (p_socket_object) {
		return p_socket_object->get_socket_network_ptr(ptr, *len);
	}
	errno = EINVAL;
	return -1;
}

extern "C"
int vma_get_ring_direct_descriptors(int __fd,
				    struct vma_mlx_hw_device_data *data)
{
	srdr_logdbg_entry("fd=%d, ptr=%p ", __fd, data);

	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(__fd);
	if (p_cq_ch_info) {
		ring_simple* p_ring = dynamic_cast<ring_simple *>(p_cq_ch_info->get_ring());
		if (likely(p_ring)) {
			return p_ring->get_ring_descriptors(*data);
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring_simple,"
					" got fd %d\n", __fd);
			return -1;
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", __fd);
		return -1;
	}
}

extern "C"
int vma_reg_mr_on_ring(int __fd, void *addr, size_t length, uint32_t *lkey)
{
	srdr_logdbg_entry("fd=%d, addr=%p length %zd key %p", __fd, addr, length, lkey);

	if (!lkey) {
		vlog_printf(VLOG_DEBUG, "key is null fd %d, addr %p, length %zd\n",
				__fd, addr, length);
		errno = EINVAL;
		return -1;
	}
	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(__fd);
	if (p_cq_ch_info) {
		ring* p_ring = p_cq_ch_info->get_ring();
		if (likely(p_ring)) {
			return p_ring->reg_mr(addr, length, *lkey);
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring, got fd "
					"%d\n", __fd);
			return -1;
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", __fd);
		return -1;
	}
}

extern "C"
int vma_dereg_mr_on_ring(int __fd, void *addr, size_t length)
{
	srdr_logdbg_entry("fd=%d, addr=%p ", __fd, addr);

	cq_channel_info* p_cq_ch_info = g_p_fd_collection->get_cq_channel_fd(__fd);
	if (p_cq_ch_info) {
		ring* p_ring = p_cq_ch_info->get_ring();
		if (likely(p_ring)) {
			return p_ring->dereg_mr(addr, length);
		} else {
			vlog_printf(VLOG_ERROR, "could not find ring, got fd "
					"%d\n", __fd);
			return -1;
		}
	} else {
		vlog_printf(VLOG_ERROR, "could not find p_cq_ch_info, got fd "
							"%d\n", __fd);
		return -1;
	}
}

//-----------------------------------------------------------------------------
//  replacement functions
//-----------------------------------------------------------------------------

/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
extern "C"
int socket(int __domain, int __type, int __protocol)
{
	return socket_internal(__domain, __type, __protocol, true);
}

// allow calling our socket(...) implementation safely from within libvma.so
// this is critical in case VMA was loaded using dlopen and not using LD_PRELOAD
// TODO: look for additional such functions/calls
int socket_internal(int __domain, int __type, int __protocol, bool check_offload /*= false*/)
{
	bool offload_sockets = (__type & 0xf) == SOCK_DGRAM || (__type & 0xf) == SOCK_STREAM;

	if (offload_sockets)
		DO_GLOBAL_CTORS();

	dbg_check_if_need_to_send_mcpkt();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.socket) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int fd = orig_os_api.socket(__domain, __type, __protocol);
	vlog_printf(VLOG_DEBUG, "ENTER: %s(domain=%s(%d), type=%s(%d), protocol=%d) = %d\n",__func__, socket_get_domain_str(__domain), __domain, socket_get_type_str(__type), __type, __protocol, fd);
	if (fd < 0) {
		return fd;
	}

	if (g_p_fd_collection) {
		// Sanity check to remove any old sockinfo object using the same fd!!
		handle_close(fd, true);

		// Create new sockinfo object for this new socket
		if (offload_sockets)
			g_p_fd_collection->addsocket(fd, __domain, __type, check_offload);
	}

	return fd;
}

extern "C"
int close(int __fd)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.close) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	srdr_logdbg_entry("fd=%d", __fd);

	handle_close(__fd);

	return orig_os_api.close(__fd);
}

extern "C"
void __res_iclose(res_state statp, bool free_addr)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.__res_iclose) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	srdr_logdbg_entry("");
	for (int ns = 0; ns < statp->_u._ext.nscount; ns++) {
		int sock = statp->_u._ext.nssocks[ns];
		if (sock != -1) {
			handle_close(sock);
		}
	}
	orig_os_api.__res_iclose(statp, free_addr);
}

/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
extern "C"
int shutdown(int __fd, int __how)
{
	srdr_logdbg_entry("fd=%d, how=%d", __fd, __how);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object)
		return p_socket_object->shutdown(__how);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.shutdown) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.shutdown(__fd, __how);
}

extern "C"
int listen(int __fd, int backlog)
{
	srdr_logdbg_entry("fd=%d, backlog=%d", __fd, backlog);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);

	if (p_socket_object) {
		int ret = p_socket_object->prepareListen(); // for verifying that the socket is really offloaded
		if (ret < 0)
			return ret; //error
		if (ret > 0) { //Passthrough
			handle_close(__fd, false, true);
			p_socket_object = NULL;
		}
	}
	if (p_socket_object) {
		return p_socket_object->listen(backlog);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.listen) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.listen(__fd, backlog);
}

extern "C"
int accept(int __fd, struct sockaddr *__addr, socklen_t *__addrlen)
{
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object)
		return p_socket_object->accept(__addr, __addrlen);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.accept) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.accept(__fd, __addr, __addrlen);
}

extern "C"
int accept4(int __fd, struct sockaddr *__addr, socklen_t *__addrlen, int __flags)
{
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object)
		return p_socket_object->accept4(__addr, __addrlen, __flags);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.accept4) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.accept4(__fd, __addr, __addrlen, __flags);
}

/* Give the socket FD the local address ADDR (which is LEN bytes long).  */
extern "C"
int bind(int __fd, const struct sockaddr *__addr, socklen_t __addrlen)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.bind) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	char buf[256];
	NOT_IN_USE(buf); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __addr, __addrlen));

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		ret = p_socket_object->bind(__addr, __addrlen);
		if (p_socket_object->isPassthrough()) {
			handle_close(__fd, false, true);
			if (ret) {
				ret = orig_os_api.bind(__fd, __addr, __addrlen);
			}
		}
	}
	else {
		ret = orig_os_api.bind(__fd, __addr, __addrlen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}

/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
int connect(int __fd, const struct sockaddr *__to, socklen_t __tolen)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.connect) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	char buf[256];
	NOT_IN_USE(buf); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	srdr_logdbg_entry("fd=%d, %s", __fd, sprintf_sockaddr(buf, 256, __to, __tolen));

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (__to && __to->sa_family == AF_INET && p_socket_object) {
		ret = p_socket_object->connect(__to, __tolen);
		if (p_socket_object->isPassthrough()) {
			handle_close(__fd, false, true);
			if (ret) {
				ret = orig_os_api.connect(__fd, __to, __tolen);
			}
		}
	}
	else {
		if (p_socket_object) {
			p_socket_object->setPassthrough();
		}
		ret = orig_os_api.connect(__fd, __to, __tolen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern "C"
int setsockopt(int __fd, int __level, int __optname,
	       __const void *__optval, socklen_t __optlen)
{
	srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);
        
        if (NULL == __optval) {
                errno = EFAULT;
                return -1;
        }

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;

	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		VERIFY_PASSTROUGH_CHANGED(ret, p_socket_object->setsockopt(__level, __optname, __optval, __optlen));
	}
	else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.setsockopt) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		ret = orig_os_api.setsockopt(__fd, __level, __optname, __optval, __optlen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}

/* Get socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
extern "C"
int getsockopt(int __fd, int __level, int __optname,
	       void *__optval, socklen_t *__optlen)
{
	srdr_logdbg_entry("fd=%d, level=%d, optname=%d", __fd, __level, __optname);

	if (__fd == -1 && __level == SOL_SOCKET && __optname == SO_VMA_GET_API &&
	    __optlen && *__optlen >= sizeof(struct vma_api_t*)) {
		DO_GLOBAL_CTORS();
		bool enable_socketxtreme = safe_mce_sys().enable_socketxtreme;
		srdr_logdbg("User request for VMA Extra API pointers");
		struct vma_api_t *vma_api = new struct vma_api_t();

		vma_api->vma_extra_supported_mask = 0;
		SET_EXTRA_API(register_recv_callback, vma_register_recv_callback, VMA_EXTRA_API_REGISTER_RECV_CALLBACK);
		SET_EXTRA_API(recvfrom_zcopy, vma_recvfrom_zcopy, VMA_EXTRA_API_RECVFROM_ZCOPY);
		SET_EXTRA_API(free_packets, vma_free_packets, VMA_EXTRA_API_FREE_PACKETS);
		SET_EXTRA_API(add_conf_rule, vma_add_conf_rule, VMA_EXTRA_API_ADD_CONF_RULE);
		SET_EXTRA_API(thread_offload, vma_thread_offload, VMA_EXTRA_API_THREAD_OFFLOAD);
		SET_EXTRA_API(get_socket_rings_num, vma_get_socket_rings_num, VMA_EXTRA_API_GET_SOCKET_RINGS_NUM);
		SET_EXTRA_API(get_socket_rings_fds, vma_get_socket_rings_fds, VMA_EXTRA_API_GET_SOCKET_RINGS_FDS);
		SET_EXTRA_API(get_socket_tx_ring_fd, vma_get_socket_tx_ring_fd, VMA_EXTRA_API_GET_SOCKET_TX_RING_FD);
		SET_EXTRA_API(vma_add_ring_profile, vma_add_ring_profile, VMA_EXTRA_API_ADD_RING_PROFILE);
		SET_EXTRA_API(get_socket_network_header, vma_get_socket_netowrk_header, VMA_EXTRA_API_GET_SOCKET_NETWORK_HEADER);
		SET_EXTRA_API(get_ring_direct_descriptors, vma_get_ring_direct_descriptors, VMA_EXTRA_API_GET_RING_DIRECT_DESCRIPTORS);
		SET_EXTRA_API(register_memory_on_ring, vma_reg_mr_on_ring, VMA_EXTRA_API_REGISTER_MEMORY_ON_RING);
		SET_EXTRA_API(deregister_memory_on_ring, vma_dereg_mr_on_ring, VMA_EXTRA_API_DEREGISTER_MEMORY_ON_RING);
		SET_EXTRA_API(socketxtreme_free_vma_packets, enable_socketxtreme ? vma_socketxtreme_free_vma_packets : dummy_vma_socketxtreme_free_vma_packets, VMA_EXTRA_API_SOCKETXTREME_FREE_VMA_PACKETS);
		SET_EXTRA_API(socketxtreme_poll, enable_socketxtreme ? vma_socketxtreme_poll : dummy_vma_socketxtreme_poll, VMA_EXTRA_API_SOCKETXTREME_POLL);
		SET_EXTRA_API(socketxtreme_ref_vma_buff, enable_socketxtreme ? vma_socketxtreme_ref_vma_buff : dummy_vma_socketxtreme_ref_vma_buff, VMA_EXTRA_API_SOCKETXTREME_REF_VMA_BUFF);
		SET_EXTRA_API(socketxtreme_free_vma_buff, enable_socketxtreme ? vma_socketxtreme_free_vma_buff : dummy_vma_socketxtreme_free_vma_buff, VMA_EXTRA_API_SOCKETXTREME_FREE_VMA_BUFF);
		SET_EXTRA_API(dump_fd_stats, vma_dump_fd_stats, VMA_EXTRA_API_DUMP_FD_STATS);
		SET_EXTRA_API(vma_cyclic_buffer_read, vma_cyclic_buffer_read, VMA_EXTRA_API_CYCLIC_BUFFER_READ);
		SET_EXTRA_API(get_mem_info, vma_get_mem_info, VMA_EXTRA_API_GET_MEM_INFO);
		SET_EXTRA_API(vma_modify_ring, vma_modify_ring, VMA_EXTRA_API_MODIFY_RING);
		*((vma_api_t**)__optval) = vma_api;
		return 0;
	}

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		VERIFY_PASSTROUGH_CHANGED(ret, p_socket_object->getsockopt(__level, __optname, __optval, __optlen));
	} else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.getsockopt) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		ret = orig_os_api.getsockopt(__fd, __level, __optname, __optval, __optlen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}

/* Do the file control operation described by CMD on FD.
   The remaining arguments are interpreted depending on CMD.

   This function is a cancellation point and therefore not marked with
   __THROW.
   NOTE: VMA throw will never occur during handling of any command.
   VMA will only throw in case VMA doesn't know to handle a command and the
   user requested explicitly that VMA will throw an exception in such a case
   by setting VMA_EXCEPTION_HANDLING accordingly (see README.txt)
   */
extern "C"
int fcntl(int __fd, int __cmd, ...)
{
	srdr_logfunc_entry("fd=%d, cmd=%d", __fd, __cmd);

	int res = -1;
	va_list va;
	va_start(va, __cmd);
	unsigned long int arg = va_arg(va, unsigned long int);
	va_end(va);

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->fcntl(__cmd, arg));
	} else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.fcntl) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		res = orig_os_api.fcntl(__fd, __cmd, arg);
	}

	if (__cmd == F_DUPFD) {
		handle_close(__fd);
	}

	if (ret >= 0)
		srdr_logfunc_exit("returned with %d", ret);
	else
		srdr_logfunc_exit("failed (errno=%d %m)", errno);
	return res;
}

/* Perform the I/O control operation specified by REQUEST on FD.
   One argument may follow; its presence and type depend on REQUEST.
   Return value depends on REQUEST.  Usually -1 indicates error. */
extern "C"
int ioctl (int __fd, unsigned long int __request, ...)
{
	srdr_logfunc_entry("fd=%d, request=%d", __fd, __request);

	int res = -1;
	va_list va;
	va_start(va, __request);
	unsigned long int arg = va_arg(va, unsigned long int);
	va_end(va);

	int ret = 0;

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object && arg) {
		VERIFY_PASSTROUGH_CHANGED(res, p_socket_object->ioctl(__request, arg));
	} else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.ioctl) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		res = orig_os_api.ioctl(__fd, __request, arg);
	}

	if (ret >= 0)
		srdr_logfunc_exit("returned with %d", ret);
	else
		srdr_logfunc_exit("failed (errno=%d %m)", errno);
	return res;
}

extern "C"
int getsockname(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
	srdr_logdbg_entry("fd=%d", __fd);

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		ret = p_socket_object->getsockname(__name, __namelen);

		if (safe_mce_sys().trigger_dummy_send_getsockname) {
			char buf[264] = {0};
			struct iovec msg_iov = {&buf, sizeof(buf)};
			struct msghdr msg = {NULL, 0, &msg_iov, 1, NULL, 0, 0};
			int ret_send = sendmsg(__fd, &msg, VMA_SND_FLAGS_DUMMY);
			srdr_logdbg("Triggered dummy message for socket fd=%d (ret_send=%d)", __fd, ret_send);
			NOT_IN_USE(ret_send);
		}
	}
	else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.getsockname) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		ret = orig_os_api.getsockname(__fd, __name, __namelen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}

extern "C"
int getpeername(int __fd, struct sockaddr *__name, socklen_t *__namelen)
{
	srdr_logdbg_entry("fd=%d", __fd);

	int ret = 0;
	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		ret = p_socket_object->getpeername(__name, __namelen);
	}
	else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.getpeername) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		ret = orig_os_api.getpeername(__fd, __name, __namelen);
	}

	if (ret >= 0)
		srdr_logdbg_exit("returned with %d", ret);
	else
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	return ret;
}


/* Read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t read(int __fd, void *__buf, size_t __nbytes)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		int dummy_flags = 0;
		return p_socket_object->rx(RX_READ, piov, 1, &dummy_flags);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.read) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.read(__fd, __buf, __nbytes);
}

/* Checks that the buffer is big enough to contain the number of bytes
 * the user requests to read. If the buffer is too small, aborts,
 * else read NBYTES into BUF from FD.  Return the
   number read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t __read_chk(int __fd, void *__buf, size_t __nbytes, size_t __buflen)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (__nbytes > __buflen) {
		    srdr_logpanic("buffer overflow detected");
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		int dummy_flags = 0;
		return p_socket_object->rx(RX_READ, piov, 1, &dummy_flags);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.__read_chk) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.__read_chk(__fd, __buf, __nbytes, __buflen);
}

/* Read COUNT blocks into VECTOR from FD.  Return the
   number of bytes read, -1 for errors or 0 for EOF.

   This function is a cancellation point and therefore not marked with
   __THROW.  */

extern "C"
ssize_t readv(int __fd, const struct iovec *iov, int iovcnt)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		struct iovec* piov = (struct iovec*)iov;
		int dummy_flags = 0;
		return p_socket_object->rx(RX_READV, piov, iovcnt, &dummy_flags);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.readv) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.readv(__fd, iov, iovcnt);
}

/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t recv(int __fd, void *__buf, size_t __nbytes, int __flags)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->rx(RX_RECV, piov, 1, &__flags);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.recv) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.recv(__fd, __buf, __nbytes, __flags);
}

/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t __recv_chk(int __fd, void *__buf, size_t __nbytes, size_t __buflen, int __flags)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (__nbytes > __buflen) {
			srdr_logpanic("buffer overflow detected");
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->rx(RX_RECV, piov, 1, &__flags);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.__recv_chk) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.__recv_chk(__fd, __buf, __nbytes, __buflen, __flags);
}

/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t recvmsg(int __fd, struct msghdr *__msg, int __flags)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	if (__msg == NULL) {
		srdr_logdbg("NULL msghdr");
		errno = EINVAL;
		return -1;
	}

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		__msg->msg_flags = 0;
		return p_socket_object->rx(RX_RECVMSG, __msg->msg_iov, __msg->msg_iovlen, &__flags, (__SOCKADDR_ARG)__msg->msg_name, (socklen_t*)&__msg->msg_namelen, __msg);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.recvmsg) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.recvmsg(__fd, __msg, __flags);
}

/* The following definitions are for kernels previous to 2.6.32 which dont support recvmmsg */
#ifndef HAVE_STRUCT_MMSGHDR
#ifndef __INTEL_COMPILER
struct mmsghdr {
    struct msghdr msg_hdr;  // Message header
    unsigned int  msg_len;  // Number of received bytes for header
};
#endif
#endif

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE  0x10000 //recvmmsg(): block until 1+ packets avail
#endif

/* Receive multiple messages as described by MESSAGE from socket FD.
   Returns the number of messages received or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
#ifdef RECVMMSG_WITH_CONST_TIMESPEC
int recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags, const struct timespec *__timeout)
#else
int recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags, struct timespec *__timeout)
#endif
{
        int num_of_msg=0;
        struct timespec start_time = TIMESPEC_INITIALIZER, current_time = TIMESPEC_INITIALIZER, delta_time = TIMESPEC_INITIALIZER;

        srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

        if (__mmsghdr == NULL) {
                srdr_logdbg("NULL mmsghdr");
                errno = EINVAL;
                return -1;
        }

        if (__timeout) {
        	gettime(&start_time);
        }
        socket_fd_api* p_socket_object = NULL;
        p_socket_object = fd_collection_get_sockfd(__fd);
        if (p_socket_object) {
        	int ret = 0;
                for (unsigned int i=0; i<__vlen; i++) {
                       int flags = __flags;
                       __mmsghdr[i].msg_hdr.msg_flags = 0;
                       ret = p_socket_object->rx(RX_RECVMSG, __mmsghdr[i].msg_hdr.msg_iov, __mmsghdr[i].msg_hdr.msg_iovlen, &flags,
                                                         (__SOCKADDR_ARG)__mmsghdr[i].msg_hdr.msg_name, (socklen_t*)&__mmsghdr[i].msg_hdr.msg_namelen,  &__mmsghdr[i].msg_hdr);
                       if (ret < 0){
                               break;
                       }
                       num_of_msg++;
                       __mmsghdr[i].msg_len = ret;
                       if ((i==0) && (flags & MSG_WAITFORONE)) {
                               __flags |= MSG_DONTWAIT;
                       }
                       if (__timeout) {
                	       gettime(&current_time);
                	       ts_sub(&current_time, &start_time, &delta_time);
                	       if (ts_cmp(&delta_time, __timeout, >)) {
                		       break;
                	       }
                       }
                }
                if (num_of_msg || ret == 0) {
                	//todo save ret for so_error if ret != 0(see kernel)
                	return num_of_msg;
                } else {
                	return ret;
                }
        }
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!orig_os_api.recvmmsg) get_orig_funcs();
        BULLSEYE_EXCLUDE_BLOCK_END

        return orig_os_api.recvmmsg(__fd, __mmsghdr, __vlen, __flags, __timeout);
}


/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t recvfrom(int __fd, void *__buf, size_t __nbytes, int __flags,
		 struct sockaddr *__from, socklen_t *__fromlen)
{
	ssize_t ret_val = 0;

	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		ret_val = p_socket_object->rx(RX_RECVFROM, piov, 1, &__flags, __from, __fromlen);
	}
	else {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.recvfrom) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		ret_val = orig_os_api.recvfrom(__fd, __buf, __nbytes, __flags, __from, __fromlen);
	}
#ifdef RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_PROCCESS_RX_BUFFER_TO_RECIVEFROM]);
#endif //RDTSC_MEASURE_RX_PROCCESS_BUFFER_TO_RECIVEFROM

#ifdef RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_LWIP_TO_RECEVEFROM]);
#endif //RDTSC_MEASURE_RX_LWIP_TO_RECEVEFROM

#ifdef RDTSC_MEASURE_RX_CQE_RECEIVEFROM
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RX_CQE_TO_RECEIVEFROM]);
#endif //RDTSC_MEASURE_RX_CQE_RECEIVEFROM

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif //RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
	return ret_val;
}

/* Checks that the buffer is big enough to contain the number of bytes
   the user requests to read. If the buffer is too small, aborts,
   else read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t __recvfrom_chk(int __fd, void *__buf, size_t __nbytes, size_t __buflen, int __flags,
		 struct sockaddr *__from, socklen_t *__fromlen)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (__nbytes > __buflen) {
		    srdr_logpanic("buffer overflow detected");
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		struct iovec piov[1];
		piov[0].iov_base = __buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->rx(RX_RECVFROM, piov, 1, &__flags, __from, __fromlen);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.__recvfrom_chk) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.__recvfrom_chk(__fd, __buf, __nbytes, __buflen, __flags, __from, __fromlen);
}

/* Write N bytes of BUF to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t write(int __fd, __const void *__buf, size_t __nbytes)
{
	srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		iovec piov[1];
		piov[0].iov_base = (void*)__buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->tx(TX_WRITE, piov, 1);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.write) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.write(__fd, __buf, __nbytes);
}

/* Write IOCNT blocks from IOVEC to FD.  Return the number written, or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t writev(int __fd, const struct iovec *iov, int iovcnt)
{
	srdr_logfuncall_entry("fd=%d, %d iov blocks", __fd, iovcnt);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		return p_socket_object->tx(TX_WRITEV, iov, iovcnt);
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.writev) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.writev(__fd, iov, iovcnt);
}


/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t send(int __fd, __const void *__buf, size_t __nbytes, int __flags)
{
	srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		iovec piov[1];
		piov[0].iov_base = (void*)__buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->tx(TX_SEND, piov, 1, __flags);
	}

	// Ignore dummy messages for OS
	if (unlikely(IS_DUMMY_PACKET(__flags))) {
		errno = EINVAL;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.send) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.send(__fd, __buf, __nbytes, __flags);
}

/* Sends a message as described by MESSAGE to socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t sendmsg(int __fd, __const struct msghdr *__msg, int __flags)
{
	srdr_logfuncall_entry("fd=%d", __fd);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		return p_socket_object->tx(TX_SENDMSG, __msg->msg_iov, __msg->msg_iovlen, __flags, (__CONST_SOCKADDR_ARG)__msg->msg_name, (socklen_t)__msg->msg_namelen);
	}

	// Ignore dummy messages for OS
	if (unlikely(IS_DUMMY_PACKET(__flags))) {
		errno = EINVAL;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.sendmsg) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.sendmsg(__fd, __msg, __flags);

}

/* Send multiple messages as described by MESSAGE from socket FD.
   Returns the number of messages sent or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
int sendmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags)
{
	int num_of_msg=0;

	srdr_logfuncall_entry("fd=%d, mmsghdr length=%d flags=%x", __fd, __vlen, __flags);

	if (__mmsghdr == NULL) {
		srdr_logdbg("NULL mmsghdr");
		errno = EINVAL;
		return -1;
	}

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		for (unsigned int i=0; i<__vlen; i++) {
			int ret = p_socket_object->tx(TX_SENDMSG, __mmsghdr[i].msg_hdr.msg_iov, __mmsghdr[i].msg_hdr.msg_iovlen, __flags,
					(__SOCKADDR_ARG)__mmsghdr[i].msg_hdr.msg_name, (socklen_t)__mmsghdr[i].msg_hdr.msg_namelen);
			if (ret < 0){
				if (num_of_msg)
					return num_of_msg;
				else
					return ret;
			}
			num_of_msg++;
			__mmsghdr[i].msg_len = ret;
		}
		return num_of_msg;
	}

	// Ignore dummy messages for OS
	if (unlikely(IS_DUMMY_PACKET(__flags))) {
		errno = EINVAL;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.sendmmsg) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.sendmmsg(__fd, __mmsghdr, __vlen, __flags);
}

/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern "C"
ssize_t sendto(int __fd, __const void *__buf, size_t __nbytes, int __flags,
	       const struct sockaddr *__to, socklen_t __tolen)
{
#ifdef RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
	RDTSC_TAKE_START(g_rdtsc_instr_info_arr[RDTSC_FLOW_SENDTO_TO_AFTER_POST_SEND]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND

#ifdef RDTSC_MEASURE_RECEIVEFROM_TO_SENDTO
	RDTSC_TAKE_END(g_rdtsc_instr_info_arr[RDTSC_FLOW_RECEIVEFROM_TO_SENDTO]);
#endif //RDTSC_MEASURE_TX_SENDTO_TO_AFTER_POST_SEND
	srdr_logfuncall_entry("fd=%d, nbytes=%d", __fd, __nbytes);

	socket_fd_api* p_socket_object = NULL;
	p_socket_object = fd_collection_get_sockfd(__fd);
	if (p_socket_object) {
		iovec piov[1];
		piov[0].iov_base = (void*)__buf;
		piov[0].iov_len = __nbytes;
		return p_socket_object->tx(TX_SENDTO, piov, 1, __flags, __to, __tolen);
	}

	// Ignore dummy messages for OS
	if (unlikely(IS_DUMMY_PACKET(__flags))) {
		errno = EINVAL;
		return -1;
	}
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.sendto) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.sendto(__fd, __buf, __nbytes, __flags, __to, __tolen);
}

inline ssize_t sendfile_helper(socket_fd_api* p_socket_object, int in_fd, __off64_t *offset, size_t count)
{
	__off64_t orig = 0;
	iovec piov[1];
	char buf[SENDFILE_BUFFER_SIZE];
	ssize_t toRead, numRead, numSent, totSent = 0;

	if (offset != NULL) {
		/* Save current file offset and set offset to value in '*offset' */
		orig = lseek64(in_fd, 0, SEEK_CUR);
		if (orig == -1)
			return -1;
		if (lseek64(in_fd, *offset, SEEK_SET) == -1)
			return -1;
	}

	piov[0].iov_base = (void*) buf;

	while (count > 0) {
		toRead = min(sizeof(buf), count);
		numRead = orig_os_api.read(in_fd, buf, toRead);
		if (numRead == -1)
			return -1;
		if (numRead == 0)
			break;                      /* EOF */

		// Update iovec size before send
		piov[0].iov_len = numRead;

		numSent = p_socket_object->tx(TX_WRITE, piov, 1);
		if (numSent == -1)
			return -1;
		if (numSent == 0)               /* Should never happen */
			srdr_logdbg("sendfile: write() transferred 0 bytes");

		count -= numSent;
		totSent += numSent;
	}

	if (offset != NULL) {
		/* Return updated file offset in '*offset', and reset the file offset
           to the value it had when we were called. */
		*offset = lseek64(in_fd, 0, SEEK_CUR);
		if (*offset == -1)
			return -1;
		if (lseek64(in_fd, orig, SEEK_SET) == -1)
			return -1;
	}

	return totSent;
}

extern "C"
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd, offset, offset ? *offset : 0, count);

	socket_fd_api* p_socket_object = fd_collection_get_sockfd(out_fd);
	if (!p_socket_object) {
		if (!orig_os_api.sendfile) get_orig_funcs();
		return orig_os_api.sendfile(out_fd, in_fd, offset, count);
	}

	return sendfile_helper(p_socket_object, in_fd, offset, count);
}

extern "C"
ssize_t sendfile64(int out_fd, int in_fd, __off64_t *offset, size_t count)
{
	srdr_logfuncall_entry("out_fd=%d, in_fd=%d, offset=%p, *offset=%zu, count=%d", out_fd, in_fd, offset, offset ? *offset : 0, count);

	socket_fd_api* p_socket_object = fd_collection_get_sockfd(out_fd);
	if (!p_socket_object) {
		if (!orig_os_api.sendfile64) get_orig_funcs();
		return orig_os_api.sendfile64(out_fd, in_fd, offset, count);
	}

	return sendfile_helper(p_socket_object, in_fd, offset, count);
}

// Format a fd_set into a string for logging
// Check nfd to know how many 32 bits hexs do we want to sprintf into user buffer
const char* sprintf_fdset(char* buf, int buflen, int __nfds, fd_set *__fds)
{
	if (buflen<1)
		return "(null)";
	buf[0] = '\0';

	if ((__nfds <= 0) || (__fds == NULL))
		return "(null)";

	int fdsize = 1 + ((__nfds-1) / (8*sizeof(uint32_t)));
	switch (fdsize) {
	case 1:
		snprintf(buf, buflen, "%08x", ((uint32_t*)__fds)[0]);
		break;
	case 2:
		snprintf(buf, buflen, "%08x %08x", ((uint32_t*)__fds)[1], ((uint32_t*)__fds)[0]);
		break;
	case 3:
		snprintf(buf, buflen, "%08x %08x %08x", ((uint32_t*)__fds)[2], ((uint32_t*)__fds)[1], ((uint32_t*)__fds)[0]);
		break;
	case 4:
		snprintf(buf, buflen, "%08x %08x %08x %08x", ((uint32_t*)__fds)[3], ((uint32_t*)__fds)[2], ((uint32_t*)__fds)[1], ((uint32_t*)__fds)[0]);
		break;
	case 5:
		snprintf(buf, buflen, "%08x %08x %08x %08x %08x", ((uint32_t*)__fds)[4], ((uint32_t*)__fds)[3], ((uint32_t*)__fds)[2], ((uint32_t*)__fds)[1], ((uint32_t*)__fds)[0]);
		break;
	case 6:
		snprintf(buf, buflen, "%08x %08x %08x %08x %08x %08x", ((uint32_t*)__fds)[5], ((uint32_t*)__fds)[4], ((uint32_t*)__fds)[3], ((uint32_t*)__fds)[2], ((uint32_t*)__fds)[1], ((uint32_t*)__fds)[0]);
		break;
	default:
		buf[0] = '\0';
	}
	return buf;
}

/* Check the first NFDS descriptors each in READFDS (if not NULL) for read
   readiness, in WRITEFDS (if not NULL) for write readiness, and in EXCEPTFDS
   (if not NULL) for exceptional conditions.  If TIMis not NULL, time out
   after waiting the interval specified therein.  Returns the number of ready
   descriptors, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
int select_helper(int __nfds,
	   fd_set *__readfds,
	   fd_set * __writefds,
	   fd_set * __exceptfds,
	   struct timeval * __timeout,
	   const sigset_t *__sigmask = NULL)
{
	int off_rfds_buffer[__nfds];
	io_mux_call::offloaded_mode_t off_modes_buffer[__nfds];

	if (g_vlogger_level >= VLOG_FUNC) {
		const int tmpbufsize = 256;
		char tmpbuf[tmpbufsize], tmpbuf2[tmpbufsize];
		NOT_IN_USE(tmpbufsize); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
		NOT_IN_USE(tmpbuf); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
		NOT_IN_USE(tmpbuf2); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
		srdr_logfunc("readfds: %s, writefds: %s",
			   sprintf_fdset(tmpbuf, tmpbufsize, __nfds, __readfds), 
			   sprintf_fdset(tmpbuf2, tmpbufsize, __nfds, __writefds));
	}

	try {
		select_call scall(off_rfds_buffer, off_modes_buffer,
		                  __nfds, __readfds, __writefds, __exceptfds, __timeout, __sigmask);
		int rc = scall.call();

		if (g_vlogger_level >= VLOG_FUNC) {
			const int tmpbufsize = 256;
			char tmpbuf[tmpbufsize], tmpbuf2[tmpbufsize];
			NOT_IN_USE(tmpbufsize); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
			NOT_IN_USE(tmpbuf); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
			NOT_IN_USE(tmpbuf2); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
			srdr_logfunc_exit("readfds: %s, writefds: %s",
				   sprintf_fdset(tmpbuf, tmpbufsize, __nfds, __readfds),
				   sprintf_fdset(tmpbuf2, tmpbufsize, __nfds, __writefds));
		}

		return rc;
	}
	catch (io_mux_call::io_error&) {
		srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
		return -1;
	}
}

extern "C"
int select(int __nfds,
	   fd_set *__readfds,
	   fd_set * __writefds,
	   fd_set * __exceptfds,
	   struct timeval * __timeout)
{
	if (!g_p_fd_collection) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.select) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		return orig_os_api.select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
	}

	if (__timeout) {
		srdr_logfunc_entry("nfds=%d, timeout=(%d sec, %d usec)",
				                   __nfds, __timeout->tv_sec, __timeout->tv_usec);
	} else {
		srdr_logfunc_entry("nfds=%d, timeout=(infinite)", __nfds);
	}

	return select_helper(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

extern "C"
int pselect(int __nfds,
	    fd_set *__readfds,
	    fd_set *__writefds,
	    fd_set *__errorfds,
	    const struct timespec *__timeout,
	    const sigset_t *__sigmask)
{
	if (!g_p_fd_collection) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.pselect) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		return orig_os_api.pselect(__nfds, __readfds, __writefds, __errorfds, __timeout, __sigmask);
	}

	struct timeval select_time;
	if (__timeout) {
		srdr_logfunc_entry("nfds=%d, timeout=(%d sec, %d nsec)",
					           __nfds, __timeout->tv_sec, __timeout->tv_nsec);
		select_time.tv_sec = __timeout->tv_sec;
		select_time.tv_usec = __timeout->tv_nsec / 1000;
	} else {
		srdr_logfunc_entry("nfds=%d, timeout=(infinite)", __nfds);
	}

	return select_helper(__nfds, __readfds, __writefds, __errorfds, __timeout ? &select_time : NULL, __sigmask);
}

/* Poll the file descriptors described by the NFDS structures starting at
   FDS.  If TIMis nonzero and not -1, allow TIMmilliseconds for
   an event to occur; if TIMis -1, block until an event occurs.
   Returns the number of file descriptors with events, zero if timed out,
   or -1 for errors.  */
int poll_helper(struct pollfd *__fds, nfds_t __nfds, int __timeout, const sigset_t *__sigmask = NULL)
{
	int off_rfd_buffer[__nfds];
	io_mux_call::offloaded_mode_t off_modes_buffer[__nfds];
	int lookup_buffer[__nfds];
	pollfd working_fds_arr[__nfds + 1];

	try {
		poll_call pcall(off_rfd_buffer, off_modes_buffer, lookup_buffer, working_fds_arr,
		                __fds, __nfds, __timeout, __sigmask);
		
		int rc = pcall.call();
		srdr_logfunc_exit("rc = %d", rc);
		return rc;
	}
	catch (io_mux_call::io_error&) {
		srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
		return -1;
	}
}

extern "C"
int poll(struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
	if (!g_p_fd_collection) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.poll) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		return orig_os_api.poll(__fds, __nfds, __timeout);
	}

	srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, __timeout);

	return poll_helper(__fds, __nfds, __timeout);
}

extern "C"
int ppoll(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout, const sigset_t *__sigmask)
{
	if (!g_p_fd_collection) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (!orig_os_api.ppoll) get_orig_funcs();
		BULLSEYE_EXCLUDE_BLOCK_END
		return orig_os_api.ppoll(__fds, __nfds, __timeout, __sigmask);
	}

	int timeout = (__timeout == NULL) ? -1 :
	           (__timeout->tv_sec * 1000 + __timeout->tv_nsec / 1000000);

	srdr_logfunc_entry("nfds=%d, timeout=(%d milli-sec)", __nfds, timeout);

	return poll_helper(__fds, __nfds, timeout, __sigmask);
}

void vma_epoll_create(int epfd, int size)
{
	if (g_p_fd_collection) {
		// Sanity check to remove any old sockinfo object using the same fd!!
		handle_close(epfd, true);

		// insert epfd to fd_collection as epfd_info
		g_p_fd_collection->addepfd(epfd, size);
	}
}

/* Creates an epoll instance.  Returns fd for the new instance.
   The "size" parameter is a hint specifying the number of file
   descriptors to be associated with the new instance.  The fd
   returned by epoll_create() should be closed with close().  */
extern "C"
int epoll_create(int __size)
{
	DO_GLOBAL_CTORS();

	if (__size <= 0 ) {
		srdr_logdbg("invalid size (size=%d) - must be a positive integer\n", __size);
		errno = EINVAL;
		return -1;
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.epoll_create) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int epfd = orig_os_api.epoll_create(__size + 1);  // +1 for the cq epfd
	srdr_logdbg("ENTER: (size=%d) = %d\n", __size, epfd);

	if (epfd <=0)
		return epfd;

	vma_epoll_create(epfd, 8);

	return epfd;
}

extern "C"
int epoll_create1(int __flags)
{
	DO_GLOBAL_CTORS();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.epoll_create1) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int epfd = orig_os_api.epoll_create1(__flags);
	srdr_logdbg("ENTER: (flags=%d) = %d\n", __flags, epfd);

	if (epfd <=0)
		return epfd;

	vma_epoll_create(epfd, 8);

	return epfd;
}

/* Manipulate an epoll instance "epfd". Returns 0 in case of success,
   -1 in case of error ("errno" variable will contain the specific
   error code). The "op" parameter is one of the EPOLL_CTL_*
   constants defined above. The "fd" parameter is the target of the
   operation. The "event" parameter describes which events the caller
   is interested in and any associated user data.  */
extern "C"
int epoll_ctl(int __epfd, int __op, int __fd, struct epoll_event *__event)
{
	const static char * op_names[] = {
	     "<null>",
	     "ADD",
	     "DEL",
	     "MOD"
	};
	NOT_IN_USE(op_names); /* to suppress warning in case VMA_MAX_DEFINED_LOG_LEVEL */
	if (__event) {
		srdr_logfunc_entry("epfd=%d, op=%s, fd=%d, events=%#x, data=%x", 
			__epfd, op_names[__op], __fd, __event->events, __event->data.u64);
	}
	else {
		srdr_logfunc_entry("epfd=%d, op=%s, fd=%d, event=NULL", __epfd, op_names[__op], __fd);
	}

	int rc = -1;
	epfd_info *epfd_info = fd_collection_get_epfd(__epfd);
	if (!epfd_info) {
		errno = EBADF;
	}
	else {
		// TODO handle race - if close() gets here..
		rc = epfd_info->ctl(__op, __fd, __event);
	}
	
	srdr_logfunc_exit("rc = %d", rc);
	return rc;
}

/* Wait for events on an epoll instance "epfd". Returns the number of
   triggered events returned in "events" buffer. Or -1 in case of
   error with the "errno" variable set to the specific error code. The
   "events" parameter is a buffer that will contain triggered
   events. The "maxevents" is the maximum number of events to be
   returned ( usually size of "events" ). The "timeout" parameter
   specifies the maximum wait time in milliseconds (-1 == infinite).  */
inline int epoll_wait_helper(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout, const sigset_t *__sigmask = NULL)
{
	if (__maxevents <= 0 || __maxevents > EP_MAX_EVENTS) {
		srdr_logdbg("invalid value for maxevents: %d", __maxevents);
		errno = EINVAL;
		return -1;
	}

	epoll_event extra_events_buffer[__maxevents];

	try {
		epoll_wait_call epcall(extra_events_buffer, NULL,
				__epfd, __events, __maxevents, __timeout, __sigmask);

		int rc = epcall.get_current_events(); // returns ready nfds
		if (rc <= 0) {
			// if no ready nfds available then check all lower level queues (VMA ring's and OS queues)
			epcall.init_offloaded_fds();
			rc = epcall.call();
		}

		srdr_logfunc_exit("rc = %d", rc);
		return rc;
	}
	catch (io_mux_call::io_error&) {
		srdr_logfunc_exit("io_mux_call::io_error (errno=%d %m)", errno);
		return -1;
	}
}

extern "C"
int epoll_wait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout)
{
	srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents, __timeout);

	return epoll_wait_helper(__epfd, __events, __maxevents, __timeout);
}

extern "C"
int epoll_pwait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout, const sigset_t *__sigmask)
{
	srdr_logfunc_entry("epfd=%d, maxevents=%d, timeout=(%d milli-sec)", __epfd, __maxevents, __timeout);

	return epoll_wait_helper(__epfd, __events, __maxevents, __timeout, __sigmask);
}

/* Create two new sockets, of type TYPE in domain DOMand using
   protocol PROTOCOL, which are connected to each other, and put file
   descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
   one will be chosen automatically.  Returns 0 on success, -1 for errors.  */
extern "C"
int socketpair(int __domain, int __type, int __protocol, int __sv[2])
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.socketpair) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int ret = orig_os_api.socketpair(__domain, __type, __protocol, __sv);

	srdr_logdbg("(domain=%s(%d) type=%s(%d) protocol=%d, fd[%d,%d]) = %d\n", socket_get_domain_str(__domain), __domain, socket_get_type_str(__type), __type, __protocol, __sv[0], __sv[1], ret);

	// Sanity check to remove any old sockinfo object using the same fd!!
	if (ret == 0 && g_p_fd_collection) {
		handle_close(__sv[0], true);
		handle_close(__sv[1], true);
	}

	return ret;
}

/* Create a one-way communication channel (pipe).
   If successful, two file descriptors are stored in PIPEDES;
   bytes written on PIPEDES[1] can be read from PIPEDES[0].
   Returns 0 if successful, -1 if not.  */
extern "C"
int pipe(int __filedes[2])
{
	bool offload_pipe = safe_mce_sys().mce_spec == MCE_SPEC_29WEST_LBM_29 ||
			    safe_mce_sys().mce_spec == MCE_SPEC_WOMBAT_FH_LBM_554;
	if (offload_pipe)
		DO_GLOBAL_CTORS();

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.pipe) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int ret = orig_os_api.pipe(__filedes);
	srdr_logdbg("(fd[%d,%d]) = %d\n", __filedes[0], __filedes[1], ret);

	if (ret == 0 && g_p_fd_collection) {
		// Sanity check to remove any old sockinfo object using the same fd!!
		int fdrd = __filedes[0];
		handle_close(fdrd, true);
		int fdwr = __filedes[1];
		handle_close(fdwr, true);

		// Create new pipeinfo object for this new fd pair
		if (offload_pipe)
			g_p_fd_collection->addpipe(fdrd, fdwr);
	}

	return ret;
}

extern "C"
int open(__const char *__file, int __oflag, ...)
{
	va_list va;
	va_start(va, __oflag);
	mode_t mode = va_arg(va, mode_t);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.open) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int fd = orig_os_api.open(__file, __oflag, mode);
	va_end(va);

	srdr_logdbg("(file=%s, flags=%#x, mode=%#x) = %d\n", __file, __oflag, mode, fd);

	// Sanity check to remove any old sockinfo object using the same fd!!
	handle_close(fd, true);

	return fd;
}

extern "C"
int creat(const char *__pathname, mode_t __mode)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.creat) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int fd = orig_os_api.creat(__pathname, __mode);

	srdr_logdbg("(pathname=%s, mode=%#x) = %d\n", __pathname, __mode, fd);

	// Sanity check to remove any old sockinfo object using the same fd!!
	handle_close(fd, true);

	return fd;
}

/* Duplicate FD, returning a new file descriptor on the same file.  */
extern "C"
int dup(int __fd)
{
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.dup) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int fid = orig_os_api.dup(__fd);

	srdr_logdbg("(fd=%d) = %d\n", __fd, fid);

	// Sanity check to remove any old sockinfo object using the same fd!!
	handle_close(fid, true);

	return fid;
}

/* Duplicate FD to FD2, closing FD2 and making it open on the same file.  */
extern "C"
int dup2(int __fd, int __fd2)
{
	if (safe_mce_sys().close_on_dup2 && __fd != __fd2) {
		srdr_logdbg("oldfd=%d, newfd=%d. Closing %d in VMA.\n", __fd, __fd2, __fd2);
		handle_close(__fd2);
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.dup2) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int fid = orig_os_api.dup2(__fd, __fd2);

	srdr_logdbg("(fd=%d, fd2=%d) = %d\n",  __fd, __fd2, fid);

	// Sanity check to remove any old sockinfo object using the same fd!!
	handle_close(fid, true);

	return fid;
}

#ifdef _CHANGE_CLONE_PROTO_IN_SLES_10_
extern "C"
int clone(int (*__fn)(void *), void *__child_stack, int __flags, void *__arg)
{
	srdr_logfunc_entry("flags=%#x", __flags);

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.clone) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	return orig_os_api.clone(__fn, __child_stack, __flags, __arg);
}
#endif

/* Clone the calling process, creating an exact copy.
   Return -1 for errors, 0 to the new process,
   and the process ID of the new process to the old process.  */

extern "C"
pid_t fork(void)
{
	srdr_logdbg("ENTER: **********\n");

	if (!g_init_global_ctors_done) {
		set_env_params();
		prepare_fork();
	}

	if (!g_init_ibv_fork_done)
		srdr_logdbg("ERROR: ibv_fork_init failed, the effect of an application calling fork() is undefined!!\n");

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.fork) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	pid_t pid = orig_os_api.fork();
	if (pid == 0) {
		g_is_forked_child = true;
		srdr_logdbg_exit("Child Process: returned with %d", pid);
		// Child's process - restart module
		vlog_stop();


		// In case of child process, we want all global objects to re-construct
		reset_globals();

		g_init_global_ctors_done = false;
		sock_redirect_exit();

		safe_mce_sys().get_env_params();
		vlog_start("VMA", safe_mce_sys().log_level, safe_mce_sys().log_filename, safe_mce_sys().log_details, safe_mce_sys().log_colors);
		if (vma_rdma_lib_reset()) {
			srdr_logerr("Child Process: rdma_lib_reset failed %m",
					errno);
		}
		srdr_logdbg_exit("Child Process: starting with %d", getpid());
		g_is_forked_child = false;
		sock_redirect_main();
	}
	else if (pid > 0) {
		srdr_logdbg_exit("Parent Process: returned with %d", pid);
	}
	else {
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	}

	return pid;
}

/* Redirect vfork to fork  */
extern "C"
pid_t vfork(void)
{
	return fork();
}

/* Put the program in the background, and dissociate from the controlling
   terminal.  If NOCHDIR is zero, do `chdir ("/")'.  If NOCLOSE is zero,
   redirects stdin, stdout, and stderr to /dev/null.  */
extern "C"
int daemon(int __nochdir, int __noclose)
{
	srdr_logdbg("ENTER: ***** (%d, %d) *****\n", __nochdir, __noclose);

	if (!g_init_global_ctors_done) {
		set_env_params();
		prepare_fork();
	}

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.daemon) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	int ret = orig_os_api.daemon(__nochdir, __noclose);
	if (ret == 0) {
		g_is_forked_child = true;
		srdr_logdbg_exit("returned with %d", ret);

		// Child's process - restart module
		vlog_stop();

		// In case of child process, we want all global objects to re-construct
		reset_globals();

		g_init_global_ctors_done = false;
		sock_redirect_exit();

		safe_mce_sys().get_env_params();
		vlog_start("VMA", safe_mce_sys().log_level, safe_mce_sys().log_filename, safe_mce_sys().log_details, safe_mce_sys().log_colors);
		if (vma_rdma_lib_reset()) {
			srdr_logerr("Child Process: rdma_lib_reset failed %m",
					errno);
		}
		srdr_logdbg_exit("Child Process: starting with %d", getpid());
		g_is_forked_child = false;
		sock_redirect_main();
	}
	else {
		srdr_logdbg_exit("failed (errno=%d %m)", errno);
	}
	return ret;
}

static void handler_intr(int sig)
{
	switch (sig) {
	case SIGINT:
		g_b_exit = true;
		srdr_logdbg("Catch Signal: SIGINT (%d)\n", sig);
		break;
	default:
		srdr_logdbg("Catch Signal: %d\n", sig);
		break;
	}

	if (g_act_prev.sa_handler)
		g_act_prev.sa_handler(sig);
}

extern "C"
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	int ret = 0;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (!orig_os_api.sigaction) get_orig_funcs();
	BULLSEYE_EXCLUDE_BLOCK_END

	if (safe_mce_sys().handle_sigintr) {
		srdr_logdbg_entry("signum=%d, act=%p, oldact=%p", signum, act, oldact);

		switch (signum) {
		case SIGINT:
			if (oldact && g_act_prev.sa_handler) {
				*oldact = g_act_prev;
			}
			if (act) {
				struct sigaction vma_action;
				vma_action.sa_handler = handler_intr;
				vma_action.sa_flags = 0;
				sigemptyset(&vma_action.sa_mask);

				ret = orig_os_api.sigaction(SIGINT, &vma_action, NULL);

				if (ret < 0) {
					srdr_logdbg("Failed to register VMA SIGINT handler, calling to original sigaction handler\n");
					break;
				}
				srdr_logdbg("Registered VMA SIGINT handler\n");
				g_act_prev = *act;
			}
			if (ret >= 0)
				srdr_logdbg_exit("returned with %d", ret);
			else
				srdr_logdbg_exit("failed (errno=%d %m)", errno);

			return ret;
			break;
		default:
			break;
		}
	}
	ret = orig_os_api.sigaction(signum, act, oldact);

	if (safe_mce_sys().handle_sigintr) {
		if (ret >= 0)
			srdr_logdbg_exit("returned with %d", ret);
		else
			srdr_logdbg_exit("failed (errno=%d %m)", errno);
	}
	return ret;
}

static void handle_signal(int signum)
{
	srdr_logdbg_entry("Caught signal! signum=%d", signum);

	if (signum == SIGINT) {
		g_b_exit = true;
	}

	if (g_sighandler) {
		g_sighandler(signum);
	}
}

extern "C"
sighandler_t signal(int signum, sighandler_t handler)
{
	srdr_logdbg_entry("signum=%d, handler=%p", signum, handler);

	if (!orig_os_api.signal) get_orig_funcs();

	if (handler && handler != SIG_ERR && handler != SIG_DFL && handler != SIG_IGN) {
		// Only SIGINT is supported for now
		if (signum == SIGINT) {
			g_sighandler = handler;
			return orig_os_api.signal(SIGINT, &handle_signal);
		}
	}

	return orig_os_api.signal(signum, handler);
}
