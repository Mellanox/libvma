/*
 * Copyright (c) 2001-2020 Mellanox Technologies, Ltd. All rights reserved.
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

#include <arpa/inet.h>
#include <stdio.h>
#include <linux/socket.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <fstream>
#include "vma/util/vtypes.h"
#include "vma_extra.h"

#ifdef HAVE_MP_RQ
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

/* buffer size is 2^17 = 128MB */
#define	VMA_CYCLIC_BUFFER_SIZE	(1<<17)
#define	VMA_CYCLIC_BUFFER_USER_PKT_SIZE	1400
#define	VMA_CYCLIC_BUFFER_MIN_PKTS	1000
#define	VMA_CYCLIC_BUFFER_MAX_PKTS	5000
#define	VMA_NM_SLEEP	1

#define	MAX_RINGS	1000
#define	PRINT_PERIOD_SEC	5
#define	PRINT_PERIOD		1000000 * PRINT_PERIOD_SEC
#define	MAX_SOCKETS_PER_RING	4096
#define	STRIDE_SIZE	2048

class RXSock;
class CommonCyclicRing;

class RXSock {
public:
	uint64_t	statTime;
	int		lastPacketType;
	int		index;
	int		fd;
	int		ring_fd;
	uint16_t	rtpPayloadType;
	uint16_t	sin_port;
	struct ip_mreqn	mc;
	char		ipAddress[INET_ADDRSTRLEN];
	int bad_packets;
};

class CommonCyclicRing {
public:
	unsigned long printCount;
	int numOfSockets;
	int ring_id;
	int ring_fd;
	RXSock* hashedSock[MAX_SOCKETS_PER_RING];
	std::ofstream * pOutputfile;
	std::vector<sockaddr_in*> addr_vect;
	std::vector<RXSock*> sock_vect;
	CommonCyclicRing():printCount(0),numOfSockets(0),ring_fd(0){
		for (int i=0; i < MAX_SOCKETS_PER_RING; i++) {
			hashedSock[i] = 0;
		}
	}
	struct vma_api_t *vma_api;
	size_t	min_s;
	size_t	max_s;
	int 	flags;
	int	sleep_time;
	struct vma_completion_cb_t completion;
	bool	is_readable;
};

struct flow_param {
	int ring_id;
	unsigned short hash;
	sockaddr_in addr;
};

static unsigned short hashIpPort2(sockaddr_in addr)
{
	int hash = ((size_t)(addr.sin_addr.s_addr) * 59) ^ ((size_t)(addr.sin_port) << 16);
	unsigned char smallHash = (unsigned char)(((unsigned char) ((hash*19) >> 24))  ^ ((unsigned char) ((hash*17) >> 16)) ^ ((unsigned char) ((hash*5) >> 8)) ^ ((unsigned char) hash));
	unsigned short mhash = ((((addr.sin_addr.s_addr >>24) & 0x7) << 8) | smallHash) ;
	//printf("0x%x\n",addr.sin_addr.s_addr);
	return mhash;
}

static inline unsigned long long int time_get_usec()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (((unsigned long long int) tv.tv_sec * 1000000LL)
			+ (unsigned long long int) tv.tv_usec);
}

static int CreateRingProfile(bool CommonFdPerRing, int RingProfile, int user_id, int RxSocket)
{
	vma_ring_alloc_logic_attr profile;
	profile.engress = 0;
	profile.ingress = 1;
	profile.ring_profile_key = RingProfile;
	if (CommonFdPerRing) {
		profile.user_id = user_id;
		profile.comp_mask = VMA_RING_ALLOC_MASK_RING_PROFILE_KEY	|
				VMA_RING_ALLOC_MASK_RING_USER_ID	|
				VMA_RING_ALLOC_MASK_RING_INGRESS;

		// if we want several Fd's per ring, we need to assign RING_LOGIC_PER_THREAD / RING_LOGIC_PER_CORE
		profile.ring_alloc_logic = RING_LOGIC_PER_USER_ID;
	} else {
		profile.comp_mask = VMA_RING_ALLOC_MASK_RING_PROFILE_KEY|
				VMA_RING_ALLOC_MASK_RING_INGRESS;
		// if we want several Fd's per ring, we need to assign RING_LOGIC_PER_THREAD / RING_LOGIC_PER_CORE
		profile.ring_alloc_logic = RING_LOGIC_PER_SOCKET;
	}
	return setsockopt(RxSocket, SOL_SOCKET, SO_VMA_RING_ALLOC_LOGIC,&profile, sizeof(profile));
}

static int OpenRxSocket(int ring_id, sockaddr_in* addr, uint32_t ssm, const char *device,
		struct ip_mreqn *mc, int RingProfile, bool CommonFdPerRing)
{
	int i_ret;
	struct timeval timeout = { 0, 1 };
	int i_opt = 1;
	struct ifreq ifr;
	struct sockaddr_in *p_addr;

	// Create the socket
	int RxSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (RxSocket < 0) {
		printf("%s: Failed to create socket (%s)\n",
				__func__,std::strerror(errno));
		return 0;
	}

	// Enable socket reuse (for multi channels bind to a single socket)
	i_ret = setsockopt(RxSocket, SOL_SOCKET, SO_REUSEADDR,
			(void *) &i_opt, sizeof(i_opt));
	if (i_ret < 0) {
		close(RxSocket);
		RxSocket = 0;
		printf("%s: Failed to set SO_REUSEADDR (%s)\n",
				__func__, strerror(errno));
		return 0;
	}
	fcntl(RxSocket, F_SETFL, O_NONBLOCK);
	CreateRingProfile(CommonFdPerRing, RingProfile, ring_id, RxSocket);
	// bind to specific device
	struct ifreq interface;
	strncpy(interface.ifr_ifrn.ifrn_name, device, IFNAMSIZ);
	//printf("%s SO_BINDTODEVICE %s\n",__func__,interface.ifr_ifrn.ifrn_name);
	if (setsockopt(RxSocket, SOL_SOCKET, SO_BINDTODEVICE,
			(char *) &interface, sizeof(interface)) < 0) {
		printf("%s: Failed to bind to device (%s)\n",
				__func__, strerror(errno));
		close(RxSocket);
		RxSocket = 0;
		return 0;
	}

	// bind to socket
	i_ret = bind(RxSocket, (struct sockaddr *)addr, sizeof(struct sockaddr));
	if (i_ret < 0) {
		printf("%s: Failed to bind to socket (%s)\n",__func__,strerror(errno));
		close(RxSocket);
		RxSocket = 0;
		return 0;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, device, IFNAMSIZ);
	// Get device IP
	i_ret = ioctl(RxSocket, SIOCGIFADDR, &ifr);
	if (i_ret < 0) {
		printf("%s: Failed to obtain interface IP (%s)\n",__func__,	strerror(errno));
		close(RxSocket);
		RxSocket = 0;
		return 0;
	}

	if (((addr->sin_addr.s_addr & 0xFF) >= 224) && ((addr->sin_addr.s_addr & 0xFF) <= 239)) {
		p_addr = (struct sockaddr_in *) &(ifr.ifr_addr);
		if (ssm == 0) {
			struct ip_mreqn mreq;
			// join the multicast group on specific device
			memset(&mreq, 0, sizeof(struct ip_mreqn));

			mreq.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
			mreq.imr_address.s_addr = p_addr->sin_addr.s_addr;
			*mc = mreq;
			// RAFI MP_RING is created
			i_ret = setsockopt(RxSocket, IPPROTO_IP,
					IP_ADD_MEMBERSHIP, &mreq,
					sizeof(struct ip_mreqn));

			if (i_ret < 0) {
				printf("%s: add membership to (0X%08X) on (0X%08X) failed. (%s)\n",__func__,mreq.imr_multiaddr.s_addr,
						mreq.imr_address.s_addr,
						strerror(errno));
				close(RxSocket);
				RxSocket = 0;
				return 0;
			}
		} else {
			struct ip_mreq_source mreqs;
			// join the multicast group on specific device
			memset(&mreqs, 0, sizeof(struct ip_mreq_source));

			mreqs.imr_multiaddr.s_addr = addr->sin_addr.s_addr;
			mreqs.imr_interface.s_addr = p_addr->sin_addr.s_addr;
			mreqs.imr_sourceaddr.s_addr = ssm;

			i_ret = setsockopt(RxSocket, IPPROTO_IP,
					IP_ADD_SOURCE_MEMBERSHIP, &mreqs,
					sizeof(struct ip_mreq_source));

			if (i_ret < 0) {
				printf("%s: add membership to (0X%08X), ssm (0X%08X) failed. (%s)\n",__func__,
						mreqs.imr_multiaddr.s_addr,
						mreqs.imr_sourceaddr.s_addr,
						strerror(errno));
				close(RxSocket);
				RxSocket = 0;
				return 0;
			}
		}
	}

	// Set max receive timeout
	i_ret = setsockopt(RxSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout,
			sizeof(struct timeval));
	if (i_ret < 0) {
		printf("%s: Failed to set SO_RCVTIMEO (%s)\n",__func__,
				strerror(errno));
		close(RxSocket);
		RxSocket = 0;
		return 0;
	}

	return RxSocket;
}

#define	IP_HEADER_OFFSET	14
#define	IP_HEADER_SIZE	20
#define	IP_DEST_OFFSET	(IP_HEADER_OFFSET+ 16)
#define	UDP_HEADER_OFFSET	(IP_HEADER_SIZE + IP_HEADER_OFFSET)
#define	PORT_DEST_OFFSET	(UDP_HEADER_OFFSET + 2)

static void AddFlow(flow_param flow,CommonCyclicRing* rings[], int &uniqueRings)
{
	int ring_id = flow.ring_id;
	if (rings[ring_id] == NULL) {
		rings[ring_id] = new CommonCyclicRing;
		rings[ring_id]->ring_id =ring_id;
		uniqueRings++;
	}
	rings[ring_id]->numOfSockets++;
	sockaddr_in* pAddr = new sockaddr_in;
	*pAddr = flow.addr;
	rings[ring_id]->addr_vect.push_back(pAddr);
}

static void destroyFlows(CommonCyclicRing* rings[])
{
	for (int i=0; i < MAX_RINGS; i++) {
		if (rings[i] != NULL) {
			for (std::vector<sockaddr_in*>::iterator it = rings[i]->addr_vect.begin(); it!=rings[i]->addr_vect.end(); ++it) {
				delete *it;
			}
			for (std::vector<RXSock*>::iterator it = rings[i]->sock_vect.begin(); it!=rings[i]->sock_vect.end(); ++it) {
				delete *it;
			}
			delete rings[i];
		}
	}
}

#define	DEFAULT_PORT	2000

static CommonCyclicRing* pRings[MAX_RINGS];
static void init_ring_helper(CommonCyclicRing* pRing);

extern "C"
struct nm_desc *nm_open_vma(const char *nm_ifname, const struct nmreq *req, uint64_t flags, const struct nm_desc *arg)
{
	NOT_IN_USE(req);
	NOT_IN_USE(flags);
	NOT_IN_USE(arg);

	char *opts = NULL;
	char *nm_ring = NULL;
	char *nm_port = NULL;
	char nm_mode = ' ';
	char ifname[IFNAMSIZ];
	char nm_ring_val[10];
	u_int namelen;
	struct nm_desc *d = NULL;
	int nm_ring_len = 0;
	int nm_ring_set = 0;
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];

	d = new nm_desc();
	if (strncmp(nm_ifname, "netmap:", 7)) {
		errno = 0;
		printf("name not recognised\n");
		return NULL;
	}
	nm_ifname += 7;
	opts = (char*)nm_ifname;
	for (; *opts && !index("-", *opts) ; opts++);
	namelen = opts - nm_ifname;
	if (namelen >= sizeof(d->req.nr_name)) {
		printf("name too long\n");
		return NULL;
	} else {
		memcpy(ifname, nm_ifname, namelen);
		ifname[namelen] = '\0';
		memcpy(d->req.nr_name, nm_ifname, namelen);
		d->req.nr_name[namelen] = '\0';
	}

	while(*opts) {
		switch (*opts) {
		case '-':
			nm_ring = ++opts;
			nm_ring_set = 1;
			break;
		case '/':
			if (nm_ring_set--) nm_ring_len = opts - nm_ring;
			nm_mode = *(opts +1);
			break;
		case ':':
			if (nm_ring_set--) nm_ring_len = opts - nm_ring;
			nm_port = ++opts;
			break;
		default:
			break;
		}
		opts++;
	}

	std::string nmring;
	nmring.append(nm_ring, nm_ring_len);

	std::string nmport;
	if (nm_port == NULL) {
		std::ostringstream s;
		s << DEFAULT_PORT;
		nmport.append(s.str());
		printf("nm_mode=%c nm_port=%d\n", nm_mode, DEFAULT_PORT);
	} else {
		nmport.append(nm_port);
		memcpy(nm_ring_val, nm_ring, nm_ring_len);
		nm_ring_val[nm_ring_len] = '\0';
		printf("nm_ring_val=%s nm_mode=%c nm_port=%s\n", nm_ring_val, nm_mode, nm_port);
	}

	if (getifaddrs(&ifaddr) == -1) {
		printf("error getifaddrs\n");
		return NULL;
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int ret;
		if (ifa->ifa_addr == NULL)
			continue;
		ret = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if ((strcmp(ifa->ifa_name, ifname) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
			if (ret != 0) {
				printf("error getnameinfo\n");
				return NULL;
			}
			break;
		}
	}
	freeifaddrs(ifaddr);

	std::string opts_line;
	opts_line.append(host);
	opts_line = opts_line + " " + nmport + " " + nmring;

	bool ringPerFd = false;
	for (int j = 0; j < MAX_RINGS; j++) {
		pRings[j] = NULL;
	}

	std::string ip;
	std::string line;
	int port;
	int ring_id;
	int sock_num = 0, socketRead = 0;
	char HashColision[MAX_RINGS][MAX_SOCKETS_PER_RING] = {0};
	int uniqueRings;
	int hash_colision_cnt = 0;
	char *cnfif_file = new char[IFNAMSIZ+4];

	snprintf(cnfif_file, IFNAMSIZ+4, "%s.txt", ifname);

	std::vector<std::string> cnf_if;

	std::ifstream infile(cnfif_file);
	if (infile) {
		while (getline(infile, line)) {
			if ((line[0] == '#') || ((line[0] == '/') && (line[1] == '/'))) {
				continue;
			}
			cnf_if.push_back(line);
		}
	} else {
		cnf_if.push_back(opts_line);
	}

	while (!cnf_if.empty()) {
		line = cnf_if.back();
		cnf_if.pop_back();
		std::istringstream iss(line);
		struct flow_param flow;
		if (iss >> ip >> port >> ring_id) {
			socketRead++;
			flow.addr.sin_family = AF_INET;
			flow.addr.sin_port = htons(port);
			flow.addr.sin_addr.s_addr = inet_addr(ip.c_str());
			flow.addr.sin_addr.s_addr = ntohl(ntohl(flow.addr.sin_addr.s_addr));
			printf("adding ip %s port %d,\n", ip.c_str(), port);
			flow.hash = hashIpPort2(flow.addr);
			printf("adding %s:%d hash val %d\n",ip.c_str(),port, flow.hash);
			if (flow.addr.sin_addr.s_addr < 0x01000001) {
				printf("Error - illegal IP %x\n", flow.addr.sin_addr.s_addr);
				return NULL;
			}
		} else {
			continue;
		}

		printf("ring_id=%d\n",ring_id);
		flow.ring_id = ring_id;
		if (HashColision[ring_id][flow.hash] == 0) {
			HashColision[ring_id][flow.hash] = 1;
			// add the fd to the ring, if needed create a ring, update num of rings, and num of flows within this ring.
			AddFlow(flow, pRings, uniqueRings);
		} else {
			hash_colision_cnt++;
			printf("Hash socket colision found , socket%s:%d - dropped, total %d\n",ip.c_str(),port,hash_colision_cnt);
		}
		if (socketRead == sock_num) {
			printf("read %d sockets from the file\n", socketRead);
			break;
		}
	}

	d->req.nr_rx_rings = ring_id;
	d->req.nr_ringid = ring_id;

	int prof = 0;
	struct vma_api_t *vma_api = vma_get_api();
	vma_ring_type_attr ring;
	ring.ring_type = VMA_RING_CYCLIC_BUFFER;
	ring.ring_cyclicb.num = VMA_CYCLIC_BUFFER_SIZE;
	ring.ring_cyclicb.stride_bytes = VMA_CYCLIC_BUFFER_USER_PKT_SIZE;
	//ring.ring_cyclicb.comp_mask = VMA_RING_TYPE_MASK;
	int res = vma_api->vma_add_ring_profile(&ring, &prof);
	if (res) {
		printf("failed adding ring profile");
		return NULL;
	}
	// for every ring, open sockets
	for (int i=0; i< MAX_RINGS; i++) {
		if (pRings[i] == NULL) {
			continue;
		}
		std::vector<sockaddr_in*>::iterator it;
		for (it = pRings[i]->addr_vect.begin();
				it!=pRings[i]->addr_vect.end(); ++it) {
			struct ip_mreqn mc;
			printf("Adding socket to ring %d\n",i);
			RXSock* pSock = new RXSock;
			pSock->fd = OpenRxSocket(pRings[i]->ring_id, *it, 0, ifname, &mc, prof, !ringPerFd);
			if (pSock->fd <= 0) {
				printf("Error OpenRxSocket failed. %d\n", i);
				return NULL;
			}
			memcpy(&pSock->mc, &mc, sizeof(mc));
			pSock->statTime = time_get_usec() + 1000*i;
			pSock->index = i;
			pSock->bad_packets = 0;
			pSock->sin_port = ntohs((*it)->sin_port);
			unsigned short hash = hashIpPort2(**it);
			//printf("hash value is %d\n",hash);
			if (NULL != pRings[i]->hashedSock[hash]) {
				printf ("Collision, reshuffle your ip addresses \n");
				return NULL;
			}
			pRings[i]->hashedSock[hash] = pSock;
			inet_ntop(AF_INET, &((*it)->sin_addr), pSock->ipAddress, INET_ADDRSTRLEN);
			pRings[i]->sock_vect.push_back(pSock);
			pRings[i]->min_s = VMA_CYCLIC_BUFFER_MIN_PKTS;
			pRings[i]->max_s = VMA_CYCLIC_BUFFER_MAX_PKTS;
			pRings[i]->flags = MSG_DONTWAIT;
			pRings[i]->vma_api = vma_get_api();
			pRings[i]->sleep_time = VMA_NM_SLEEP;
			pRings[i]->is_readable = false;
			init_ring_helper(pRings[i]);
		}
	}
	return d;
}

void init_ring_helper(CommonCyclicRing* pRing)
{
	int sock_len = pRing->numOfSockets;
	for (int i = 0; i < sock_len; i++) {
		int ring_fd_num = pRing->vma_api->get_socket_rings_num(pRing->sock_vect[i]->fd);
		int* ring_fds = new int[ring_fd_num];
		pRing->vma_api->get_socket_rings_fds(pRing->sock_vect[i]->fd, ring_fds, ring_fd_num);
		pRing->sock_vect[i]->ring_fd = *ring_fds;
		pRing->ring_fd = *ring_fds;
		delete[] ring_fds;
	}
}

static inline int cb_buffer_read(int ring)
{
	pRings[ring]->completion.packets = 0;
	return pRings[ring]->vma_api->vma_cyclic_buffer_read(pRings[ring]->ring_fd, &pRings[ring]->completion, pRings[ring]->min_s, pRings[ring]->max_s, pRings[ring]->flags);
}

static inline int cb_buffer_is_readable(int ring)
{
	for (int j = 0; j < 10; j++) {
		pRings[ring]->completion.packets = 0;
		if (pRings[ring]->vma_api->vma_cyclic_buffer_read(pRings[ring]->ring_fd, &pRings[ring]->completion, pRings[ring]->min_s, pRings[ring]->max_s, pRings[ring]->flags) < 0) {
			return -1;
		}
		if (pRings[ring]->completion.packets) {
			pRings[ring]->is_readable = true;
			return 1;
		}
	}
	//usleep(pRings[ring]->sleep_time);
	return 0;
}

// delay_ms(10) - 1ms
static void delay_ms(int ms)
{
	int start_time_ms, now_time_ms, time_diff;
	struct timespec start;
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &start);
	start_time_ms = ((double)(start.tv_nsec)/1e9)*10000; // 0.1ms

	while(1) {
		clock_gettime(CLOCK_REALTIME, &now);
		now_time_ms = ((double)(now.tv_nsec)/1e9)*10000;
		time_diff = now_time_ms - start_time_ms;
		if (time_diff < 0) {
			time_diff += 1000000000;
		}
		if (time_diff > ms) {
			break;
		}
		usleep(0);
	}
}

extern "C"
int poll_nm_vma(struct nm_desc *d, int timeout)
{
	int ret = 0;

	int ring = d->req.nr_ringid;
	pRings[ring]->is_readable = true;

	if (timeout == 0) {
		return cb_buffer_is_readable(ring);
	}
	if (timeout > 0) {
		while (timeout--) {
			ret = cb_buffer_is_readable(ring);
			if (ret)
				return ret;
			delay_ms(10); // daly 1ms
		}
	} else if (timeout < 0) {
		while(!ret) {
			ret = cb_buffer_is_readable(ring);
		}
	}
	return ret;
}

extern "C"
u_char *nm_nextpkt_vma(struct nm_desc *d, struct nm_pkthdr *hdr)
{
	int ring = d->req.nr_ringid;
	uint8_t *data = NULL;
	struct vma_completion_cb_t *completion = &pRings[ring]->completion;

	if (pRings[ring]->is_readable) {
		pRings[ring]->is_readable = false;
		hdr->len = hdr->caplen = completion->packets;
		hdr->buf = data = ((uint8_t *)completion->payload_ptr);

		d->hdr.buf = data;
		d->hdr.len = completion->packets;
		d->hdr.caplen = 0;
		return (u_char *)data;
	}

	for (int j = 0; j < 10; j++) {
		int res = cb_buffer_read(ring);
		if (res == -1) {
			printf("vma_cyclic_buffer_read returned -1");
			return NULL;
		}
		if (completion->packets == 0) {
			continue;
		}
		hdr->len = hdr->caplen = completion->packets;
		hdr->buf = data = ((uint8_t *)completion->payload_ptr);
		d->hdr.buf = data;
		d->hdr.len = completion->packets;
		d->hdr.caplen = 0;
		break;
	}
	return (u_char *)data;
}

extern "C"
int nm_dispatch_vma(struct nm_desc *d, int cnt, nm_cb_t cb, u_char *arg)
{
	NOT_IN_USE(arg);
	int ring = d->req.nr_ringid;
	struct vma_completion_cb_t *completion = &pRings[ring]->completion;
	int c = 0, got = 0;
	d->hdr.buf = NULL;
	d->hdr.flags = NM_MORE_PKTS;
	d->hdr.d = d;

	if (cnt == 0)
		cnt = -1;
	/* cnt == -1 means infinite, but rings have a finite amount
	 * of buffers and the int is large enough that we never wrap,
	 * so we can omit checking for -1
	 */
	for (c = 0; cnt != got; c++) {
		int res = cb_buffer_read(ring);
		if (res == -1) {
			printf("vma_cyclic_buffer_read returned -1");
			return 0;
		}
		if (completion->packets == 0) {
			continue;
		}
		got++;
		d->hdr.len = d->hdr.caplen = completion->packets;
		d->hdr.buf = ((uint8_t *)completion->payload_ptr);
	}
	if (d->hdr.buf) {
		cb(arg, &d->hdr, d->hdr.buf);
	}
	return got;
}

extern "C"
int nm_close_vma(struct nm_desc *d)
{
	destroyFlows(pRings);
	if (d == NULL) {
		return EINVAL;
	}
	delete d;
	return 0;
}
#endif

