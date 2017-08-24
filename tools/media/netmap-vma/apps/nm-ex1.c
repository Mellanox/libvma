#include <poll.h>
#include <stdbool.h>
#include <time.h>

#include <bitstream/ieee/ethernet.h>
#include <bitstream/ietf/ip.h>

#define NETMAP_WITH_LIBS
#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#ifdef NETMAP_VMA
#include "netmap_vma.h"
#endif

/* switch for blocking or non blocking API */
static const bool block = true;

/* packet processing */
static void handle(const uint8_t *pkt, size_t len)
{
#ifndef NETMAP_VMA
	if (len < ETHERNET_HEADER_LEN + IP_HEADER_MINSIZE)
	{
		return;
	}

	if (ethernet_get_lentype(pkt) != ETHERNET_TYPE_IP)
	{
		return;
	}

	const uint8_t *ip = &pkt[ETHERNET_HEADER_LEN];
	if (ip_get_version(ip) != 4) {
		return;
	}
	//printf("ip_get_len=%d ip_get_proto=%d\n", ip_get_len(ip), ip_get_proto(ip));

#else
	size_t k, packets = len;

	for (k = 0; k < packets; k++) {

		if (ethernet_get_lentype(pkt) != ETHERNET_TYPE_IP)
		{
			return;
		}

		const uint8_t *ip = &pkt[ETHERNET_HEADER_LEN];
		if (ip_get_version(ip) != 4) {
			return;
		}
		//printf("ip_get_len=%d ip_get_proto=%d\n", ip_get_len(ip), ip_get_proto(ip));

		pkt += STRIDE_SIZE;
	}
#endif
}

static void loop(struct nm_desc *d)
{
#ifndef NETMAP_VMA
	struct pollfd pfd = {
			.fd = NETMAP_FD(d),
			.events = POLLIN|POLLERR,
	};
	nfds_t nfds = 1;
#endif
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = 1000000; // 1ms
#ifndef NETMAP_VMA
	struct netmap_ring *rxring = NETMAP_RXRING(d->nifp, d->cur_rx_ring);
#endif
	for (;;) {
		if (block) {
#ifndef NETMAP_VMA
			if (poll(&pfd, nfds, -1) != (int)nfds) {
#else
			if (poll_nm_vma(d, -1) < 0) {
#endif
				perror("poll");
				break;
			}
		} else {
				clock_nanosleep(CLOCK_MONOTONIC, 0, &delay, NULL);
#ifndef NETMAP_VMA
				if (ioctl(NETMAP_FD(d), NIOCRXSYNC, NULL) < 0)
					perror("ioctl");
#endif
		}
#ifndef NETMAP_VMA
		uint32_t cur = rxring->cur;
		/* process all packets */
		while (!nm_ring_empty(rxring)) {
			struct netmap_slot *slot = &rxring->slot[cur];
			const uint8_t *src = (uint8_t*)NETMAP_BUF(rxring, slot->buf_idx);
			/* process packet */
			handle(src, slot->len);
			/* next packet */
			cur = nm_ring_next(rxring, cur);
		}
		/* update ring buffer */
		rxring->head = rxring->cur = nm_ring_next(rxring, cur);
#else
		uint8_t *buf;
		struct nm_pkthdr h;

		/* process all packets */
		while ((buf = (uint8_t*)nm_nextpkt(d, &h))) {
			/* process packets */
			handle(h.buf, h.len);
		}
#endif
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s netmap:p1p2-0/R\n", argv[0]);
		return 1;
	}

	/* open interface */
	struct nm_desc *d = nm_open(argv[1], NULL, 0, 0);
	if (!d) {
		return 2;
	}
	sleep(2);
	loop(d);
	nm_close(d);

	return 0;
}
