/* server_tcp.c
 *
 * build:
 * epoll: gcc server_tcp.c -o server_tcp.out -DVMA_DEV="ens1f0" -DVMA_API=0 -I/usr/include
 * xtreme: gcc server_tcp.c -o server_tcp.out -DVMA_DEV="ens1f0" -DVMA_API=1 -I<path to mellanox/vma_extra.h>
 *
 * usage:
 * epoll: sudo server_tcp.out 1.1.3.15:17000
 * socketxtreme: sudo env LD_PRELOAD=libvma.so server_tcp.out 1.1.3.15:17000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/mman.h> /* mlock */
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/epoll.h>

#if defined(VMA_API) && (VMA_API == 1)
#include <mellanox/vma_extra.h>
#endif /* VMA_API */

/* Bind to device */
#if !defined(VMA_DEV)
#define IB_DEV "ens3f1"
#else
#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)
#define IB_DEV STR(VMA_DEV)
#endif

/* Number of listeners */
#define SFD_NUM 2

/* Number of peers */
#define FD_NUM 10

#define EXIT_FAILURE 1

#if defined(VMA_API) && (VMA_API == 1)
static struct vma_api_t *_vma_api = NULL;
static int _vma_ring_fd = -1;
#endif /* VMA_API */

static volatile int _done = 0;

static inline char *_addr2str(struct sockaddr_in *addr) {
	static __thread char addrbuf[100];
	inet_ntop(AF_INET, &addr->sin_addr, addrbuf, sizeof(addrbuf));
	sprintf(addrbuf, "%s:%d", addrbuf, ntohs(addr->sin_port));

	return addrbuf;
}

static void _proc_signal(int signal_id)
{
   _done = signal_id;
}

static int _set_noblock(int fd)
{
	int rc = 0;
	int flag;

	flag = fcntl(fd, F_GETFL);
	if (flag < 0) {
		rc = -errno;
		printf("failed to get socket flags %s\n", strerror(errno));
	}
	flag |= O_NONBLOCK;
	rc = fcntl(fd, F_SETFL, flag);
	if (rc < 0) {
		rc = -errno;
		printf("failed to set socket flags %s\n", strerror(errno));
	}

	return rc;
}

static int _tcp_create_and_bind(struct sockaddr_in *addr)
{
	int rc = 0;
	int fd;
	int flag;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (!fd) {
		rc = -EBUSY;
		printf("Failed to create socket\n");
		goto err;
	}

#if defined(IB_DEV)
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)IB_DEV, strlen(IB_DEV));
    if (rc < 0) {
            printf("Failed to setsockopt(SO_BINDTODEVICE) for %s: %s\n", IB_DEV, strerror(errno));
            exit(1);
    }
#endif

	flag = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(int));
	if (rc < 0) {
		printf("Failed to setsockopt(SO_REUSEADDR): %s\n", strerror(errno));
		goto err;
	}

	rc = bind(fd, (struct sockaddr *) addr, sizeof(*addr));
	if (rc < 0) {
		rc = -EBUSY;
		printf("Failed to bind socket\n");
		goto err;
	}

	listen(fd, SOMAXCONN);

	printf("Listen  : fd=%d %s\n", fd, _addr2str((struct sockaddr_in *)addr));

err:
	return (rc == 0 ? fd : (-1));
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int ret = 0;
	int efd;
	int sfd[SFD_NUM];
	int fd = -1;
	int max_events = 0;
	int max_sfd = 0;
	struct epoll_event ev;
	uint64_t event;
	struct epoll_event *events = NULL;
	struct conn_info {
		int *fds;
		int count;
		char msg[1024];
	} conns;
#if defined(VMA_API) && (VMA_API == 1)
	struct vma_completion_t *vma_comps;
#endif /* VMA_API */
	int flag;
	struct sockaddr_in addr;
	struct sockaddr in_addr;
	socklen_t in_len;
	int i = 0;
	int j = 0;

	/* catch SIGINT to exit */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = _proc_signal;
	sa.sa_flags = 0;
	sigemptyset(&(sa.sa_mask));
	if (sigaction(SIGINT, &sa, NULL) != 0) {
        	perror("Failed to create signal handler");
        	exit(EXIT_FAILURE);
	}

	/* Step:1 Initialize VMA API */
#if defined(VMA_API) && (VMA_API == 1)
	_vma_api = vma_get_api();
	if (_vma_api == NULL) {
		printf("VMA Extra API not found\n");
	}
#endif /* VMA_API */

	max_events = FD_NUM + sizeof(sfd) / sizeof(sfd[0]);

	conns.count = 0;
	conns.fds = calloc(max_events, sizeof(*conns.fds));
	assert(conns.fds);

#if defined(VMA_API) && (VMA_API == 1)
	vma_comps = calloc(max_events, sizeof(*vma_comps));
	assert(vma_comps);
#else
	efd = epoll_create1(0);
	assert(efd >= 0);

	events = calloc(max_events, sizeof(*events));
	assert(events);
#endif /* VMA_API */

	printf("Launching <receiver> mode...\n");

	/* Step:2 Create listen socket */
	for (i = 0; (i < SFD_NUM) && (argc > (i + 1)); i++) {
		char *optarg = argv[i + 1];
		char *token1 = NULL;
		char *token2 = NULL;
		const char s[2] = ":";

		token1 = strtok(optarg, s);
		token2 = strtok(NULL, s);

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = PF_INET;
		addr.sin_addr.s_addr = inet_addr(token1);
		addr.sin_port = htons(atoi(token2));
		sfd[i] = _tcp_create_and_bind(&addr);
		if (sfd[i] < 0) {
			perror("Failed to create socket");
			exit(EXIT_FAILURE);
		}
		max_sfd++;
	}

	/* Step:3 Need to get ring or set listen socket */
#if defined(VMA_API) && (VMA_API == 1)
	if (_vma_ring_fd < 0) {
		_vma_api->get_socket_rings_fds(sfd[0], &_vma_ring_fd, 1);
		assert((-1) != _vma_ring_fd);
	}
#else
	for (i = 0; i < max_sfd; i++) {
		ev.events = EPOLLIN;
		ev.data.fd = sfd[i];
		if (epoll_ctl(efd, EPOLL_CTL_ADD, sfd[i], &ev) == -1) {
				perror("epoll_ctl() failed");
			exit(EXIT_FAILURE);
		}
	}
#endif /* VMA_API */

	while (!_done) {
		int n = 0;

		/* Step:4 Get events */
#if defined(VMA_API) && (VMA_API == 1)
		while (0 == n) {
			n = _vma_api->socketxtreme_poll(_vma_ring_fd, vma_comps, max_events, 0);
		}
#else
		n = epoll_wait(efd, events, max_events, 0);
#endif /* VMA_API */
		for (j = 0; j < n; j++) {

#if defined(VMA_API) && (VMA_API == 1)
			event = vma_comps[j].events;
			event |= ( event & VMA_SOCKETXTREME_PACKET ? EPOLLIN : 0);
			fd = (event & VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED ? vma_comps[j].listen_fd : vma_comps[j].user_data);
#else
			event = events[j].events;
			fd = events[j].data.fd;
#endif /* VMA_API */

			if ((event & EPOLLERR) || (event & EPOLLHUP) || (event & EPOLLRDHUP)) {
				printf("epoll error\n");
				exit(EXIT_FAILURE);
			}

			/* Step:5 Accept connections */
			for (i = 0; i < max_sfd; i++) {
				if (fd == sfd[i]) break;
			}
			if (i < max_sfd) {
				in_len = sizeof(in_addr);
#if defined(VMA_API) && (VMA_API == 1)
				fd = vma_comps[j].user_data;
				memcpy(&in_addr, &vma_comps[j].src, in_len);
#else
				fd = accept(fd, &in_addr, &in_len);
				if (fd < 0) {
					printf("Accept failed: %s", strerror(errno));
			        	exit(EXIT_FAILURE);
				}
				ev.events = EPOLLIN | EPOLLET;
				ev.data.fd = fd;
				if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					printf("epoll_ctl() failed: %s", strerror(errno));
					exit(EXIT_FAILURE);
			    	}
#endif /* VMA_API */

				conns.fds[conns.count] = fd;
				conns.count++;

				printf("Accepted: #%d by sfd=%d fd=%d from %s\n", conns.count, sfd[i], fd, _addr2str((struct sockaddr_in *)&in_addr));

				flag = 1;
				ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
				if (ret < 0) {
					printf("Failed to disable NAGLE: %s\n", strerror(errno));
			        	exit(EXIT_FAILURE);
				}

				ret = _set_noblock(fd);
				continue;
			}

			/* Step:6 Process data */
			if (event & EPOLLIN) {
#if defined(VMA_API) && (VMA_API == 1)
			  printf("vma_comps[j].packet.num_bufs equal to %d \n", vma_comps[j].packet.num_bufs);
				assert(1 == vma_comps[j].packet.num_bufs);
				assert(sizeof(conns.msg) > vma_comps[j].packet.total_len);
				memcpy(conns.msg, vma_comps[j].packet.buff_lst->payload, vma_comps[j].packet.total_len);
				ret = vma_comps[j].packet.total_len;
				_vma_api->socketxtreme_free_vma_packets(&vma_comps[j].packet, 1);
#else
				ret = recv(fd, conns.msg, sizeof(conns.msg), 0);
#endif /* VMA_API */
				if (ret < 0) {
			        	exit(EXIT_FAILURE);
				}
				if (ret > 0) {
					conns.msg[ret - 1] = '\0';
				} else {
					conns.msg[0] = '\0';
				}
				printf("Received: fd=%d ret=%d %s\n", fd, ret, conns.msg);
			}
		}
	}

err:

	for (i = 0; i < max_sfd; i++) {
		if (sfd[i] > 0) {
			close(sfd[i]);
		}
	}

	for (i = 0; i < conns.count; i++) {
		if (conns.fds[i] > 0) {
#if defined(VMA_API) && (VMA_API == 1)
#else
			epoll_ctl(efd, EPOLL_CTL_DEL, conns.fds[i], NULL);
#endif /* VMA_API */
			close(conns.fds[i]);
		}
	}
	if (conns.fds) {
		free(conns.fds);
	}

#if defined(VMA_API) && (VMA_API == 1)
	if (vma_comps) {
		free(vma_comps);
	}
#else
	if (events) {
		free(events);
	}
#endif /* VMA_API */

	close(efd);

	exit(0);
}
