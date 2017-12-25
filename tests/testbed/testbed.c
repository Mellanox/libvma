/*
 * testbed.c
 *
 * This application includes sender, engine, receiver units.
 * Where sender and receiver are located on the same node.
 *
 * gcc testbed.c -o testbed.out -g -Wall -Werror -DTIMESTAMP_ENABLED=1 -DTIMESTAMP_RDTSC=1 -DNDEBUG -lrt
 *
 * Additional compilation options:
 *
 * -DTIMESTAMP_ENABLED=1
 * -DTIMESTAMP_ENABLED=0 (default)
 *
 * -DTIMESTAMP_RDTSC=1 - rdtsc based time  (default)
 * -DTIMESTAMP_RDTSC=0 - clock_gettime()
 *
 * -DVMA_ZCOPY_ENABLED=1
 * -DVMA_ZCOPY_ENABLED=0 (default)
 *
 * -DNDEBUG – ON/OFF assert and log_trace()
 *
 * How to use (launch using this order):
 * sender and receiver are launched on 10.0.0.9
 * engine is launched on 10.0.0.10
 *
 * ./testbed.out --receiver=:10.0.0.9 --scount=20 --rcount=10 --msg-size=500 --msg-rate=2000 -d4 -n8000
 * ./testbed.out --engine=10.0.0.9:10.0.0.10  --scount=20 --rcount=10 --msg-size=500 --msg-rate=2000 -d4 -n8000
 * ./testbed.out --sender=10.0.0.10:10.0.0.9 --scount=20 --rcount=10 --msg-size=500 --msg-rate=2000 -d4 -n8000
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
#if  defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#include <mellanox/vma_extra.h>
#endif /* VMA_ZCOPY_ENABLED */

#ifndef __LINUX__
#define __LINUX__
#endif
#ifndef TIMESTAMP_RDTSC
#define TIMESTAMP_RDTSC 1
#endif
#ifndef TIMESTAMP_ENABLED
#define TIMESTAMP_ENABLED 0
#endif
#ifndef BLOCKING_READ_ENABLED
#define BLOCKING_READ_ENABLED 0
#endif
#ifndef BLOCKING_WRITE_ENABLED
#define BLOCKING_WRITE_ENABLED 0
#endif
#ifndef VMA_ZCOPY_ENABLED
#define VMA_ZCOPY_ENABLED 0
#endif
#ifndef PONG_ENABLED
#define PONG_ENABLED 0
#endif
#ifndef UDP_ENABLED
#define UDP_ENABLED 0
#endif


struct testbed_config {
	enum {
		MODE_ENGINE = 0,
		MODE_SENDER,
		MODE_RECEIVER
	} mode;
	struct sockaddr_in addr;
	struct sockaddr_in bind_addr;
	uint16_t port;
	int scount;
	int rcount;
	uint32_t msg_size;
	int msg_count;
	int msg_rate;
	int msg_skip;
	int log_level;
};

#define MSG_MAGIC 0xAA
#define MSG_BAD 0xFF
#define MSG_IN  1
#define MSG_OUT 2
#define NANOS_IN_SEC  1000000000L
#define NANOS_IN_MSEC 1000000L
#define NANOS_IN_USEC 1000L

#define MAX_FD 1024

#pragma pack(push, 1)
struct msg_header {
	uint8_t magic_num;
	uint8_t msg_type;
	uint16_t len;
	int32_t seq_num;
	int16_t client_id;
	int16_t receiver;
#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
	int64_t time_start;
	int64_t time_end;
#endif /* TIMESTAMP_ENABLED */
};
#pragma pack( pop )

struct testbed_stat {
#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
	struct msg_header *data;
	int size;
	int count;
#endif /* TIMESTAMP_ENABLED */
	int tx_count;
	int rx_count;
};

#define log_fatal(fmt, ...) \
	do {                                                       \
		if (_config.log_level > 0)                             \
			fprintf(stderr, "[FATAL ] " fmt, ##__VA_ARGS__);    \
			exit(1);    \
	} while (0)

#define log_error(fmt, ...) \
	do {                                                       \
		if (_config.log_level > 1)                             \
			fprintf(stderr, "[ERROR ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_warn(fmt, ...) \
	do {                                                       \
		if (_config.log_level > 2)                             \
			fprintf(stderr, "[WARN  ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#define log_info(fmt, ...) \
	do {                                                       \
		if (_config.log_level > 3)                             \
			fprintf(stderr, "[INFO  ] " fmt, ##__VA_ARGS__);    \
	} while (0)

#if defined(NDEBUG)
#define log_trace(fmt, ...)     ((void)0)
#else
#define log_trace(fmt, ...) \
	do {                                                       \
		if (_config.log_level > 4)                             \
			fprintf(stderr, "[TRACE ] " fmt, ##__VA_ARGS__);    \
	} while (0)
#endif /* NDEBUG */

#define _min(a, b) ((a) > (b) ? (b) : (a))
#define _max(a, b) ((a) < (b) ? (b) : (a))

static int _set_config(int argc, char **argv);
static int _def_config(void);
static void _usage(void);
static int _proc_sender(void);
static int _proc_engine(void);
static int _proc_receiver(void);
static void _proc_signal(int signal_id);

static inline int64_t _get_time_ns(void);
static inline char *_addr2str(struct sockaddr_in *addr);
static int _get_addr(char *dst, struct sockaddr_in *addr);
static int _set_noblock(int fd);

static int _write(int fd, uint8_t *buf, int count, int block);
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
static int _read(int fd, uint8_t *buf, int count, int block);
#endif /* VMA_ZCOPY_ENABLED */

#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
static int _udp_client_init(struct sockaddr_in *addr);
static int _udp_server_init(int fd);
static int _udp_create_and_bind(struct sockaddr_in *addr);
#else
static int _tcp_client_init(struct sockaddr_in *addr);
static int _tcp_server_init(int fd);
static int _tcp_create_and_bind(struct sockaddr_in *addr);
#endif /* UDP_ENABLED */

static void _ini_stat(void);
static void _fin_stat(void);

static struct testbed_config _config;
static struct testbed_stat _stat;
static volatile int _done;
#if defined(BLOCKING_READ_ENABLED) && (BLOCKING_READ_ENABLED == 1)
static int _rb = 1;
#else
static int _rb = 0;
#endif /* BLOCKING_READ_ENABLED */
#if defined(BLOCKING_WRITE_ENABLED) && (BLOCKING_WRITE_ENABLED == 1)
static int _wb = 1;
#else
static int _wb = 0;
#endif /* BLOCKING_WRITE_ENABLED */

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
static struct vma_api_t *_vma_api = NULL;
static int _vma_ring_fd = -1;
#endif /* VMA_ZCOPY_ENABLED */

#if defined(PONG_ENABLED) && (PONG_ENABLED == 1)
#if defined(UDP_ENABLED) && (UDP_ENABLED == 0)
static int _udp_create_and_bind(struct sockaddr_in *addr);
#endif
#define PONG_PORT		41794
#endif /* PONG_ENABLED */

int main(int argc, char **argv)
{
	int rc = 0;
	struct sigaction sa;

	if (argc < 2) {
		rc = -EINVAL;
		_usage();
		goto err;
	}

	srand(time(0));

	_rb = _rb;
	_wb = _wb;
	rc = _def_config();
	if (0 != rc) {
		goto err;
	}

	rc = _set_config(argc, argv);
	if (0 != rc) {
		goto err;
	}

	/* catch SIGINT to exit */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = _proc_signal;
	sa.sa_flags = 0;
	sigemptyset(&(sa.sa_mask));
	if (sigaction(SIGINT, &sa, NULL) != 0) {
		goto err;
	}

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	_vma_api = vma_get_api();
	if (_vma_api == NULL) {
		log_fatal("VMA Extra API not found\n");
	}
#endif /* VMA_ZCOPY_ENABLED */

	_done = 0;
	_ini_stat();
	switch ((int)_config.mode) {
		case MODE_ENGINE:
			rc = _proc_engine();
			break;
		case MODE_SENDER:
			rc = _proc_sender();
			break;
		case MODE_RECEIVER:
			rc = _proc_receiver();
			break;
		default:
			break;
	}
	_fin_stat();
err:
	return rc;
}

static void _usage(void)
{
	fprintf(stderr, "Usage: testbed [options]\n"
		"\t--engine <ip>           Engine mode (receiver ip)\n"
		"\t--sender <ip>           Sender mode (engine ip)\n"
		"\t--receiver              Receiver mode\n"
		"\t--port <num>	           Listen/connect to port <num> (default %d).\n"
		"\t--scount,-s <count>     Total number of senders (default %d).\n"
		"\t--rcount,-r <count>     Total number of receivers (default %d).\n"
		"\t--msg-size,-l <bytes>   Message size in bytes (default %d).\n"
		"\t--msg-count,-n <count>  Total number of messages to send (default %d).\n"
		"\t--msg-rate,-f <count>   Number of messages per second (default %d).\n"
		"\t--msg-skip,-i <count>   Skip number of messages in statistic (default %d).\n"
		"\t--debug,-d <level>      Output verbose level (default: %d).\n"
		"\t--help,-h               Print help and exit\n",

	    _config.port,
	    _config.scount,
		_config.rcount,
        _config.msg_size,
        _config.msg_count,
        _config.msg_rate,
        _config.msg_skip,
    	_config.log_level);
}

static void _proc_signal(int signal_id)
{
   _done = signal_id;
}

static int _def_config(void)
{
	int rc = 0;

	memset(&_config, 0, sizeof(_config));
	_config.mode = -1;
	_config.port = 12345;
	_config.bind_addr.sin_family = PF_INET;
	_config.bind_addr.sin_addr.s_addr = INADDR_ANY;
	_config.msg_size = 500;
	_config.scount = 20;
	_config.rcount = 10;
	_config.msg_count = 8000;
	_config.msg_rate = 2000;
	_config.msg_skip = 500;
	_config.log_level = 4;

	return rc;
}

static int _set_config(int argc, char **argv)
{
	int rc = 0;
	static struct option long_options[] = {
		{"engine",       required_argument, 0, MODE_ENGINE},
		{"sender",       required_argument, 0, MODE_SENDER},
		{"receiver",     optional_argument, 0, MODE_RECEIVER},
		{"port",         required_argument, 0, 'p'},
		{"scount",       required_argument, 0, 's'},
		{"rcount",       required_argument, 0, 'r'},
		{"msg-size",     required_argument, 0, 'l'},
		{"msg-count",    required_argument, 0, 'n'},
		{"msg-rate",     required_argument, 0, 'f'},
		{"msg-skip",     required_argument, 0, 'i'},
		{"debug",        required_argument, 0, 'd'},
		{"help",         no_argument,       0, 'h'},
	};
	int op;
	int option_index;

	while ((op = getopt_long(argc, argv, "p:s:r:l:n:f:i:d:h", long_options, &option_index)) != -1) {
		switch (op) {
			case MODE_ENGINE:
			case MODE_SENDER:
			case MODE_RECEIVER:
				if ((int)_config.mode < 0) {
					char *token1 = NULL;
					char *token2 = NULL;
					const char s[2] = ":";
					if (optarg) {
						if (optarg[0] != ':') {
							token1 = strtok(optarg, s);
							token2 = strtok(NULL, s);
						} else {
							token1 = NULL;
							token2 = strtok(optarg, s);
						}
					}

					if (token1) {
						rc = _get_addr(token1, &_config.addr);
						if (rc < 0) {
							rc = -EINVAL;
							log_fatal("Failed to resolve ip address %s\n", token1);
						}
					}
					if (token2) {
						if (0 == inet_aton(token2, &_config.bind_addr.sin_addr)) {
							log_fatal("Failed to resolve ip address %s\n", token2);
						}
					}
					_config.mode = op;
				} else {
					rc = -EINVAL;
					log_error("Wrong option usage \'%c\'\n", op);
				}
				break;
			case 'p':
				errno = 0;
				_config.port = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 's':
				errno = 0;
				_config.scount = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'r':
				errno = 0;
				_config.rcount = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'l':
				errno = 0;
				_config.msg_size = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				if (_config.msg_size < sizeof(struct msg_header)) {
					rc = -EINVAL;
					log_error("Message size can not be less than <%d>\n", (int)sizeof(struct msg_header));
				}
				break;
			case 'n':
				errno = 0;
				_config.msg_count = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'f':
				errno = 0;
				_config.msg_rate = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'i':
				errno = 0;
				_config.msg_skip = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'd':
				errno = 0;
				_config.log_level = strtol(optarg, NULL, 0);
				assert(errno == 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'h':
			default:
				log_error("Unknown option <%c>\n", op);
				_usage();
				break;
		}
	}

	if (0 != rc) {
		_usage();
	} else {
		_config.addr.sin_port = htons(_config.port);
		_config.bind_addr.sin_port = htons(_config.port);
		log_info("CONFIGURATION:\n");
		log_info("mode: %d\n", _config.mode);
		log_info("senders: %d\n", _config.scount);
		log_info("receivers: %d\n", _config.rcount);
		log_info("log level: %d\n", _config.log_level);
		log_info("msg size: %d\n", _config.msg_size);
		log_info("msg count: %d\n", _config.msg_count);
		log_info("msg rate: %d\n", _config.msg_rate);
		log_info("msg skip: %d\n", _config.msg_skip);
		log_info("connect to ip: %s\n", _addr2str(&_config.addr));
		log_info("listen on ip: %s\n", _addr2str(&_config.bind_addr));
	}

	return rc;
}

static int _proc_sender(void)
{
	int rc = 0;
	int efd;
	struct epoll_event *events = NULL;
	int max_events;
	struct conn_info {
		int id;
		int fd;
		int msg_len;
		struct per_sender_connection {
			int msgs_sent;
			int64_t begin_send_time;
		} stat;
		uint8_t msg[1];
	} *conns_out = NULL;
	struct per_sender_connection *stat;
	struct msg_header *msg_hdr;
	int i;
	int total_msg_count;
	int conns_size = sizeof(struct conn_info) + _config.msg_size + 1;
#if defined(PONG_ENABLED) && (PONG_ENABLED == 1)
	struct sockaddr_in addr;
	memcpy(&addr, &_config.bind_addr, sizeof(addr));
	addr.sin_port = htons(PONG_PORT);
	int fd_pong = _udp_create_and_bind(&addr);
	assert(fd_pong >= 0);
#endif /* PONG_ENABLED */

	log_trace("Launching <sender> mode...\n");

	efd = epoll_create1(0);
	assert(efd >= 0);

	conns_out = calloc(_config.scount, conns_size);
	assert(conns_out);
	for (i = 0; i < _config.scount; i++) {
		struct epoll_event event;
		struct conn_info *conn;

		conn = (struct conn_info *)((uint8_t *)conns_out + i * conns_size);
		conn->stat.msgs_sent = 0;
		conn->stat.begin_send_time = 0;

		msg_hdr = (struct msg_header *)conn->msg;
		msg_hdr->magic_num = MSG_MAGIC;
		msg_hdr->msg_type = MSG_IN;
		msg_hdr->len = _config.msg_size;
		msg_hdr->seq_num = 0;
		msg_hdr->client_id = i;
		msg_hdr->receiver = 0;

		conn->id = i;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		conn->fd = _udp_client_init(&_config.addr);
#else
		conn->fd = _tcp_client_init(&_config.addr);
#endif /* UDP_ENABLED */
		conn->msg_len = 0;
		if (_done) {
			goto err;
		}
		assert(conn->fd >= 0);

		event.data.ptr = conn;
		event.events = EPOLLOUT;
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, conn->fd, &event);
		assert(rc == 0);
	}

	log_trace("<sender> established %d connections with <engine>\n", _config.scount);

	max_events = _config.scount * 10;
	events = calloc(max_events, sizeof(*events));
	assert(events);

	total_msg_count = _config.scount * _config.msg_count;
	while (!_done) {
		int n;
		int j;

		n = epoll_wait(efd, events, max_events, 0);
		for (j = 0; j < n; j++) {
			struct conn_info *conn = NULL;
			uint32_t event;

			event = events[j].events;
			conn = (struct conn_info *)events[j].data.ptr;
			assert(conn);

			if ((event & EPOLLERR) ||
				(event & EPOLLHUP) ||
				(!(event & EPOLLOUT))) {
				log_error("epoll error\n");
				goto err;
			}

			/* Check message count threshold */
			if (_config.msg_count > 0 &&
					conn->stat.msgs_sent >= _config.msg_count) {
				continue;
			}

#if defined(PONG_ENABLED) && (PONG_ENABLED == 1)
			recv(fd_pong, "pong", sizeof("pong"), 0);
#else
			usleep(0);
#endif /* PONG_ENABLED */

			if (event & EPOLLOUT) {
				int fd;
				int64_t time_now = _get_time_ns();

				fd = conn->fd;
				stat = &conn->stat;
				msg_hdr = (struct msg_header *)conn->msg;

				if (stat->begin_send_time > 0) {
					int expected_msg_count = 0;
					int ret;

					/* check if this connection hasn’t reached begin time yet */
					if (stat->begin_send_time > time_now) {
						continue;
					}

					/* check if it is new message */
					if (0 == conn->msg_len) {
						/* calculate the expected number of sent message */
						expected_msg_count = _config.msg_rate * (time_now - stat->begin_send_time) / NANOS_IN_SEC;
						if (stat->msgs_sent >= expected_msg_count) {
							continue;
						}

						/* Each time while sending messages to engine, sender connection
						 * randomly picks up a integer X in range of 0 to N-1 (inclusive),
						 * and put into receiver filed so that engine program will forward
						 * the message to its Xth connection with receiver.
						 */
						msg_hdr->receiver = rand() % _config.rcount;
#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
						msg_hdr->time_start = time_now;
#endif /* TIMESTAMP_ENABLED */
					}

					ret = _write(fd,
							((uint8_t *)msg_hdr) + conn->msg_len,
							_config.msg_size - conn->msg_len, _wb);
					if (ret < 0) {
						goto err;
					}
					conn->msg_len += ret;
					if (conn->msg_len != _config.msg_size) {
						continue;
					} else {
						conn->msg_len = 0;
					}
					log_trace("<sender> [%d]->[%d] Send %d bytes fd=%d ret=%d\n",
							msg_hdr->client_id, msg_hdr->receiver, msg_hdr->len, fd, ret);

					/* send message */
					msg_hdr->seq_num++;
					stat->msgs_sent++;
					_stat.tx_count++;

					/* check exit condition */
					if (total_msg_count > 0) {
						total_msg_count--;
						if (total_msg_count == 0) {
							_done++;
							sleep(3);
						}
					};
				} else {
					int64_t interval = NANOS_IN_SEC / _config.msg_rate;

					/* pick a random time for each connection so they don’t
					 * start at the same time
					 */
					stat->begin_send_time = time_now + rand() % interval;
				}
			}
		}
	}

err:

	if (conns_out) {
		for (i = 0; i < _config.scount; i++) {
			struct conn_info *conn;

			conn = (struct conn_info *)((uint8_t *)conns_out + i * conns_size);
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
			_write(conn->fd, (uint8_t *)"?", sizeof("?"), 0);
#endif /* UDP_ENABLED */
			epoll_ctl(efd, EPOLL_CTL_DEL, conn->fd, NULL);
			close(conn->fd);
			conn->fd = -1;
		}
		free(conns_out);
	}

	if (events) {
		free(events);
	}

	close(efd);

	return rc;
}

static int _proc_engine(void)
{
	int rc = 0;
	int efd;
	struct epoll_event *events = NULL;
	int max_events;
	struct conn_info {
		int id;
		int fd;
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		struct vma_packet_desc_t vma_packet;
		struct vma_buff_t *vma_buf;
		int vma_buf_offset;
#endif /* VMA_ZCOPY_ENABLED */
		int msg_len;
		uint8_t msg[1];
	} *conns_out, **conns_in;
	struct conn_info *conn = NULL;
	struct msg_header *msg_hdr;
	int i;
	int sfd = -1;
	int conns_size = sizeof(struct conn_info) + _config.msg_size + 1;

	log_trace("Launching <engine> mode...\n");

	conns_out = NULL;
	conns_in = NULL;
	efd = epoll_create1(0);
	assert(efd >= 0);

#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
	sfd = _udp_create_and_bind(&_config.bind_addr);
#else
	sfd = _tcp_create_and_bind(&_config.bind_addr);
#endif /* UDP_ENABLED */
	if (sfd < 0) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	conns_in = calloc(MAX_FD, sizeof(*conns_in));
	assert(conns_in);
	for (i = 0; i < _config.scount; i++) {
		struct epoll_event event;
		int fd;

#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		fd = _udp_server_init(sfd);
#else
		fd = _tcp_server_init(sfd);
#endif /* UDP_ENABLED */
		if (fd >= MAX_FD) {
			log_error("fd(%d) >= MAX_FD(%d)\n", fd, MAX_FD);
			goto err;
		}
		conn = (struct conn_info *)calloc(1, conns_size);
		assert(conn);

		msg_hdr = (struct msg_header *)conn->msg;
		msg_hdr->msg_type = MSG_BAD;

		conn->id = i;
		conn->fd = fd;
		conn->msg_len = 0;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		conns_in[i] = conn;
#else
		conns_in[fd] = conn;
#endif /* UDP_ENABLED */

		if (_done) {
			goto err;
		}
		assert(conn->fd >= 0);

		event.data.ptr = conn;
		event.events = EPOLLIN;
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		event = event;
#else
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, conn->fd, &event);
		assert(rc == 0);
#endif /* VMA_ZCOPY_ENABLED */
	}

	log_trace("<engine> established %d connections with <sender>\n", _config.scount);

	conns_out = calloc(_config.rcount, conns_size);
	assert(conns_out);
	for (i = 0; i < _config.rcount; i++) {
		conn = (struct conn_info *)((uint8_t *)conns_out + i * conns_size);

		msg_hdr = (struct msg_header *)conn->msg;
		msg_hdr->msg_type = MSG_BAD;

		conn->id = i;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		conn->fd = _udp_client_init(&_config.addr);
#else
		conn->fd = _tcp_client_init(&_config.addr);
#endif /* UDP_ENABLED */
		conn->msg_len = 0;
		if (_done) {
			goto err;
		}
		assert(conn->fd >= 0);
	}

	log_trace("<engine> established %d connections with <receiver>\n", _config.rcount);

	max_events = (_config.scount + _config.rcount) * 10;
	events = calloc(max_events, sizeof(*events));
	assert(events);

	conn = NULL;
	while (!_done) {
		uint32_t event = 0;
		int n = 0;
		int j = 0;

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		if (conn) {
			if (conn->vma_buf && (conn->vma_buf_offset < conn->vma_buf->len)) {
				n = 1;
			} else if (conn->vma_buf && conn->vma_buf->next) {
				conn->vma_buf = conn->vma_buf->next;
				conn->vma_buf_offset = 0;
				n = 1;
			} else if (conn->vma_buf && !conn->vma_buf->next) {
				_vma_api->socketxtreme_free_vma_packets(&conn->vma_packet, 1);
				conn->vma_buf = NULL;
				conn->vma_buf_offset = 0;
				conn = NULL;
				n = 0;
			}
		}
		while (0 == n) {
			struct vma_completion_t vma_comps;
			n = _vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if (n > 0) {
				event = (uint32_t)vma_comps.events;
				if (vma_comps.events & VMA_SOCKETXTREME_PACKET) {
					event |= EPOLLIN;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
					if (vma_comps.packet.buff_lst->len >= sizeof(struct msg_header)) {
						msg_hdr = (struct msg_header *)vma_comps.packet.buff_lst->payload;
						vma_comps.user_data = msg_hdr->client_id;
					} else {
						event |= EPOLLERR;
						log_error("event=0x%x user_data size=%d\n", event, vma_comps.packet.buff_lst->len);
						log_error("EOF?\n");
						goto err;
					}
#endif /* UDP_ENABLED */
					conn = conns_in[vma_comps.user_data];
					conn->vma_packet.num_bufs = vma_comps.packet.num_bufs;
					conn->vma_packet.total_len = vma_comps.packet.total_len;
					conn->vma_packet.buff_lst = vma_comps.packet.buff_lst;
					conn->vma_buf = conn->vma_packet.buff_lst;
					conn->vma_buf_offset = 0;
				} else if ((event & EPOLLERR) || (event & EPOLLRDHUP) ||
						(event & EPOLLHUP)) {
					event |= EPOLLERR;
					log_error("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
					log_error("EOF?\n");
					goto err;
				} else {
					log_warn("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
					n = 0;
				}
			}
		}
#else
		n = epoll_wait(efd, events, max_events, 0);
#endif /* VMA_ZCOPY_ENABLED */

		for (j = 0; j < n; j++) {
			int fd = 0;
			int ret = 0;

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
			event = events[j].events;
			conn = (struct conn_info *)events[j].data.ptr;
			assert(conn);
#endif /* VMA_ZCOPY_ENABLED */

			fd = conn->fd;
			fd = fd;
			msg_hdr = (struct msg_header *)conn->msg;

			if ((event & EPOLLERR) ||
				(event & EPOLLHUP)) {
				log_error("epoll error\n");
				goto err;
			}

			if (event & EPOLLIN) {
				struct conn_info *conn_peer = NULL;

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
				ret = _min((_config.msg_size - conn->msg_len), (conn->vma_buf->len - conn->vma_buf_offset));
				memcpy(((uint8_t *)msg_hdr) + conn->msg_len,
						((uint8_t *)conn->vma_buf->payload) + conn->vma_buf_offset,
						ret);
				conn->vma_buf_offset += ret;
#else
				ret = _read(fd,
						((uint8_t *)msg_hdr) + conn->msg_len,
						_config.msg_size - conn->msg_len, _wb);
#endif /* VMA_ZCOPY_ENABLED */
				if (ret < 0) {
					goto err;
				}
				conn->msg_len += ret;
				if (conn->msg_len != _config.msg_size) {
					continue;
				} else {
					conn->msg_len = 0;
				}
				log_trace("<engine> [%d]<- Read %d bytes fd=%d ret=%d\n",
						msg_hdr->client_id, msg_hdr->len, fd, ret);
				assert(msg_hdr->msg_type == MSG_IN);
				_stat.rx_count++;

				msg_hdr->msg_type = MSG_OUT;
				conn_peer = (struct conn_info *)((uint8_t *)conns_out + msg_hdr->receiver * conns_size);
				/* use blocking operation */
				ret = _write(conn_peer->fd, (uint8_t *)msg_hdr, msg_hdr->len, 1);
				log_trace("<engine> [%d]-> Send %d bytes fd=%d ret=%d\n",
						msg_hdr->receiver, msg_hdr->len, conn_peer->fd, ret);
				if (ret != msg_hdr->len) {
					goto err;
				}
				_stat.tx_count++;
			}
		}
	}

err:

	close(sfd);

	if (conns_in) {
		for (i = 0; i < MAX_FD; i++) {
			struct conn_info *conn;

			conn = conns_in[i];
			if (conn) {
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
				epoll_ctl(efd, EPOLL_CTL_DEL, conn->fd, NULL);
#endif /* VMA_ZCOPY_ENABLED */
				close(conn->fd);
				conn->fd = -1;
				free(conn);
			}
		}
		free(conns_in);
	}

	if (conns_out) {
		for (i = 0; i < _config.rcount; i++) {
			struct conn_info *conn;

			conn = (struct conn_info *)((uint8_t *)conns_out + i * conns_size);
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
			_write(conn->fd, (uint8_t *)"?", sizeof("?"), 0);
#endif /* UDP_ENABLED */
			epoll_ctl(efd, EPOLL_CTL_DEL, conn->fd, NULL);
			close(conn->fd);
			conn->fd = -1;
		}
		free(conns_out);
	}

	if (events) {
		free(events);
	}

	close(efd);

	return rc;
}

static int _proc_receiver(void)
{
	int rc = 0;
	int efd;
	struct epoll_event *events = NULL;
	int max_events;
	struct conn_info {
		int id;
		int fd;
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		struct vma_packet_desc_t vma_packet;
		struct vma_buff_t *vma_buf;
		int vma_buf_offset;
#endif /* VMA_ZCOPY_ENABLED */
		int msg_len;
		uint8_t msg[1];
	} **conns_in = NULL;
	struct conn_info *conn;
	struct msg_header *msg_hdr;
	int i;
	int sfd = -1;
	int conns_size = sizeof(struct conn_info) + _config.msg_size + 1;

	log_trace("Launching <receiver> mode...\n");

	efd = epoll_create1(0);
	assert(efd >= 0);

#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
	sfd = _udp_create_and_bind(&_config.bind_addr);
#else
	sfd = _tcp_create_and_bind(&_config.bind_addr);
#endif /* UDP_ENABLED */
	if (sfd < 0) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	conns_in = calloc(MAX_FD, sizeof(*conns_in));
	assert(conns_in);
	for (i = 0; i < _config.rcount; i++) {
		struct epoll_event event;
		int fd;

#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		fd = _udp_server_init(sfd);
#else
		fd = _tcp_server_init(sfd);
#endif /* UDP_ENABLED */
		if (fd >= MAX_FD) {
			log_error("fd(%d) >= MAX_FD(%d)\n", fd, MAX_FD);
			goto err;
		}
		conn = (struct conn_info *)calloc(1, conns_size);
		assert(conn);

		conn->id = i;
		conn->fd = fd;
		conn->msg_len = 0;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
		conns_in[i] = conn;
#else
		conns_in[fd] = conn;
#endif /* UDP_ENABLED */

		if (_done) {
			goto err;
		}
		assert(conn->fd >= 0);

		event.data.ptr = conn;
		event.events = EPOLLIN;
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		event = event;
#else
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, conn->fd, &event);
		assert(rc == 0);
#endif /* VMA_ZCOPY_ENABLED */
	}

	log_trace("<receiver> established %d connections with <engine>\n", _config.rcount);

	max_events = _config.rcount * 10;
	events = calloc(max_events, sizeof(*events));
	assert(events);

	conn = NULL;
	while (!_done) {
		uint32_t event = 0;
		int n = 0;
		int j = 0;

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
		if (conn) {
			if (conn->vma_buf && (conn->vma_buf_offset < conn->vma_buf->len)) {
				n = 1;
			} else if (conn->vma_buf && conn->vma_buf->next) {
				conn->vma_buf = conn->vma_buf->next;
				conn->vma_buf_offset = 0;
				n = 1;
			} else if (conn->vma_buf && !conn->vma_buf->next) {
				_vma_api->socketxtreme_free_vma_packets(&conn->vma_packet, 1);
				conn->vma_buf = NULL;
				conn->vma_buf_offset = 0;
				conn = NULL;
				n = 0;
			}
		}
		while (0 == n) {
			struct vma_completion_t vma_comps;
			n = _vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
			if (n > 0) {
				event = (uint32_t)vma_comps.events;
				if (vma_comps.events & VMA_SOCKETXTREME_PACKET) {
					event |= EPOLLIN;
#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
					if (vma_comps.packet.buff_lst->len >= sizeof(struct msg_header)) {
						msg_hdr = (struct msg_header *)vma_comps.packet.buff_lst->payload;
						vma_comps.user_data = msg_hdr->receiver;
					} else {
						event |= EPOLLERR;
						log_error("event=0x%x user_data size=%d\n", event, vma_comps.packet.buff_lst->len);
						log_error("EOF?\n");
						goto err;
					}
#endif /* UDP_ENABLED */
					conn = conns_in[vma_comps.user_data];
					conn->vma_packet.num_bufs = vma_comps.packet.num_bufs;
					conn->vma_packet.total_len = vma_comps.packet.total_len;
					conn->vma_packet.buff_lst = vma_comps.packet.buff_lst;
					conn->vma_buf = conn->vma_packet.buff_lst;
					conn->vma_buf_offset = 0;
				} else if ((event & EPOLLERR) || (event & EPOLLRDHUP) ||
						(event & EPOLLHUP)) {
					event |= EPOLLERR;
					log_error("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
					log_error("EOF?\n");
					goto err;
				} else {
					log_warn("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
					n = 0;
				}
			}
		}
#else
		n = epoll_wait(efd, events, max_events, 0);
#endif /* VMA_ZCOPY_ENABLED */
		for (j = 0; j < n; j++) {
			int fd = 0;
			int ret = 0;

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
			event = events[j].events;
			conn = (struct conn_info *)events[j].data.ptr;
			assert(conn);
#endif /* VMA_ZCOPY_ENABLED */

			fd = conn->fd;
			fd = fd;
			msg_hdr = (struct msg_header *)conn->msg;

			if ((event & EPOLLERR) ||
				(event & EPOLLHUP)) {
				log_error("epoll error\n");
				goto err;
			}

			if (event & EPOLLIN) {
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
				ret = _min((_config.msg_size - conn->msg_len), (conn->vma_buf->len - conn->vma_buf_offset));
				memcpy(((uint8_t *)msg_hdr) + conn->msg_len,
						((uint8_t *)conn->vma_buf->payload) + conn->vma_buf_offset,
						ret);
				conn->vma_buf_offset += ret;
#else
				ret = _read(fd,
						((uint8_t *)msg_hdr) + conn->msg_len,
						_config.msg_size - conn->msg_len, _rb);
#endif /* VMA_ZCOPY_ENABLED */
				if (ret < 0) {
					goto err;
				}
				conn->msg_len += ret;
				if (conn->msg_len != _config.msg_size) {
					continue;
				} else {
					conn->msg_len = 0;
				}
				log_trace("<receiver> [%d]<-[%d] Read %d bytes fd=%d ret=%d\n",
						msg_hdr->receiver, msg_hdr->client_id, msg_hdr->len, fd, ret);
				assert(msg_hdr->msg_type == MSG_OUT);
				_stat.rx_count++;
#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
				msg_hdr->time_end = _get_time_ns();
				memcpy(_stat.data + _stat.count, msg_hdr, sizeof(*msg_hdr));
				_stat.count++;
#endif /* TIMESTAMP_ENABLED */
			}
		}
	}

err:

	close(sfd);

	if (conns_in) {
		for (i = 0; i < MAX_FD; i++) {
			struct conn_info *conn;

			conn = conns_in[i];
			if (conn) {
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
				epoll_ctl(efd, EPOLL_CTL_DEL, conn->fd, NULL);
#endif /* VMA_ZCOPY_ENABLED */
				close(conn->fd);
				conn->fd = -1;
				free(conn);
			}
		}
		free(conns_in);
	}

	if (events) {
		free(events);
	}

	close(efd);

	return rc;
}

#if defined(TIMESTAMP_RDTSC) && (TIMESTAMP_RDTSC == 1)
static inline double __get_cpu_clocks_per_sec(void)
{
	static double clocks_per_sec = 0.0;
	static int initialized = 0;

	if (!initialized) {
	        double mhz = 0.0;
#if defined(__LINUX__)
		FILE* f;
		char buf[256];

		f = fopen("/proc/cpuinfo", "r");
		if (!f) {
			return 0.0;
		}

		while (fgets(buf, sizeof(buf), f)) {
			double m;
			int rc;

#if defined(__ia64__)
			rc = sscanf(buf, "itc MHz : %lf", &m);
#elif defined(__powerpc__)
			rc = sscanf(buf, "clock : %lf", &m);
#else
			rc = sscanf(buf, "cpu MHz : %lf", &m);
#endif
			if (rc != 1) {
				continue;
			}
			if (mhz == 0.0) {
				mhz = m;
				continue;
			}
			if (mhz != m) {
				double mm = (mhz < m ? m : mhz);
				mhz = mm;
			}
		}
		fclose(f);
#endif
	        clocks_per_sec = mhz * 1.0e6;
	        initialized = 1;
	}

	return clocks_per_sec;
}
#endif /* TIMESTAMP_RDTSC */

static inline int64_t _get_time_ns(void)
{
#if defined(TIMESTAMP_RDTSC) && (TIMESTAMP_RDTSC == 1)
	unsigned long long int result=0;

#if defined(__LINUX__)
#if defined(__i386__)
	__asm volatile(".byte 0x0f, 0x31" : "=A" (result) : );

#elif defined(__x86_64__)
	unsigned hi, lo;
	__asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	result = hi;
	result = result<<32;
	result = result|lo;

#elif defined(__powerpc__)
	unsigned long int hi, lo, tmp;
	__asm volatile(
			"0:                 \n\t"
			"mftbu   %0         \n\t"
			"mftb    %1         \n\t"
			"mftbu   %2         \n\t"
			"cmpw    %2,%0      \n\t"
			"bne     0b         \n"
			: "=r"(hi),"=r"(lo),"=r"(tmp)
	);
	result = hi;
	result = result<<32;
	result = result|lo;

#endif
#endif /* __LINUX__ */

	return ((int64_t)((double)result * NANOS_IN_SEC / __get_cpu_clocks_per_sec()));
#else
    static struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (NANOS_IN_SEC * time.tv_sec + time.tv_nsec);
#endif /* TIMESTAMP_RDTSC */
}

static inline char *_addr2str(struct sockaddr_in *addr)
{
	static __thread char addrbuf[100];
	inet_ntop(AF_INET, &addr->sin_addr, addrbuf, sizeof(addrbuf));
	sprintf(addrbuf,"%s:%d", addrbuf, ntohs(addr->sin_port));

	return addrbuf;
}

static int _get_addr(char *dst, struct sockaddr_in *addr)
{
	int rc = 0;
	struct addrinfo *res;

	rc = getaddrinfo(dst, NULL, NULL, &res);
	if (rc) {
		log_error("getaddrinfo failed - invalid hostname or IP address\n");
		return rc;
	}

	if (res->ai_family != PF_INET) {
		rc = -1;
		goto out;
	}

	*addr = *(struct sockaddr_in *)res->ai_addr;
out:
	freeaddrinfo(res);
	return rc;
}

static int _set_noblock(int fd)
{
	int rc = 0;
	int flag;

	flag = fcntl(fd, F_GETFL);
	if (flag < 0) {
		rc = -errno;
		log_error("failed to get socket flags %s\n", strerror(errno));
	}
	flag |= O_NONBLOCK;
	rc = fcntl(fd, F_SETFL, flag);
	if (rc < 0) {
		rc = -errno;
		log_error("failed to set socket flags %s\n", strerror(errno));
	}

	return rc;
}


#if defined(UDP_ENABLED) && (UDP_ENABLED == 1)
static int _udp_client_init(struct sockaddr_in *addr)
{
	int rc = 0;
	int fd = -1;
	struct sockaddr_in bind_addr;

	memcpy(&bind_addr, &_config.bind_addr, sizeof(bind_addr));
	bind_addr.sin_port = 0;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (!fd) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	rc = _set_noblock(fd);
	if (rc < 0) {
		log_error("Configure failed: %s\n", strerror(errno));
		goto err;
	}

	rc = bind(fd, (struct sockaddr *) &bind_addr, sizeof(bind_addr));
	if (rc < 0) {
		rc = -EBUSY;
		log_fatal("Failed to bind socket\n");
		goto err;
	}

	rc = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("Connect failed: %s\n", strerror(errno));
		goto err;
	}

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	/* Need to get ring after listen() or nonblocking connect() */
	if (_vma_ring_fd < 0) {
		_vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		assert((-1) != _vma_ring_fd);
	}
#endif /* VMA_ZCOPY_ENABLED */

	log_trace("Established connection: fd=%d to %s\n", fd, _addr2str(addr));

err:
	return (rc == 0 ? fd : (-1));
}

static int _udp_server_init(int fd)
{

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	/* Need to get ring after listen() or nonblocking connect() */
	if (_vma_ring_fd < 0) {
		_vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		assert((-1) != _vma_ring_fd);
	}
#endif /* VMA_ZCOPY_ENABLED */

	return fd;
}

static int _udp_create_and_bind(struct sockaddr_in *addr)
{
	int rc = 0;
	int fd;
	int flag;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!fd) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	flag = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(int));
	if (rc < 0) {
		log_error("Failed to setsockopt: %s\n", strerror(errno));
		goto err;
	}

	rc = _set_noblock(fd);
	if (rc < 0) {
		log_error("Failed to nonblocking: %s\n", strerror(errno));
		goto err;
	}

	rc = bind(fd, (struct sockaddr *) addr, sizeof(*addr));
	if (rc < 0) {
		rc = -EBUSY;
		log_fatal("Failed to bind socket\n");
		goto err;
	}

err:
	return (rc == 0 ? fd : (-1));
}
#else
static int _tcp_client_init(struct sockaddr_in *addr)
{
	int rc = 0;
	int fd = -1;
	int flag;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (!fd) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	flag = 1;
	rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	if (rc < 0) {
		log_error("Failed to disable NAGLE: %s\n", strerror(errno));
		goto err;
	}

	rc = _set_noblock(fd);
	if (rc < 0) {
		log_error("Configure failed: %s\n", strerror(errno));
		goto err;
	}

	rc = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("Connect failed: %s\n", strerror(errno));
		goto err;
	}

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	/* Need to get ring after listen() or nonblocking connect() */
	if (_vma_ring_fd < 0) {
		_vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		assert((-1) != _vma_ring_fd);
	}
#endif /* VMA_ZCOPY_ENABLED */

	/* do this for non-blocking socket */
	rc = 0;
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	while (0 == rc) {
		uint32_t event;
		struct vma_completion_t vma_comps;
		rc = _vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
		if (rc > 0) {
			event = (uint32_t)vma_comps.events;
			if (vma_comps.events & EPOLLOUT) {
				fd = vma_comps.user_data;
				rc = 0;
				break;
			} else {
				log_warn("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
				rc = 0;
			}
		}
	}
#else
	/* wait for setting connection */
	if (0) {
		fd_set rset, wset;
		FD_ZERO(&rset);
		FD_SET(fd, &rset);
		wset = rset;

		if (select(fd + 1, &rset, &wset, NULL, NULL) == 0) {
			close(fd);
			errno = ETIMEDOUT;
			rc = -ETIMEDOUT;
			log_error("select failed: %s\n", strerror(errno));
			goto err;
		}
	} else {
		int efd;
		struct epoll_event event;
		int n;
		struct epoll_event events[10];

		efd = epoll_create1(0);
		event.events = EPOLLOUT | EPOLLIN;
		event.data.fd = fd;
		rc = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
		n = epoll_wait(efd, events, 10, -1);
		epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
		close(efd);
		if (n <= 0 || events[0].events != EPOLLOUT || events[0].data.fd != fd) {
			log_error("epoll_wait event=0x%x fd=%d\n", events[0].events, events[0].data.fd);
			goto err;
		}
	}
#endif /* VMA_ZCOPY_ENABLED */

	log_trace("Established connection: fd=%d to %s\n", fd, _addr2str(addr));

err:
	return (rc == 0 ? fd : (-1));
}

static int _tcp_server_init(int fd)
{
	int rc = 0;
	struct sockaddr in_addr;
	socklen_t in_len;
	int flag;

	/* Need to get ring after listen() or nonblocking connect() */
#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	if (_vma_ring_fd < 0) {
		_vma_api->get_socket_rings_fds(fd, &_vma_ring_fd, 1);
		assert((-1) != _vma_ring_fd);
	}
#endif /* VMA_ZCOPY_ENABLED */

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
	while (0 == rc) {
		uint32_t event;
		struct vma_completion_t vma_comps;
		rc = _vma_api->socketxtreme_poll(_vma_ring_fd, &vma_comps, 1, 0);
		if (rc > 0) {
			event = (uint32_t)vma_comps.events;
			if (vma_comps.events & VMA_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {
				fd = vma_comps.user_data;
				in_len = sizeof(in_addr);
				memcpy(&in_addr, &vma_comps.src, in_len);
			} else {
				log_warn("event=0x%x user_data=%ld\n", event, vma_comps.user_data);
				rc = 0;
			}
		}
	}
#else
	in_len = sizeof(in_addr);
	fd = accept(fd, &in_addr, &in_len);
	if (fd < 0) {
		log_error("Accept failed: %s\n", strerror(errno));
		goto err;
	}
#endif /* VMA_ZCOPY_ENABLED */

	log_trace("Accepted connection: fd=%d from %s\n", fd, _addr2str((struct sockaddr_in *)&in_addr));

	flag = 1;
	rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	if (rc < 0) {
		log_error("Failed to disable NAGLE: %s\n", strerror(errno));
		goto err;
	}

	rc = _set_noblock(fd);

err:
	return fd;
}

static int _tcp_create_and_bind(struct sockaddr_in *addr)
{
	int rc = 0;
	int fd;
	int flag;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (!fd) {
		rc = -EBUSY;
		log_fatal("Failed to create socket\n");
		goto err;
	}

	flag = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(int));
	if (rc < 0) {
		log_error("Failed to setsockopt: %s\n", strerror(errno));
		goto err;
	}

	rc = bind(fd, (struct sockaddr *) addr, sizeof(*addr));
	if (rc < 0) {
		rc = -EBUSY;
		log_fatal("Failed to bind socket\n");
		goto err;
	}

	listen(fd, SOMAXCONN);

err:
	return (rc == 0 ? fd : (-1));
}
#endif /* UDP_ENABLED */

static int _write(int fd, uint8_t *buf, int count, int block)
{
	int n, nb;

	nb = 0;
	do {
		n = write(fd, buf, count);
		if (n <= 0) {
			if (errno == EAGAIN) {
				log_trace("blocking write fd=%d ret=%d written %d of %d %s\n",
						fd, n, nb, count, strerror(errno));
				if (block) {
					continue;
				}
				return nb;
			}
			log_error("bad write fd=%d ret=%d written %d of %d %s\n",
					fd, n, nb, count, strerror(errno));
			return nb;
		}
		count -= n;
		buf += n;
		nb += n;
	} while (block && (count > 0));

	return nb;
}

#if defined(VMA_ZCOPY_ENABLED) && (VMA_ZCOPY_ENABLED == 1)
#else
static int _read(int fd, uint8_t *buf, int count, int block)
{
	int n;
	int nb;

	nb = 0;
	do {
		n = read(fd, buf, count);
		if (n == 0) {
			log_error("EOF?\n");
			return -1;
		}
		if (n < 0) {
			if (errno == EAGAIN) {
				log_trace("blocking read fd=%d ret=%d read %d of %d %s\n",
						fd, n, nb, count, strerror(errno));
				if (block) {
					continue;
				}
				return nb;
			}
			log_error("bad read fd=%d ret=%d read %d of %d %s\n",
					fd, n, nb, count, strerror(errno));
			return nb;
		}
		count -= n;
		buf += n;
		nb += n;
	} while (block && (count > 0));

	return nb;
}
#endif /* VMA_ZCOPY_ENABLED */

static void _ini_stat(void)
{
	memset(&_stat, 0, sizeof(_stat));

#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
	if (_config.mode == MODE_RECEIVER) {
		_stat.count = 0;
		_stat.size = _config.scount * (_config.msg_count < 0 ? 10000 : _config.msg_count);
		_stat.data = malloc(_stat.size * sizeof(*_stat.data) + _config.msg_size);
		if (!_stat.data) {
			log_fatal("Can not allocate memory for statistic\n");
			exit(1);
		}
		memset(_stat.data, 0, _stat.size * sizeof(*_stat.data) + _config.msg_size);
		mlock(_stat.data, _stat.size * sizeof(*_stat.data) + _config.msg_size);
	}
#endif /* TIMESTAMP_ENABLED */
}

#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
static int _cmpfunc (const void *a, const void *b)
{
   return ( *(int64_t*)a - *(int64_t*)b );
}
#endif /* TIMESTAMP_ENABLED */

static void _fin_stat(void)
{
	log_info("STATISTIC:\n");
	log_info("mode: %d\n", _config.mode);
	log_info("tx: %d\n", _stat.tx_count);
	log_info("rx: %d\n", _stat.rx_count);
#if defined(TIMESTAMP_ENABLED) && (TIMESTAMP_ENABLED == 1)
	if (_config.mode == MODE_RECEIVER) {
		int64_t *values;
		int64_t values_count = 0;
		int64_t values_sum = 0;
		int i, j, k;

		values = calloc(_stat.count, sizeof(*values));
		values_count = 0;
		for (i = 0; i < _config.scount; i++) {
			k = 0;
			for (j = 0; j < _stat.count; j++) {
				if (i == _stat.data[j].client_id) {
					if (k < _config.msg_skip) {
						k++;
						continue;
					}
					/* calculate RTD/2 */
					values[values_count] = (_stat.data[j].time_end - _stat.data[j].time_start) / 2;
					values_sum += values[values_count];
					values_count++;
				}
			}
		}
		assert(values_count <= _stat.count);

		if (values_count > 0) {
			double percentile[] = {0.9999, 0.999, 0.995, 0.99, 0.95, 0.90, 0.75, 0.50, 0.25};
			int num = sizeof(percentile) / sizeof(percentile[0]);
			double observationsInPercentile = (double)values_count / 100;

			qsort(values, values_count, sizeof(*values), _cmpfunc);

			log_info("====> avg-lat=%7.3lf\n", (double)values_sum / (values_count * (double)NANOS_IN_USEC));
			log_info("Total %lu observations; each percentile contains %.2lf observations\n", (long unsigned)values_count, observationsInPercentile);

			log_info("---> <MAX> observation = %8.3lf\n", (double)values[values_count - 1] / (double)NANOS_IN_USEC);
			for (j = 0; j < num; j++) {
				int index = (int)( 0.5 + percentile[j] * values_count ) - 1;
				if (index >= 0) {
					log_info("---> percentile %6.2lf = %8.3lf\n", 100 * percentile[j], (double)values[index] / (double)NANOS_IN_USEC);
				}
			}
			log_info("---> <MIN> observation = %8.3lf\n", (double)values[0] / (double)NANOS_IN_USEC);
		} else {
			log_info("Total %lu observations\n", (long unsigned)values_count);
		}
		free(values);
		if (_stat.data) {
			munlock(_stat.data, _stat.size * sizeof(*_stat.data) + _config.msg_size);
			free(_stat.data);
		}
	}
#endif /* TIMESTAMP_ENABLED */
}
