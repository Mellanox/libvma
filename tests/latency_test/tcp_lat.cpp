/*
 * Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software is made available under either the GPL v2 license or a commercial license.
 * If you wish to obtain a commercial license, please contact Mellanox at support@mellanox.com.
 */


/*
 * How to Build: 'gcc -lrt -o tcp_lat tcp_lat.c'
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

#include <src/vma/util/rdtsc.h>

#define log_dbg(fmt, args...) \
do { \
	if (debug) \
		printf(fmt, ##args); \
} while (0)

#define TCP_LAT_PORT	1212

#undef log_dbg
#define log_dbg(fmt, args...)

enum { 
	OPT_REQS_PER_RESP = 1,
	OPT_USE_PERFECT_BATCH,
	OPT_TIME_RR,
	OPT_DELAY_TIME,
	OPT_NOBLOCK,
	OPT_SELECT_ON_ACCEPT,
	OPT_TCP_PORT
};
	

static struct option long_options[] = {
	{"server", 0, 0, 's'},
	{"client", 1, 0, 'c'},	
	{"test", 1, 0, 't'},	
	{"msglen", 1, 0, 'l'},
	{"msgnum", 1, 0, 'n'},
	{"reqs-per-resp", 1, 0, OPT_REQS_PER_RESP},
	{"use-perfect-batch", 0, 0, OPT_USE_PERFECT_BATCH},
	{"time-rr", 0, 0, OPT_TIME_RR},
	{"use-alert-poll", 0, 0, 'p'},
	{"delay", 1, 0, OPT_DELAY_TIME},
	{"port", 1, 0, OPT_TCP_PORT},
	{"noblock", 0, 0, OPT_NOBLOCK},
	{"select-on-accept", 0, 0, OPT_SELECT_ON_ACCEPT},
	{"debug", 0, 0, 'd'},
	{"help", 0, 0, 'h'},
};

static int debug = 0;
static int tcp_lat_pkt_size = 200;
static int max_n_msgs = 1000000;
//static int max_n_msgs = 1000;
static int reqs_per_resp = 1;
static int use_perfect_batch = 0;
static int time_rr = 0;
static int delay_time = 0;
static int noblock = 0;
static int select_on_accept = 0;
static int tcp_lat_port = TCP_LAT_PORT;
bool g_b_exit = false;
struct sigaction sigact;

//#define N_MSGS	1000000 //10000000
struct timestamp {
	uint32_t secs;
	uint32_t nsecs;
};

enum tcp_lat_msg_types {
	TCP_LAT_MSG_TS = 0xAC
};
struct tcp_lat_msg {
	uint8_t msg_type;
	union {
		struct timestamp ts;
	};
} __attribute__((packed));

enum test_modes {
	TST_BLOCKING_PING_PONG = 1,
	TST_SELECT_PING_PONG,
	TST_CL_THREADED_PING_PONG,
	TST_MAX_TEST
	
};

void sig_handler(int signum)
{
	if (g_b_exit) {
		printf("Test end (interrupted by signal %d)", signum);
		return;
	}

	switch (signum) {
	case SIGINT:
		printf("Test end (interrupted by user)");
		break;
	default:
		printf("Test end (interrupted by signal %d)", signum);
		break;
	}
	g_b_exit = true;
}

/* set the action taken when signal received */
void set_signal_action()
{
	sigact.sa_handler = sig_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;

	sigaction(SIGINT, &sigact, NULL);
}

static void usage()
{
	printf("Usage: tcp_lat [options]\n"
	"\t--test,-t <num>     Test to run. Default is 1\n"
	"\t--server,-s         Server mode\n"
	"\t--client,-c <ip>    Client mode. Connect to server at <ip>\n"
	"\t--msglen,-l <bytes> Message size in bytes. Default %d\n"
	"\t--msgnum,-n <count> Total number of messages to send. Default %d\n"
	"\t--reqs-per-resp <n> Send a responce on every nth request. Default %d\n"    
	"\t--use-perfect-batch Send one transaction as a one HUGE message (TCP only)\n"
	"\t--time-rr           Time every req/responce cycle with gettimeofday()\n"
  	"\t--delay <sec>       Sleep <sec> between transactions\n"
	"\t--noblock	       Use non blocking sockets\n"
	"\t--select-on-accept  Use select to check if socket is ready to accept()\n"
	"\t--port <num>	       Listen/connect to port <num>. Default %d\n"
	"\t--debug,-d          Print extra debug info\n"
        "\t--help,-h           Print help and exit\n",

        tcp_lat_pkt_size,
        max_n_msgs,
        reqs_per_resp,
	tcp_lat_port
  
	);
	printf("Test types:\n"
		"	1 - blocking ping pong\n"
		"	2 - select() with non blocking ping pong\n"
		"\n"
	);

	exit(1);
}

static void set_noblock(int ns)
{
	int ret;
	int flag;
	// set it to non blocking mode
	if (noblock) {
		flag = fcntl(ns, F_GETFL);
		if (flag < 0) {
			printf("failed to get socket flags %m\n");
		}
		flag |=  O_NONBLOCK;
		ret = fcntl(ns, F_SETFL, flag);
		if (ret < 0) {
			printf("failed to set socket flags %m\n");
		}
		printf("set socket to nb mode\n");
	}
}

static int do_select_on_accept(int s)
{
	fd_set rfds;
	int ret;

	while(!g_b_exit) {
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		ret = select(s+1, &rfds, 0, 0, 0);
		if (ret < 0 && errno == EINTR) {
			printf("select interrupted\n");
			continue;
		}
		if (ret < 0)
			return -1;
		if (FD_ISSET(s, &rfds))
			return s;
	}
	return -1;
}

static int get_addr(char *dst, struct sockaddr_in *addr)
{
        struct addrinfo *res;
        int ret;

        ret = getaddrinfo(dst, NULL, NULL, &res);
        if (ret) {
                printf
                    ("getaddrinfo failed - invalid hostname or IP address\n");
                return ret;
        }

        if (res->ai_family != PF_INET) {
                ret = -1;
                goto out;
        }

        *addr = *(struct sockaddr_in *)res->ai_addr;
      out:
        freeaddrinfo(res);
        return ret;
}

static int tcp_read(int s, char *b, int count)
{
	int n;
	int nb;

	nb = 0;
	do {
		n = read(s, b, count);
		if (n == 0) {
			printf("EOF?\n");
			return nb;
		}
		if (n < 0) {
			if (errno == EAGAIN) {
				log_dbg("blocking read ret=%d read %d of %d = %m\n", n, nb, count);
				continue;
			}
			printf("bad read ret=%d read %d of %d = %m(%d)\n", n, nb, count, errno);
			return nb;
		}
		count -= n;
		b += n;
		nb += n;
	} while (count > 0);
	return nb;
}

static int tcp_write(int s, char *b, int count)
{
	int n, nb;

	nb = 0;
	do {
		n = write(s, b, count);
		if (n <= 0) {
			if (errno == EAGAIN) {
				log_dbg("blocking write ret=%d written %d of %d = %m\n", n, nb, count);
				continue;
			}
			printf("bad write ret=%d written %d of %d = %m(%d)\n", n, nb, count, errno);
			return nb;
		}
		count -= n;
		b += n;
		nb += n;
	} while (count > 0);
	return nb;
}

void run_select_server()
{
	int s, ns;
	struct sockaddr_in addr;
	int ret;
	unsigned len;
	char buf[tcp_lat_pkt_size];
	//char batch_buf[tcp_lat_pkt_size*reqs_per_resp];
	int flag;
	fd_set rfds, wfds;

	signal(SIGPIPE, SIG_IGN);
	printf("starting TCP select() server\n");
	s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (s < 0) {
		printf("Failed to create socket\n");
		exit(1);
	}

	/* listen on any port */
        memset(&addr, sizeof(addr), 0);
        addr.sin_family = PF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(tcp_lat_port);
	flag = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(int));

	ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		printf("failed to bind = %m\n");
		exit(1);
	}
	listen(s, 5);
	while(!g_b_exit) {
		//int flag;
		printf("Waiting for connection\n");
		len = sizeof(addr);
		ns = accept(s, (struct sockaddr *)&addr, &len);
		if (ns < 0) {
			printf("accept failed = %m\n");
			exit(1);
		}
#if 1
		flag = 1;
		ret = setsockopt(ns, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
		if (ret < 0) {
			printf("Failed to disable NAGLE\n");
		}
#endif
		//set_noblock(ns);
		if (noblock) set_noblock(ns);
		printf("connected\n");
		while(!g_b_exit) {
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			// select()
			FD_SET(ns, &rfds);
			ret = select(ns+1, &rfds, 0, 0, 0); 
			if (ret <= 0) { 
				if (errno != EINTR) {
					printf("select erroro %m\n");
					break;
				}
				else {
					printf("interrupted select!\n");
					continue;
				}
			}
			ret = tcp_read(ns, buf, tcp_lat_pkt_size);
			if (ret < 0) {
				printf("bad read? = %m (%d/%d)\n", ret, tcp_lat_pkt_size);
				exit(1);
			}	
			if (ret == 0) { 
				printf("EOF detected - going back to accept\n");
				break;
			}

			// get requests till we block...
			// send reply
			log_dbg("Read request, sending responce\n");
			ret = tcp_write(ns, buf, tcp_lat_pkt_size);
			if (ret != tcp_lat_pkt_size) {
				printf("partial packet write (%d != %d)\n", ret, tcp_lat_pkt_size);
				exit(1);
			}
			log_dbg("==ack sent\n");
		}

		close(ns);
		printf("all done\n");
	}	
	
}


static void run_tcp_server()
{
	int s, ns;
	struct sockaddr_in addr;
	int ret, i;
	unsigned len;
	char buf[tcp_lat_pkt_size];
	char batch_buf[tcp_lat_pkt_size*reqs_per_resp];
	int flag;

	signal(SIGPIPE, SIG_IGN);
	printf("starting TCP server\n");
	s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (s < 0) {
		printf("Failed to create socket\n");
		exit(1);
	}

	/* listen on any port */
        memset(&addr, sizeof(addr), 0);
        addr.sin_family = PF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(tcp_lat_port);
	flag = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(int));

	ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		printf("failed to bind = %m\n");
		exit(1);
	}
	listen(s, 5);
	while(!g_b_exit) {
		//int flag;
		printf("Waiting for connection\n");
		len = sizeof(addr);
		if (select_on_accept) {
			log_dbg("select() to check for new connection\n");
			if (do_select_on_accept(s) < 0) {
				printf("can not select on accept\n");
				exit(1);
			}
		}
		ns = accept(s, (struct sockaddr *)&addr, &len);
		if (ns < 0) {
			printf("accept failed = %m\n");
			exit(1);
		}
#if 1
		flag = 1;
		ret = setsockopt(ns, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
		if (ret < 0) {
			printf("Failed to disable NAGLE\n");
		}
#endif
		if (noblock) set_noblock(ns);
		printf("connected\n");
		for (i = 0; i < max_n_msgs; i+=reqs_per_resp) {
			int k;
			uint64_t sum = 0;
			if (use_perfect_batch) {
				ret = tcp_read(ns, batch_buf, tcp_lat_pkt_size*reqs_per_resp);
				if (ret < 0) {
					printf("bad read? = %m (%d/%d)\n", ret, tcp_lat_pkt_size);
					exit(1);
				}	
				if (ret == 0) { 
					printf("EOF detected - going back to accept\n");
					break;
				}
			}
			for (k = 0; k < reqs_per_resp; k++) {
				if (use_perfect_batch) {
					memcpy(buf, batch_buf + k*tcp_lat_pkt_size, tcp_lat_pkt_size);
					sum += buf[11];
				}
				else {
					ret = tcp_read(ns, buf, tcp_lat_pkt_size);
					if (ret < 0) {
						printf("bad read? = %m (%d/%d)\n", ret, tcp_lat_pkt_size);
						exit(1);
					}	
					if (ret == 0) { 
						printf("EOF detected - going back to accept\n");
						goto done;
					}
					log_dbg("==> trans req: %d\n", i);
				}
			}
			//printf("Read request, sending responce\n");
			ret = tcp_write(ns, buf, tcp_lat_pkt_size);
			if (ret != tcp_lat_pkt_size) {
				printf("partial packet write (%d != %d)\n", ret, tcp_lat_pkt_size);
				exit(1);
			}
			log_dbg("==ack %d sent\n", i);
		}
	done:
		close(ns);
		printf("all done\n");
	}	
	
}

static int tcp_client_init(struct sockaddr_in *addr)
{
	int s;
	int ret;
	int flag;

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_IP);
	if (!s) {
		printf("Failed to create socket\n");
		exit(1);
	}
	addr->sin_port = htons(tcp_lat_port);

#if 1
	flag = 1;
	ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	if (ret < 0) {
		printf("Failed to disable NAGLE\n");
	}
#endif
	ret = connect(s, (struct sockaddr *)addr, sizeof(*addr));
	if (ret < 0) {
		printf("connect failed\n");
		exit(1);
	}

	if (noblock) set_noblock(s);

	return s;
}

static struct timeval _st, _et;
pthread_spinlock_t lck;
static unsigned tx_cnt;
static uint64_t _total_usec, _n_rr;

static void take_ts(struct tcp_lat_msg *m)
{
	struct timeval dt;
	m->msg_type = TCP_LAT_MSG_TS;
	
	gettimeofday(&dt, 0);
	m->ts.secs = dt.tv_sec;
	m->ts.nsecs = dt.tv_usec * 1000;
//	printf("tx start: sec: %u usec: %u\n", m->ts.secs, m->ts.nsecs/1000);
}

void *tcp_rep_handler(void *arg)
{
	unsigned long s = (unsigned long)arg;
	int ret, i;
	char buf[tcp_lat_pkt_size];
	unsigned rx_cnt = 0; 

	for (i = 0; i < max_n_msgs; i++) {
		log_dbg("==> waiting for resp: %d\n", i);
//pthread_spin_lock(&lck);
//		log_dbg("==> waiting for resp1: %d\n", i);
//		while(tx_cnt <= rx_cnt);
//		log_dbg("==> waiting for resp2: %d\n", i);
		ret = tcp_read(s, buf, tcp_lat_pkt_size);
		log_dbg("==> resp1: %d\n", i);
//pthread_spin_unlock(&lck);
		if (ret != tcp_lat_pkt_size) {
			printf("resp: %d partial packet read (%d != %d)\n", i, ret, tcp_lat_pkt_size);
			//exit(1);
			break;
		}
		if (time_rr) {
			struct timeval st_rr, et_rr, dt_rr;
			struct tcp_lat_msg *m = (struct tcp_lat_msg *)buf;
			if (m->msg_type != TCP_LAT_MSG_TS) {
				printf("expect timestamped packet\n");
				exit(1);
			}	
			gettimeofday(&et_rr, 0);
			st_rr.tv_sec = m->ts.secs;
			st_rr.tv_usec = m->ts.nsecs/1000;	
			//printf("rx start: sec: %u usec: %u\n", m->ts.secs, m->ts.nsecs/1000);
			//printf("RX NOW: sec: %ld usec: %ld\n", et_rr.tv_sec, et_rr.tv_usec);
			timersub(&et_rr, &st_rr, &dt_rr);
			_total_usec += dt_rr.tv_sec * 1000000 + dt_rr.tv_usec;
			//printf("DELTA: %ld\n", dt_rr.tv_sec * 1000000 + dt_rr.tv_usec);
			_n_rr++;
		}
		log_dbg("==> resp: %d\n", i);
		rx_cnt++;
	}
	gettimeofday(&_et, 0);
	return 0;	
}


static void run_tcp_threaded_client(struct sockaddr_in *addr)
{
	int s;
	char buf[tcp_lat_pkt_size];
	pthread_t tid;
	struct timeval dt;
	int i, ret;
	struct tcp_lat_msg *msg;

	if ((unsigned)tcp_lat_pkt_size < sizeof(*msg)) {
		printf("message size is too small\n");
		exit(1);
	}

pthread_spin_init(&lck, 0);
	printf("running client in thread per read/thread per write mode\n");
	s =  tcp_client_init(addr);
	if (!s) {
		printf("Failed to create socket\n");
		exit(1);
	}
	// spawn reader thread
	pthread_create(&tid, 0, tcp_rep_handler, (void *)(unsigned long)s);
	gettimeofday(&_st, 0);
	for (i = 0; i < max_n_msgs; i++) {
		log_dbg("==> write req: %d\n", i);
//pthread_spin_lock(&lck);
		log_dbg("==> write req1: %d\n", i);
		msg = (struct tcp_lat_msg *)buf;
		if (time_rr)
			take_ts(msg);		
		ret = tcp_write(s, buf, tcp_lat_pkt_size);
		log_dbg("==> done write req1: %d\n", i);
//pthread_spin_unlock(&lck);
		if (ret < 0) {
			printf("partial packet write (%d != %d)\n", ret, tcp_lat_pkt_size);
			exit(1);
		}
		log_dbg("==> done write req: %d\n", i);
		tx_cnt++;
	}
	pthread_join(tid, 0);
	timersub(&_et, &_st, &dt);
	printf("%d message processed in %u s %u usec\n", max_n_msgs, (unsigned)dt.tv_sec, (unsigned)dt.tv_usec);
	printf("Average latency is: %1.2lf usec\n", (double)(dt.tv_sec * 1000000 + dt.tv_usec)/(max_n_msgs+max_n_msgs));
	printf("Speed is: %1.2lf msg/sec\n", 1000000*(double)(max_n_msgs + max_n_msgs)/(dt.tv_sec * 1000000 + dt.tv_usec));
	if (time_rr) {	
		printf("Average latency: %1.2f usec\n", (double)_total_usec/(2*_n_rr));
	}
}

static void run_tcp_client(struct sockaddr_in *addr)
{
	int s;
	int ret, i;
	char buf[tcp_lat_pkt_size];
	char batch_buf[tcp_lat_pkt_size*reqs_per_resp];
	struct timeval st, et, dt;
	//struct timeval st_rr, et_rr, dt_rr;
	struct timespec st_rr, et_rr, dt_rr;
	uint64_t total_usec, n_rr;

	printf("starting TCP client\n");
	s = tcp_client_init(addr);
	if (!s) {
		printf("Failed to create socket\n");
		exit(1);
	}
	gettimeofday(&st, 0);
	total_usec = n_rr = 0;
	ts_clear(&st_rr);
	ts_clear(&et_rr);
	ts_clear(&dt_rr);
	//printf("Starting run\n");
	for (i = 0; i < max_n_msgs && !g_b_exit; i+=reqs_per_resp) {
		log_dbg("==> write req\n");
		int k;
		if (time_rr) {
			gettimefromtsc(&st_rr); 
			//gettimeofday(&st_rr, 0);
		}
		for (k = 0; k < reqs_per_resp; k++) {
			if (!use_perfect_batch) {
				ret = tcp_write(s, buf, tcp_lat_pkt_size);
				if (ret < 0) {
					printf("partial packet write (%d != %d)\n", ret, tcp_lat_pkt_size);
					exit(1);
				}
			}
			else 
				memcpy(batch_buf + k * tcp_lat_pkt_size, buf, tcp_lat_pkt_size);
		}
		if (use_perfect_batch) {
			ret = tcp_write(s, batch_buf, tcp_lat_pkt_size*reqs_per_resp);
			if (ret < 0) {
				printf("partial packet write (%d != %d)\n", ret, tcp_lat_pkt_size);
				exit(1);
			}
		}
		log_dbg("==> write req done - waiting for resp resp\n");
		ret = tcp_read(s, buf, tcp_lat_pkt_size);
		if (ret != tcp_lat_pkt_size) {
			printf("partial packet read (%d != %d)\n", ret, tcp_lat_pkt_size);
			exit(1);
		}
		if (time_rr) {
			gettimefromtsc(&et_rr); 
			//gettimeofday(&et_rr, 0);
			//timersub(&et_rr, &st_rr, &dt_rr);
			ts_sub(&et_rr, &st_rr, &dt_rr);
			total_usec += dt_rr.tv_sec * 1000000000L + dt_rr.tv_nsec;
			n_rr++;
		}
		log_dbg("all rcvd\n");
		if (delay_time)
			sleep(delay_time);

	}
	gettimeofday(&et, 0);
	timersub(&et, &st, &dt);
	printf("%d message processed in %u s %u usec\n", max_n_msgs, (unsigned)dt.tv_sec, (unsigned)dt.tv_usec);
	//printf("Average latency is: %1.2lf usec\n", (double)(dt.tv_sec * 1000000 + dt.tv_usec)/(max_n_msgs+max_n_msgs/reqs_per_resp));
	printf("Speed is: %1.2lf msg/sec\n", 1000000*(double)(max_n_msgs + max_n_msgs/reqs_per_resp)/(dt.tv_sec * 1000000 + dt.tv_usec));
	if (time_rr) {	
		printf("Average ***latency: %1.3f usec\n", (double)total_usec/(2*n_rr*1000));
	}
	
	close(s);
	printf("client done\n");
}



int main(int argc, char *argv[])
{
	int op;
	int option_index;
	int server_mode = -1;
	struct sockaddr_in server_addr;
	int ret;
	int poll_mode = 0;
	int testn = 1;

	while ((op = getopt_long(argc, argv, "psc:dhl:n:t:", long_options, &option_index)) != -1) {
		switch (op) {
			case 'c':
				if (server_mode == 1) {
					printf("can not run both in server and client mode\n");
					exit(1);
				}
				ret = get_addr(optarg, &server_addr);
				if (ret < 0) {
					printf("Failed to resolve server address\n");
					exit(1);
				}
				server_mode = 0;
				break;
			case 's':
				if (server_mode == 0) {
					printf("can not run both in server and client mode\n");
					exit(1);
				}
				server_mode = 1;
				break;
			case 'l':
				tcp_lat_pkt_size = atoi(optarg);
				if (tcp_lat_pkt_size <= 0) {
					printf("Invalid packed size value\n");
					exit(1);
				}
				break;
			case 'n':
				max_n_msgs = atoi(optarg);
				if (max_n_msgs <= 0) {
					printf("Invalind number of messages\n");
					exit(1);
				}
				break;
			case OPT_REQS_PER_RESP:
				reqs_per_resp = atoi(optarg);
				break;
			case OPT_USE_PERFECT_BATCH:
				use_perfect_batch = 1;
				break;
			case OPT_TIME_RR:
				time_rr = 1;
				break;
			case OPT_DELAY_TIME:
				delay_time = atoi(optarg);
				break;
			case OPT_NOBLOCK:
				noblock = 1;
				printf("using non blocking sockets");
				break;
			case OPT_SELECT_ON_ACCEPT:
				select_on_accept = 1;
				printf("Use select to check for new connections\n");
				break;
			case OPT_TCP_PORT:
				tcp_lat_port = atoi(optarg);
				printf("Use port %d\n", tcp_lat_port);
				break;
			case 't':
				testn = atoi(optarg);
				if (testn <= 0 || testn >= TST_MAX_TEST) {
					printf("uknown test number: %d\n", testn);
					exit(1);
				}
				printf("Test number %d\n", atoi(optarg));
				break;
			case 'd':
				debug = 1;
				break;
			case 'p':
				poll_mode = 1;
				break;
			case 'h':
			default:
				usage();
		}
	}
	if (server_mode == -1) {
		printf("Must choose either client (-c) or server (-s) mode\n");
		exit(1);
	}
	set_signal_action();

	// force tsc init
	struct timespec ts;
	gettimefromtsc(&ts);
	switch (testn) {
		case TST_BLOCKING_PING_PONG:
			if (server_mode) {
				run_tcp_server();
			}
			else {
				run_tcp_client(&server_addr);
			}
			return 0;
		case TST_SELECT_PING_PONG:
			if (server_mode) {
				run_select_server();
			}
			else {
				run_tcp_client(&server_addr);
			}
			return 0;
		case TST_CL_THREADED_PING_PONG:
			if (server_mode) {
				printf("only works in client mode\n");
				exit(1);
			}
			run_tcp_threaded_client(&server_addr);
			return 0;
		default:
			printf("bad test number %d\n", testn);
	}
	return 0;
}
