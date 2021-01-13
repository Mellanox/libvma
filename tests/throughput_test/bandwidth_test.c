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



#include <sys/types.h>		// sockets
#include <sys/socket.h>		// sockets
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>		// internet address manipulation
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>		// random()
#include <sys/time.h>		// timers
#include <time.h>		// clock_gettime()
#include <unistd.h>		// getopt() and sleep()
#include <getopt.h>		// getopt()
#include <ctype.h>		// isprint()
#include <sys/select.h>		// select()  According to POSIX 1003.1-2001 #include <regex.h>
#include <errno.h>
#include <linux/rtc.h>       //Linux RTC 
#include <sys/ioctl.h>
#include <fcntl.h>
#include <regex.h>





#define UDP_PERF_VERSION "1.2"
#define UDP_PERF_VERSION_DATE "21 November 2007"
#define HEADER (sizeof(struct iphdr)+sizeof(struct udphdr))
#define MSG_RATE "5MB"
#define RTC_HZ  1024 				   
#define MIN_PAYLOAD_SIZE        	17
#define DEFAULT_PAYLOAD_SIZE            1470
#define MAX_STREAM_SIZE         	(50*1024*1024)
#define DEFAULT_MC_ADDR			"0.0.0.0"
#define DEFAULT_PORT			11111
#define DEFAULT_TEST_DURATION		10	/* [sec] */
#define MAX_TEST_DURATION_ON_i386	4	/* [sec] */ 
#define MS  1000000
#define KB 1024
#define MB (KB*1024)
#define GB (MB*1024)
#define END_OF_PACKETS 9
#define BYTE 1
#define KBYTE 2
#define MBYTE 3
#define GBYTE 4
#ifndef MAX_PATH_LENGTH
	#define MAX_PATH_LENGTH         1024
#endif
#define IP_PORT_FORMAT_REG_EXP	"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"\
				"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):"\
				"(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5]?[0-9]{1,4})\n"

//long msg_rate=0;
bool b_exit = false;
struct sigaction sigact;
unsigned int client_counter = 0;
struct timespec ts;
struct timespec start_time, end_time;
int max_fd = 0;
int fd;				/* used when single mc group is given */
fd_set readfds;
double totaltime=0;


regex_t regexpr;

typedef struct tagPKT {
	long seqnum;
	char buf;
	int size;
} PKT;

PKT *pkt=NULL;

struct user_params_t {
	struct sockaddr_in addr;
	uint16_t mc_dest_port;
	int sec;		/* test duration */
	int msg_size;
	int server;
	double sendRate;
	char sendRateDetails;

} user_params;

static void usage(const char *argv0)
{
	printf("\nUdp Bandwidth Test\n");
	printf("Usage:\n");
	printf("\t%s [OPTIONS]\n", argv0);
	printf("\t%s -s [-i ip [-p port] [-m message_size]\n", argv0);
	printf("\t%s -c -i ip  [-p port] [-m message_size] [-t time] \n", argv0);
	printf("\t%s -c -r message_rate [-m message_size] [-t time] \n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -s, --server\t\t\trun server (default - unicast)\n");
	printf("  -c, --client\t\t\trun client\n");
	printf("  -i, --ip=<ip>\t\t\tlisten on/send to ip <ip>\n");
	printf("  -p, --port=<port>\t\tlisten on/connect to port <port> (default %d)\n", DEFAULT_PORT);
	printf("  -t, --time=<sec>\t\trun for <sec> seconds (default %d, max = 3600)\n", DEFAULT_TEST_DURATION);
	printf("  -m, --msg_size=<size>\t\tuse messages of size <size> bytes\n");
	printf("  -r, --msg rate expected\n");
	printf("  -v, --version\t\t\tprint the version\n");
	printf("  -h, --help\t\t\tprint this help message\n");
}


void cleanup()
{
	if (pkt) {
		free(pkt);
	}
	close(fd);
} 

void server_sig_handler(int signum)
{
	printf("Got signal %d - exiting.\n", signum);
	b_exit = true;
	//exit(0);
}

void client_sig_handler(int signum)
{
	if (signum) {};

	if (clock_gettime(CLOCK_REALTIME, &end_time)) {
		perror("udp_perf: clock_gettime()");
		exit(1);
	}

	if (!pkt) {
		printf("packet not allocated\n");
	} 
	else if (pkt->seqnum) {
		printf("udp_perf: Total time taken:%.3lf sec, total packet sent %ld, avg msg rate %.0lf pps,\n",totaltime/1000 ,pkt->seqnum, (pkt->seqnum*1000/totaltime));
	}

	b_exit = true;
	//exit(0);
}

/* set the timer on client to the [-t sec] parameter given by user */

void set_client_timer(struct itimerval *timer)
{

	timer->it_value.tv_sec = user_params.sec;
	timer->it_value.tv_usec = 0;
	timer->it_interval.tv_sec = 0;
	timer->it_interval.tv_usec = 0;

}

/* set the action taken when signal received */

void set_signal_action()
{
	sigact.sa_handler =
	user_params.server ? server_sig_handler : client_sig_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(user_params.server ? SIGINT : SIGALRM, &sigact, NULL);
} 


int get_send_rate(char *tmp)
{
	int i;
	char ez[MAX_PATH_LENGTH];
	for (i=0;tmp[i];i++) {
		if (tmp[i] < '0' || tmp[i] > '9' )
			break;
		else
			ez[i]=tmp[i];
	}
	ez[i]='\0';
	if (strstr(tmp,"M") || strstr(tmp,"m"))
		user_params .sendRateDetails = MBYTE;
	else if (strstr(tmp,"K") || strstr(tmp,"k"))
		user_params .sendRateDetails = KBYTE;
	else if (strstr(tmp,"G") || strstr(tmp,"g"))
		user_params .sendRateDetails = GBYTE;
	else if (strstr(tmp,"B") || strstr(tmp,"b"))
		user_params .sendRateDetails = BYTE;
	else
		user_params .sendRateDetails = BYTE;

	// printf("user_params.sendRateDetails=%d\n",user_params.sendRateDetails);
	return atoi(ez);
}


void set_defaults()
{
	memset(&user_params, 0, sizeof(struct user_params_t));
	user_params.addr.sin_family = AF_INET;
	inet_aton(DEFAULT_MC_ADDR, &user_params.addr.sin_addr);
	user_params.mc_dest_port = DEFAULT_PORT;
	user_params.addr.sin_port = htons(user_params.mc_dest_port);
	user_params.sec = DEFAULT_TEST_DURATION;
	user_params.msg_size = DEFAULT_PAYLOAD_SIZE;
	user_params.server = 1;
	//user_params.use_select = 0;
	user_params.sendRate = get_send_rate(MSG_RATE);

	if (user_params.sendRateDetails == KBYTE)
		user_params.sendRate *= KB;
	else if (user_params.sendRateDetails == MBYTE)
		user_params.sendRate *= MB;
	else if (user_params.sendRateDetails == GBYTE)
		user_params.sendRate *= GB;

}

void print_version()
{
	printf("udp_perf version %s (%s)\n", UDP_PERF_VERSION, UDP_PERF_VERSION_DATE);
}


int check_empty_addr(struct in_addr  in){
	return  !(strcmp(DEFAULT_MC_ADDR, inet_ntoa(in)));

}

void prepare_network(int is_server)
{
	u_int yes = 1;
	u_char i_loop = 0;
	struct ip_mreq mreq;
	uint32_t in_addr; 
	struct sockaddr_in client_addr;
	//printf("udp_lat: %s: entry\n", __func__);

	memset(&mreq,0,sizeof(struct ip_mreq));
	printf(" %s port %d\n", inet_ntoa(user_params.addr.sin_addr), user_params.mc_dest_port); 
	/* create a UDP socket */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("udp_lat: socket()");
		exit(1);
	}

	/* allow multiple sockets to use the same PORT number */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("udp_lat: Reusing ADDR failed");
		exit(1);
	}

	in_addr = ntohl(((struct sockaddr_in *)&user_params.addr)->sin_addr.s_addr);

	/* bind to receive address */
	if (is_server) {
		/* check if the ip is 0.0.0.0 and if so insert INADDR_ANY to user_params.addr */
		if (check_empty_addr(user_params.addr.sin_addr)) {
			user_params.addr.sin_addr.s_addr = htonl(INADDR_ANY);
		}
	}

	if (IN_MULTICAST(in_addr)) {
		if (bind(fd, (struct sockaddr *)&user_params.addr, sizeof(user_params.addr)) < 0) {
			perror("udp_lat: bind()");
			exit(1);
		}

		/* use setsockopt() to request that the kernel join a multicast group */
		mreq.imr_multiaddr.s_addr = user_params.addr.sin_addr.s_addr;
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			perror("udp_lat: setsockopt()");
			exit(1);
		}

		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &i_loop, sizeof(i_loop)) == (-1)) {
			perror("udp_lat: setsockopt()");
			exit(1);
		}
	} else {
		if (!is_server) {
			client_addr.sin_family = AF_INET;
			client_addr.sin_port = user_params.addr.sin_port;
			client_addr.sin_addr.s_addr = htonl( INADDR_ANY );
			memset(&(client_addr.sin_zero), '\0', 8); // zero the rest of the struct

			//printf ("IP to bind: %s\n",inet_ntoa(client_addr.sin_addr));
			if (bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
				perror("udp_lat: bind()");
				exit(1);
			}
		} else {   //server - unicast
			if (bind(fd, (struct sockaddr *)&user_params.addr, sizeof(user_params.addr)) < 0) {
				perror("udp_lat: bind()");
				exit(1);
			}
		}
	}

}

long get_current_time_us()
{
	struct timeval tv;
	long usec;
	/* Obtain the time of day, and convert it to a tm struct. */
	gettimeofday (&tv, NULL);
	usec = tv.tv_sec * MS;
	usec += tv.tv_usec;
	return usec;
}

float get_recieve(PKT *pkt,float recv)
{
	if (pkt ->buf == MBYTE)
		recv/=MB;
	else if (pkt ->buf == KBYTE)
		recv/=KB;
	else if (pkt ->buf == GBYTE)
		recv/=GB;

	return  recv;

}

void set_msg_size()
{

	pkt=(PKT *)malloc(user_params.msg_size);
	if (!pkt) {
		printf("Error due memmory allocation\n");
		exit(1);
	}



}



void server_handler()
{

	struct timeval; 
	int nbytes;
	socklen_t size = sizeof(struct sockaddr);
	struct sockaddr_in client_addr;
	printf("udp_perf: [SERVER] listen on: ");
	prepare_network(1);
	long now = 0;
	int missed=0,totalMissed=0,lastMissed=0;
	float timeTaken=0,actualRecieve=0;
	long totalPkt = 0,lastTotalPkt = 0;
	char detail[3];
	while (!b_exit) {
		nbytes = recvfrom(fd, pkt, user_params.msg_size, 0, (struct sockaddr *)&client_addr, &size);
		if (b_exit)
			goto get_out_s;
		if (nbytes < 0) {
			perror("udp_perf: recvfrom()");
			cleanup();
			exit(1);
		}
	        //printf("nbytes= %d\n",nbytes);
		//exit(1);
		
		if (nbytes < (pkt ->size)) {
			printf("Error:Expected %d,recieved=%d\n",pkt->size ,nbytes);
			cleanup();
			exit(1);
		}
		
		if (pkt->buf == END_OF_PACKETS) {
			timeTaken = (get_current_time_us()-now)/1000;
		        actualRecieve = get_recieve(pkt ,actualRecieve);
			totalMissed=pkt->seqnum - totalPkt;
			missed=totalMissed-lastMissed;
			printf("Missed %d pkt, Actual rate = %.2lf%s, Actual packets recived %.0lf pps, Time %.2lf ms\n",
			       missed,actualRecieve,detail ,(totalPkt-lastTotalPkt)*1000/timeTaken,timeTaken);
			printf("Expected packets:%ld ,Total recieved :%ld ,Total missed %d \n",pkt->seqnum,totalPkt,totalMissed); 
			continue;
		}

		if (0 == pkt->seqnum) {
			printf("New instance of server started.  Resetting counters\n");
			now = get_current_time_us();
			totalPkt = 0;
			lastTotalPkt=0;
			lastMissed=0;
			if (pkt->buf == 1)
				strcpy(detail,"B");
			else if (pkt->buf == 2)
				strcpy(detail,"KB");
			else if (pkt->buf == 3)
				strcpy(detail,"MB");
			else if (pkt->buf == 4)
				strcpy(detail,"GB");

			totalMissed=0;
		}

		if ((get_current_time_us()-now) / MS >= 1) {

			timeTaken = (get_current_time_us()-now)/1000;
			actualRecieve = (totalPkt-lastTotalPkt)*((nbytes)/(timeTaken/1000));
			totalMissed=pkt->seqnum - totalPkt; //(sizeof(struct iphdr)+sizeof(struct udphdr))
			actualRecieve = get_recieve(pkt ,actualRecieve);
			missed=totalMissed-lastMissed;
			printf("Missed %d pkt, Actual rate = %.2lf%s, Actual packets recived %.0lf pps, Time %.2lf ms\n",
			       missed,actualRecieve,detail,(totalPkt-lastTotalPkt)*1000/timeTaken,timeTaken);
			lastMissed = totalMissed;
			lastTotalPkt = totalPkt;
			now = get_current_time_us();
		}

		totalPkt++;
	}

get_out_s:
	return;
}

void client_handler()
{        
	int retval,fd_delay;
	unsigned long data;
	struct itimerval timer;
	int ret;
	float timeTaken,actualSend,total_pkt;
	long sent_pkt;
	int i,j;
	long now;
	char detail[3];
	if (!pkt) {
		printf("pkt not allocated");
		exit(1);
	}
	pkt->size = user_params.msg_size;
	prepare_network(0);
	sleep(2);

	if (user_params.sendRateDetails  == 1)
		strcpy(detail,"B");
	else if (user_params.sendRateDetails == 2)
		strcpy(detail,"KB");
	else if (user_params.sendRateDetails == 3)
		strcpy(detail,"MB");
	else if (user_params.sendRateDetails == 4)
		strcpy(detail,"GB");

	printf("udp_perf: Client Start sending ...\n");
	fd_delay = open("/dev/rtc", O_RDONLY);
	if (fd_delay ==  -1) {
		perror("/dev/rtc");
		exit(1);
	}
	//printf("Turning RTC interrupts (%d HZ)\n",RTC_HZ);
	/* Turn on update interrupts (RTC_HZ per second) */
	retval = ioctl(fd_delay, RTC_IRQP_SET,RTC_HZ);
	if (retval == -1) {
		perror("ioctl");
		exit(1);
	}

	/* Enable periodic interrupts */
	retval = ioctl(fd_delay,RTC_PIE_ON, 0);
	if (retval == -1) {
		perror("ioctl");
		exit(1);
	}
	total_pkt = (user_params.sendRate / (user_params.msg_size));
	if(total_pkt<RTC_HZ)
		total_pkt=RTC_HZ;
 	pkt->buf = user_params.sendRateDetails;
	pkt->seqnum=0;
	set_client_timer(&timer);
	if (clock_gettime(CLOCK_REALTIME, &start_time)) {
		perror("udp_perf: clock_gettime()");
		exit(1);
	}
	ret = setitimer(ITIMER_REAL, &timer, NULL);
	if (ret) {
		perror("udp_perf: setitimer()");
		exit(1);
	}
	while (!b_exit) {
		sent_pkt = 0;
		now = get_current_time_us();
	        for (j=0; sent_pkt < total_pkt;j++) {
			/*
		        if (total_pkt < RTC_HZ) { 
				 //now = get_current_time_us();
				if (sendto(fd, pkt, user_params.msg_size , 0,
					   (struct sockaddr *)&(user_params.addr), sizeof(user_params.addr)) <user_params.msg_size) {
					perror("udp_perf: sendto()");
					exit(1);
				}
				sent_pkt++;
				pkt->seqnum++;
			        for (i=0; i<RTC_HZ/(total_pkt) ;i++) {     
					retval = read(fd_delay, &data, sizeof(unsigned long));
					if (retval == -1) {
						perror("read");
						exit(1);
					}
				}

			 */     

			//} else {
				for (i=0; i < (total_pkt/RTC_HZ) && (sent_pkt < total_pkt) ; i++) {
					int nbytes = sendto(fd, pkt, user_params.msg_size, 0, (struct sockaddr *)&(user_params.addr), sizeof(user_params.addr));
					if (b_exit)
						goto get_out_c;
					if (nbytes < 0) {
						perror("udp_perf: sendto()");
						exit(1);
					} 
					else {
						sent_pkt++;
						pkt->seqnum++;

					}
				}
				retval = read(fd_delay, &data, sizeof(unsigned long));
				if (retval == -1) {
					perror("read");
					exit(1);
				}
			}
		


		timeTaken = (get_current_time_us() - now) / 1000;
		totaltime+=timeTaken;
		if (total_pkt==RTC_HZ)
		     actualSend=(RTC_HZ * user_params .msg_size) / (timeTaken / 1000 );
		else
		     actualSend = (user_params.sendRate / (timeTaken / 1000));

		if (user_params.sendRateDetails == KBYTE)
			actualSend /= KB;
		else if (user_params.sendRateDetails == MBYTE)
			actualSend /= MB;
		else if (user_params.sendRateDetails == GBYTE)
			actualSend /= GB;
	        printf("Time taken = %.0lf ms, Actual sent Rate = %.2lf%s, Actual packets sent %ld pps \n",  timeTaken,actualSend,detail ,sent_pkt*1000/(long)timeTaken);
	}
	
get_out_c:
	pkt->buf = (char)END_OF_PACKETS;
	if (sendto(fd, pkt, user_params.msg_size, 0, (struct sockaddr *)&(user_params.addr), sizeof(user_params.addr)) < user_params .msg_size ) {
		perror("udp_perf: sendto()");
		exit(1);
	}
	return;
}



int main(int argc, char *argv[]) {
	char send_rate[1024];
	if (argc == 1){
		usage(argv[0]);
        	 return 1;
	}
	set_defaults();

	/* Parse the parameters */
	while (1) {
		int c = 0;

		static struct option long_options[] = {
			{.name = "port",	.has_arg = 1,.val = 'p'},
			{.name = "time",	.has_arg = 1,.val = 't'},
			{.name = "rate",	.has_arg = 1,.val = 'r'},
			{.name = "msg_size",	.has_arg = 1,.val = 'm'},
			{.name = "ip",		.has_arg = 1,.val = 'i'},
			{.name = "client",	.has_arg = 0,.val = 'c'},
			{.name = "server",	.has_arg = 0,.val = 's'},
			{.name = "help",	.has_arg = 0,.val = 'h'},
			{.name = "version",	.has_arg = 0,.val = 'v'},
			{0,0,0,0}
		};

		if ((c = getopt_long(argc, argv, "p:t:r:m:i:schv",
				     long_options, NULL)) == -1) 
			break;

		switch (c) {
		case 'p':
			user_params.mc_dest_port = strtol(optarg, NULL, 0);
			/* strtol() returns 0 if there were no digits at all */
			if (user_params.mc_dest_port <= 0) {
				printf("udp_perf: Invalid port: %d \n",
				       user_params.mc_dest_port);
				usage(argv[0]);
				return 1;
			}
			user_params.addr.sin_port =
			    htons(user_params.mc_dest_port);
			break;
		case 't':
			user_params.sec = strtol(optarg, NULL, 0);
			if (user_params.sec <= 0 || user_params.sec > 3600) {
				printf("udp_perf: Invalid duration: %d \n",
				       user_params.sec);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'r':
			strncpy(send_rate, optarg, MAX_PATH_LENGTH);
			user_params.sendRate=get_send_rate(send_rate);
			
			if (user_params.sendRateDetails == (char)KBYTE)
			      user_params.sendRate *= KB;
			else if (user_params.sendRateDetails == (char)MBYTE) 
			      user_params.sendRate *= MB;
			else if (user_params.sendRateDetails == (char)GBYTE) 
			      user_params.sendRate *= GB;
			if (user_params.sendRate <= 0) {
				printf("udp_perf: Invalid message rate %fd\n",user_params.sendRate);
				usage(argv[0]);
				return 1;
			}
			
			break;

		case 'm':
			user_params.msg_size = strtol(optarg, NULL, 0);
			if (user_params.msg_size < MIN_PAYLOAD_SIZE) {
				printf("udp_perf: Invalid message size: %d (min: %d)\n",
				       user_params.msg_size, MIN_PAYLOAD_SIZE);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'i':
			if (!inet_aton(optarg, &user_params.addr.sin_addr)) {	// already in network byte order
				printf("udp_perf: Invalid address: %s\n", 
					optarg);
				usage(argv[0]);
				return 1;
			}
			break;
		case 's':
			user_params.server = 1;
                        break;
		case 'c':
			user_params.server = 0;
			break;
		case 'h':
			usage(argv[0]);
			return 1;
			break;
		case 'v':
			print_version();
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind < argc) {
		printf("udp_perf: non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s\n", argv[optind++]);
		printf("\n");
		usage(argv[0]);
		return 1;
	}
        set_msg_size();
	if (user_params.sendRate <= user_params.msg_size ) {
		printf("udp_perf: Invalid message rate, should be bigger than msg size\n");
		return 1;
	}

	set_signal_action();
 



	if (user_params.server)
		server_handler();
	else 
		client_handler();

	return 0;
}

