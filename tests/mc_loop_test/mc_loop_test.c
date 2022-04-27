/*
 * Copyright (c) 2001-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <arpa/inet.h>		// internet address manipulation
#include <time.h>		      
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>		// random()
#include <unistd.h>		// getopt() and sleep()
#include <getopt.h>		// getopt()
#include <regex.h>

#define DEFAULT_MC_ADDR			"224.4.4.1"
#define DEFAULT_PORT			11111

#define IP_PORT_FORMAT_REG_EXP	"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"\
				"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):"\
				"(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5]?[0-9]{1,4})\n"

struct sigaction sigact;
int fd;				/* used when single mc group is given */
char *msgbuf = 0;
char *pattern = 0;

u_char is_loop = 0;

struct user_params_t {
	struct sockaddr_in addr;
	uint16_t mc_dest_port;
	int msg_size;
	int server;
} user_params;


static void usage(const char *argv0)
{
	printf("\nMC Loop Test\n");
	printf("Usage:\n");
	printf("\t%s [OPTIONS]\n", argv0);
	printf("\t%s -s [-i ip] [-p port] [-m message_size] [-l]\n", argv0);
	printf("\t%s -c [-i ip]  [-p port] [-m message_size] [-l]\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -s, --server\t\t\trun server (default - unicast)\n");
	printf("  -c, --client\t\t\trun client\n");
	printf("  -i, --ip=<ip>\t\t\tlisten on/send to ip <ip> (default %s)\n", DEFAULT_MC_ADDR);
    printf("  -l, --loop\t\t\tto enable mc loop (in the default it's disabled)\n");
	printf("  -p, --port=<port>\t\tlisten on/connect to port <port> (default %d)\n", DEFAULT_PORT);
	printf("  -m, --msg_size=<size>\t\tuse messages of size <size> bytes\n");
	printf("  -h, --help\t\t\tprint this help message\n");
}

void cleanup()
{
    close(fd);
}

void server_sig_handler(int signum)
{
	printf("Got signal %d - exiting.\n", signum);
	cleanup();
	exit(0);
}

void client_sig_handler(int signum)
{
	cleanup();
	exit(0);
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

void set_defaults()
{
	memset(&user_params, 0, sizeof(struct user_params_t));
	inet_aton(DEFAULT_MC_ADDR, &user_params.addr.sin_addr);
    user_params.mc_dest_port = DEFAULT_PORT;
	user_params.addr.sin_family = AF_INET;
	user_params.addr.sin_port = htons(user_params.mc_dest_port);
	user_params.msg_size = 1;
	user_params.server = 1;
}


/* write a pattern to buffer */
void write_pattern(char * buf, int buf_size)
{
        int len = 0;
        char c;

        srand((unsigned)time(NULL));
        while (len < buf_size) {
		c = (char) (rand() % 128);
		//buf[len] = c;
		pattern[len] = c;
		len++;
	}
}


int check_empty_addr(struct in_addr  in){
	return  !(strcmp("0.0.0.0", inet_ntoa(in)));
	 
}

void prepare_network(int is_server)
{
        u_int yes = 1;
        struct ip_mreq mreq;
        uint32_t in_addr; 
        struct sockaddr_in client_addr;
        u_char i_loop = is_loop;

        memset(&mreq,0,sizeof(struct ip_mreq));
        printf(" %s port %d\n", inet_ntoa(user_params.addr.sin_addr), user_params.mc_dest_port); 
        /* create a UDP socket */
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("mc_loop_test: socket()");
            exit(1);
        }
        
        /* allow multiple sockets to use the same PORT number */
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            perror("mc_loop_test: Reusing ADDR failed");
            exit(1);
        }
        
        in_addr = ntohl(((struct sockaddr_in *)&user_params.addr)->sin_addr.s_addr);
            
        /* bind to receive address */
        if (is_server){
            /* check if the ip is 0.0.0.0 and if so insert INADDR_ANY to user_params.addr */
            if (check_empty_addr(user_params.addr.sin_addr)){
                user_params.addr.sin_addr.s_addr = htonl(INADDR_ANY);
            }
        }
        
        if (IN_MULTICAST(in_addr)){
            if (bind(fd, (struct sockaddr *)&user_params.addr, sizeof(user_params.addr)) < 0) {
                                perror("mc_loop_test: bind()");
                                exit(1);
                        }
        
            /* use setsockopt() to request that the kernel join a multicast group */
            mreq.imr_multiaddr.s_addr = user_params.addr.sin_addr.s_addr;
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                perror("mc_loop_test: setsockopt()");
                exit(1);
            }
        
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &i_loop, sizeof(i_loop)) == (-1)) {
                perror("mc_loop_test: setsockopt()");
                exit(1);
            }
        }
        else {
            if (!is_server){
                client_addr.sin_family = AF_INET;
                client_addr.sin_port = user_params.addr.sin_port;
                client_addr.sin_addr.s_addr = htonl( INADDR_ANY );
                memset(&(client_addr.sin_zero), '\0', 8); // zero the rest of the struct
        
                //printf ("IP to bind: %s\n",inet_ntoa(client_addr.sin_addr));
                if (bind(fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
                                    perror("mc_loop_test: bind()");
                                    exit(1);
                }
            }
            else {   //server - unicast
                if (bind(fd, (struct sockaddr *)&user_params.addr, sizeof(user_params.addr)) < 0) {
                    perror("mc_loop_test: bind()");
                    exit(1);
                            }
            }
        }
        //printf("udp_lat: %s: exit\n", __func__);
}

void server_handler()
{
 	int nbytes;
	socklen_t size = sizeof(struct sockaddr);
	struct sockaddr_in client_addr;
	printf("mc_loop_test: [SERVER] Listen on: ");
	prepare_network(1);

    printf("Waiting to receive from FD %d\n", fd);
    if ((nbytes = recvfrom(fd, msgbuf, user_params.msg_size, 0, (struct sockaddr *)&client_addr, &size)) < 0) {
        perror("mc_loop_test: recvfrom()");
        exit(1);
    }
    printf("server:Message received...\n");

	printf("mc_loop_test: %s: exit\n", __func__);
}

void client_handler()
{
	printf("mc_loop_test: [CLIENT] Start sending on: ");
	prepare_network(0);

	sleep(2);

    //printf("Sending to: FD = %d; IP = %s; PORT = %d\n",fd, inet_ntoa(user_params.addr.sin_addr), ntohs(user_params.addr.sin_port));
    if (sendto(fd, pattern/*msgbuf*/, user_params.msg_size, 0,
         (struct sockaddr *)&(user_params.addr), sizeof(user_params.addr)) < 0) {
        perror("mc_loop_test: sendto()");
        exit(1);
    }
    printf("mc_loop_test: Client done sending.\n") ;
}

int main(int argc, char *argv[]) {
	if (argc == 1){
		usage(argv[0]);
        	 return 1;
	}
	/* set default values */
	set_defaults();

	/* Parse the parameters */
	while (1) {
		int c = 0;

		static struct option long_options[] = {
			{.name = "port",	.has_arg = 1,.val = 'p'},
			{.name = "loop",	.has_arg = 0,.val = 'l'},
			{.name = "msg_size",	.has_arg = 1,.val = 'm'},
			{.name = "ip",		.has_arg = 1,.val = 'i'},
			{.name = "client",	.has_arg = 0,.val = 'c'},
			{.name = "server",	.has_arg = 0,.val = 's'},
			{.name = "help",	.has_arg = 0,.val = 'h'},
			{0}
		};

		if ((c = getopt_long(argc, argv, "p:m:i:lsch",
				     long_options, NULL)) == -1) 
			break;

		switch (c) {
		case 'p':
			user_params.mc_dest_port = strtol(optarg, NULL, 0);
			/* strtol() returns 0 if there were no digits at all */
			if (user_params.mc_dest_port <= 0) {
				printf("mc_loop_test: Invalid port: %d \n", user_params.mc_dest_port);
				usage(argv[0]);
				return 1;
			}
			user_params.addr.sin_port = htons(user_params.mc_dest_port);
			break;

        case 'l':
            is_loop=1;
   			break;
		case 'm':
			user_params.msg_size = strtol(optarg, NULL, 0);
			if (user_params.msg_size <= 0) {
				printf("mc_loop_test: Invalid message size: %d \n",
				       user_params.msg_size);
				usage(argv[0]);
				return 1;
			}
			break;
		case 'i':
			if (!inet_aton(optarg, &user_params.addr.sin_addr)) {	// already in network byte order
				printf("mc_loop_test: Invalid address: %s\n", optarg);
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
			return 0;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind < argc) {
		printf("mc_loop_test: non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		usage(argv[0]);
		return 1;
	}

	msgbuf = malloc(user_params.msg_size+1);
	msgbuf[0] = '$';

	pattern = malloc(user_params.msg_size+1);
	pattern[0] = '$';

	write_pattern(msgbuf, user_params.msg_size);

	set_signal_action();

	if (user_params.server) {
		server_handler();
	}
	else {
		client_handler();
	}

	if (msgbuf) {
		free(msgbuf);
		msgbuf = 0;
	}
	if (pattern) {
		free(pattern);
		pattern = 0;
	}
	return 0;
}

