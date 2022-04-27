/*
 * Copyright © 2013-2022 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFLEN 1024

void usage(char *prog)
{
  printf("Usage: %s { OPTIONS }\n where options are:\n"
	  "	      -s/c client/server (if not specified running as server)\n"
	  "	      -p port\n"
	  "	      -r remote server address(for the client side)\n"
	  , prog);
  exit(0);
}

int run_tcp_client(char* remote_server, int remote_port)
{
    int s;
    struct    sockaddr_in servaddr;
    int rc;
    char msg[] = "asdfg";

    if ( (s = ::socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        perror("socket");
        fprintf(stderr, "Error creating socket.\n");
    }

    int resize = 128;
    void* test;
    socklen_t test_size;
    rc = setsockopt(s, SOL_SOCKET, SO_RCVBUF, &resize, sizeof(int));
    if (rc < 0)
        perror("setsockopt");

    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &test, &test_size);
    printf("SO_RECVBUF level=%d SOL_SOCKET level=%d test %d\n", SO_RCVBUF, SOL_SOCKET, (int*)test);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_port        = htons(remote_port);
    if ( inet_aton(remote_server, &servaddr.sin_addr) <= 0 ) {
        printf("ERROR: Invalid remote IP address.\n");
        return -1;
    }

    printf("Connecting..\n");
    rc = ::connect(s, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if ( (rc < 0) ) {
        printf("ECHOCLNT: Error calling connect()\n");
        perror("connect");
        close(s);
    }

    sleep(1);
    
    for (int i=0; i<5; i++)
    {
        printf("Sending...\n");
        rc = send(s, msg, 6, 0);
        sleep(1);
    }
    shutdown(s, SHUT_RDWR);
    close (s);

    sleep(1);
}

int run_tcp_server(int server_port)
{
    int			i;		/* index counter for loop operations */
    int			rc; 		/* system calls return value storage */
    int			s; 		/* socket descriptor */
    int			ws; 		/* new connection's socket descriptor */
    char		buf[1024];  /* buffer for incoming data */
    struct sockaddr_in	sa, tmp; 		/* Internet address struct */
    struct sockaddr_in	csa; 		/* client's address struct */
    socklen_t         	size_csa = sizeof(sockaddr_in); 	/* size of client's address struct */


    
    /* initiate machine's Internet address structure */
    /* first clear out the struct, to avoid garbage  */
    memset(&sa, 0, sizeof(sa));
    /* Using Internet address family */
    sa.sin_family = AF_INET;
    /* copy port number in network byte order */
    sa.sin_port = htons(server_port);
    /* we will accept cnnections coming through any IP	*/
    /* address that belongs to our host, using the	*/
    /* INADDR_ANY wild-card.				*/
    sa.sin_addr.s_addr = INADDR_ANY;
    /* allocate a free socket                 */
    /* Internet address family, Stream socket */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("socket: allocation failed");
    }

    //bind the socket to the newly formed address
    rc = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rc) {
         perror("bind");
    }
    /* ask the system to listen for incoming connections	*/
    /* to the address we just bound. specify that up to		*/
    /* 5 pending connection requests will be queued by the	*/
    /* system, if we are not directly awaiting them using	*/
    /* the accept() system call, when they arrive.		*/
    rc = listen(s, 1024);


    /* check there was no error */
    if (rc) {
	perror("listen");
    }
    
    memset(&tmp, 0, sizeof(tmp));
    rc = getsockname(s, (struct sockaddr *)&tmp, &size_csa);

    /* check there was no error */
    if (rc) {
        perror("getsockname");
    }
    printf("Listening on port %d\n", ntohs(tmp.sin_port));

    ws = accept(s, (struct sockaddr *)&csa, &size_csa); 

    printf("Connected...\n");

    while ( true ) 
    {
        rc = recv(ws, buf, 1024, 0);
        if ( rc < 0 ) {
            perror("recv");
            return -1;
        }

        printf("Got msg, size=%d\n", rc);
        if ( rc == 0 ) {
            shutdown(ws, SHUT_RDWR);
            close(ws);
            printf("Closing %d\n", ws);
            return 0;
        }
        printf("Recieved: %s\n", buf);
    }

}

int main(int argc, char* argv[])
{
    char optstring[20] = "r:p:hsc";
    char c;

    char* remote_server;
    int port;
    bool run_as_server = true;

    while ((c = getopt(argc, argv, optstring)) != -1)
    {
        switch(c)
        {
            case 'r':
                remote_server = strdup(optarg);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                run_as_server = true;
                break;
            case 'c':
                run_as_server = false;
                break;
            case 'h':
                usage(argv[0]);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    if ( run_as_server )
            run_tcp_server(port);
    else
            run_tcp_client(remote_server, port);

}

