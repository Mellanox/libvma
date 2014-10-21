#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <mellanox/vma_extra.h>
#include "types.h"

#define BUFFER_SIZE	1024
#define TIMEOUT	5

extern struct config_t		config;

typedef vma_recv_callback_retval_t (*vma_recv_callback_t)(int fd, size_t sz_iov, struct iovec iov[],
                                                          struct vma_info_t* vma_info, void *context);
vma_recv_callback_retval_t myapp_vma_recv_pkt_notify_callback(
                                                              int fd,
                                                              size_t iov_sz,
                                                              struct iovec iov[],
                                                              struct vma_info_t* vma_info,
                                                              void *context);
void free_packet(void* packet_id, int fd);
int server_management(int *mangSocket);
int get_sock_fd(int *sock, int mangSock);
int receive_data(int *sock, int mangSock);
struct vma_api_t *vma_api = NULL;

int server_main(){
	int		sock	= INVALID_SOCKET;
	int		mangSock	= INVALID_SOCKET;
	int		result	= -1;
	int		rc;
	struct 	timeval timeout;
	struct 	pending_packet_t pending_packet;
	
	printf("Enter Function server_main\n");
		
	if (config.callbackReturn == HOLD) {	
		pending_packet.valid = 0;
	}
	
	rc =  server_management(&mangSock);
    CHECK_VALUE("server_management", rc, 0, goto cleanup);

	rc = get_sock_fd(&sock, mangSock);
	CHECK_VALUE("get_sock_fd", rc, 0, goto cleanup);
	
	if(config.nonBlocking){
	  	rc = make_socket_non_blocking(sock);
		CHECK_VALUE("make_socket_non_blocking", rc, 0, goto cleanup);
	}
	else {
		timeout.tv_sec = TIMEOUT;
		timeout.tv_usec = 0;
		
		rc = setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
				 sizeof(timeout));
		CHECK_VALUE("setsockopt", rc, 0, goto cleanup);
	}
	
	vma_api = vma_get_api();
	CHECK_NOT_EQUAL("vma_get_api", vma_api, NULL, goto cleanup);
	
	printf("Server gets VMA APIs\n");
	
	rc = vma_api->register_recv_callback(sock, myapp_vma_recv_pkt_notify_callback, &pending_packet);
	CHECK_VALUE("register_recv_callback", rc, 0, goto cleanup);
	
	printf("Callback function registered with VMA\n");

	rc = receive_data(&sock, mangSock);
	CHECK_VALUE("receive_data", rc, 0, goto cleanup);

	if (config.callbackReturn == HOLD) {
		CHECK_VALUE("pending_packet.valid", pending_packet.valid, 1, goto cleanup);
		free_packet(pending_packet.vma_info->packet_id, sock);
		free(pending_packet.vma_info);
	}
	
	/* sync for termination */
	rc = sync_side(mangSock, 1);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	result = 0;
 cleanup:
  	if(sock != INVALID_SOCKET){
		rc = close(sock);
		CHECK_VALUE("close", rc, 0, result = -1);
	}
	
	if(mangSock != INVALID_SOCKET) {
		rc = close(mangSock);
		CHECK_VALUE("close", rc, 0, result = -1);
	}
	return result;
}

void myapp_processes_packet_func(
                            struct iovec* iov,
                            size_t iov_sz,
                            void* packet_id,
                            int s){
  printf("Enter Function myapp_processes_packet_func\n");
  /*myapp_processes_packet_func(.....);*/
  
  /* Return zero copied packet buffer back to VMA
  // Would be better to collect a bunch of buffers and return them all at once
  // which will save locks inside VMA
  */
	free_packet(packet_id, s);
}

/**
 * Free VMA buffer reserved for given packet
 * Params:
 *		*packet_id	: ID of packet to remove
 *		fd			: File descriptor for socket.
 **/
void free_packet(void* packet_id, int fd){

  struct vma_packet_t* vma_packet;
  vma_packet = malloc(sizeof(vma_packet->packet_id));
  vma_packet->packet_id = packet_id;
  vma_api->free_packets(fd, vma_packet, 1);
  free(vma_packet);
}

vma_recv_callback_retval_t myapp_vma_recv_pkt_notify_callback(
                                                              int fd,
                                                              size_t iov_sz,
                                                              struct iovec iov[],
                                                              struct vma_info_t* vma_info,
                                                              void *context)
{
	struct pending_packet_t *p_pending_packet;
	
	printf("Enter Function myapp_vma_recv_pkt_notify_callback\n");
		
	if (strcmp(iov[0].iov_base, "recv") == 0) {
		printf("VMA's info struct is not something we recognize so un register the application's callback function\n");
		printf("VMA extra API filtered to VMA_PACKET_RECV\n");
		return VMA_PACKET_RECV;
	}
	
	if (strcmp(iov[0].iov_base, "drop") == 0){
		printf("VMA extra API filtered to VMA_PACKET_DROP\n");
		return VMA_PACKET_DROP;
	}
	
	if (strcmp(iov[0].iov_base, "hold") == 0){
		printf("VMA extra API filtered to VMA_PACKET_HOLD\n");

		/* In hold case we check pending_packet,free its holding buffer if its valid and then fill it with new packet data,
		   so each packet will be freed in the next callback */
		p_pending_packet = (struct pending_packet_t *)context;
		if (p_pending_packet->valid)
			myapp_processes_packet_func(p_pending_packet->iov, p_pending_packet->iovec_size, p_pending_packet->vma_info->packet_id, fd);
		memcpy(p_pending_packet->iov, iov, sizeof(struct iovec)*iov_sz);
		p_pending_packet->iovec_size = iov_sz;
		p_pending_packet->vma_info = malloc(sizeof(struct vma_info_t));
		memcpy (p_pending_packet->vma_info, vma_info, sizeof(struct vma_info_t));
		p_pending_packet->valid = 1;
		
		return VMA_PACKET_HOLD;
	}
	printf("VMA extra API filtered to VMA_PACKET_RECV\n");
	
	return VMA_PACKET_RECV;
}


int server_management(
                      int            *mangSocket){
	int                     rc;
	int                     result          = -1;
	int                     on              = 1;
	int                     mainSocket      = INVALID_SOCKET;
	socklen_t               clilen;
	struct sockaddr_in      servAddr;
	struct sockaddr_in      cliAddr;
	
	printf("Enter Function server_management\n");
	
	mainSocket = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_NOT_EQUAL("socket", mainSocket, INVALID_SOCKET, goto cleanup);
	
	bzero((char *) &servAddr, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(config.mngip);
	servAddr.sin_port = htons(config.port + 15);
	
	rc = setsockopt(mainSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	CHECK_VALUE("setsockopt", rc, 0, goto cleanup);
	
	rc = bind(mainSocket, (struct sockaddr *) &servAddr, sizeof(servAddr));
	CHECK_VALUE("bind", rc, 0, goto cleanup);
	
	listen(mainSocket,1);
	CHECK_VALUE("listen", rc, 0, goto cleanup);
	clilen = sizeof(cliAddr);
	
	*mangSocket = accept(mainSocket, (struct sockaddr *) &cliAddr, &clilen);
	CHECK_NOT_EQUAL("accept", *mangSocket, INVALID_SOCKET, goto cleanup);
	
	printf("server Accepting new client\n");
	result = 0;
 cleanup:
	return result;
}

/**
 *Generate TCP socket, bind it to specific address, listen and accept new connection.
 *
 * Params:
 *		*sock	: File descriptor represent generated socket
 *		mangSock	: File descriptor used for management
 * Returns:
 *		These calls return 0, or -1 if an error occurred.
 **/
int get_sock_fd(int *sock, int mangSock){
	int		rc;
	int		on		= 1;
	int		result	= -1;
	int		mainSocket	= INVALID_SOCKET;
	struct 	sockaddr_in	sAddr;
	struct		sockaddr_in	cliAddr;
	socklen_t	clilen;

	printf("Enter Function get_sock_fd\n");
	
	memset(&sAddr, 0, sizeof(sAddr)); 
	
	mainSocket = socket(AF_INET, SOCK_STREAM, 0);
	CHECK_NOT_EQUAL("socket", mainSocket, INVALID_SOCKET, goto cleanup);
	
	/* Set server Address */
	sAddr.sin_family		= AF_INET;
	sAddr.sin_port			= htons(config.port);
	sAddr.sin_addr.s_addr	= inet_addr(config.sip);
	
	if(config.reuseAddr){
		rc = setsockopt(mainSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		CHECK_VALUE("setsockopt", rc, 0, goto cleanup);
	}
	
	/* Bind socket to server address */
	rc = bind(mainSocket, (struct sockaddr *) &sAddr, sizeof(sAddr));
	CHECK_VALUE("bind", rc, 0, goto cleanup);
			
	memset(&cliAddr, 0, sizeof(cliAddr));
	
	rc = listen(mainSocket, 1);
	CHECK_VALUE("listen", rc, 0, goto cleanup);
	
	/* sync to connect from other side */
	rc = sync_side(mangSock, 1);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	clilen = sizeof(cliAddr);
	
	*sock = accept(mainSocket, (struct sockaddr *) &cliAddr, &clilen);
	CHECK_NOT_EQUAL("accept", *sock, INVALID_SOCKET, goto cleanup);
	
	printf("server Accepting new client\n");
	
	result = 0;
cleanup:
	return result;
}

/**
 *Receive data from given TCP socket fd.
 *
 * Params:
 *		*sock	: File descriptor represent test socket
 *		mangSock	: File descriptor used for management
 * Returns:
 *		These calls return 0, or -1 if an error occurred.
 **/
int receive_data(int *sock, int mangSock){
	
	int	result	= -1;
	int	rc;
	void* recv_data;
	
	printf("Enter Function receive_data\n");

	recv_data = malloc(sizeof(char) * BUFFER_SIZE);
	CHECK_NOT_EQUAL("malloc", recv_data, NULL, goto cleanup);
	
	rc = sync_side(mangSock, 1);
	CHECK_VALUE("sync_side", rc, 0, goto cleanup);
	
	if(config.nonBlocking){
		rc = select_read(sock, TIMEOUT, 0);
		if (config.callbackReturn == DROP) {
			CHECK_VALUE("select_read", rc, 0, goto cleanup);
		}	
		else {
			CHECK_NOT_EQUAL("select_read", rc, 0, goto cleanup);
			CHECK_NOT_EQUAL("select_read", rc, -1, goto cleanup);
		}
	}

	rc = recv(*sock, recv_data, BUFFER_SIZE, 0);
	if (config.callbackReturn == RECV) {
		CHECK_NOT_EQUAL("recv", rc, -1, goto cleanup);
		CHECK_NOT_EQUAL("recv", rc, 0, goto cleanup);
	}
	else {
		CHECK_VALUE("recv", rc, -1, goto cleanup);
		CHECK_VALUE("recv", errno, EAGAIN, goto cleanup);
	}
	
	result = 0;
cleanup:
	if (recv_data)
		free(recv_data);
	return result;
}

