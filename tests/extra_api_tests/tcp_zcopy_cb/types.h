#ifndef _TYPES_H_
#define _TYPES_H_

#include <errno.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

int make_socket_non_blocking (int sfd);
int select_read(int *fd, int sec, int usec);
int sync_side(int sock, int front);

enum callback_return{
	RECV,
	HOLD,
	DROP
} ;

struct  __attribute__ ((packed)) config_t {
  	int                     server;
  	char                    sip[20];
  	char                    mngip[20];
  	int                     port;
  	int                     nonBlocking;
  	int                     reuseAddr;
	enum callback_return	callbackReturn;	
};

struct __attribute__ ((packed)) pending_packet_t{
	int                   valid;
	int                   iovec_size;
	struct iovec          iov[10];
	struct vma_info_t     *vma_info;
};

#define INVALID_SOCKET -1

#define CHECK_VALUE(verb, act_val, exp_val, cmd) if((exp_val) != (act_val)){ \
    printf("Error in %s, expected value %d, actual value %d\n",	\
		 (verb), (exp_val), (act_val));			\
    cmd;                                                                \
  }

#define CHECK_NOT_EQUAL(verb, act_val, exp_val, cmd) if((exp_val) == (act_val)){ \
    printf("Error in %s\n", (verb));						\
    cmd;                                                                \
  }

#endif
