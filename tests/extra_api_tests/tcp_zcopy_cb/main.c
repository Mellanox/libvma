/*
 * Copyright © 2014-2022 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "server.h"
#include "client.h"

int process_arg(char *argv[]);
void print_config(void);

struct config_t config = {
  	0,                      /* Is server            */
	"0",                    /* Server's IP          */
	"0",                    /* Management IP        */
	5000,                   /* Server's port num    */
	0,                      /* Using NONBlocking FDs*/
	1,                      /* Bind Reusable Addres */
	RECV					/* Callback return operation to applied on packet */
};

/****************************************
 *Function: main                        *
 ****************************************/
int main(int argc, char *argv[])
{
  	int                     test_result     = 1;
	int                     rc;
	
	if (argc < 6 || process_arg(argv)) {
      printf("usage: Incorrect parameter \n"
	  "%s <SERVER\\CLIENT> <server IP> <management IP> <BLOCKING\\NONBLOCKING> <RECV\\HOLD\\DROP>\n", argv[0]);
      return -1;
    }
	
	print_config();
	
	if (config.server) {
		rc = server_main();
		CHECK_VALUE("server_main", rc, 0, goto cleanup);
	}
	else {
	  	rc = client_main();
		CHECK_VALUE("client_main", rc, 0, goto cleanup);
	}
	
	test_result = 0;
	
 cleanup:
	if(!test_result)
		printf("Test pass\n");
	else 
		printf("Test Fail\n");

	return test_result;
}

/* Fill entered arguments in config_t variable */
int process_arg(char *argv[]) {

	if(strcmp(argv[1], "SERVER") == 0){
		config.server = 1;
	}
	else if(strcmp(argv[1], "CLIENT") == 0){
		config.server = 0;
	}
	else {
		printf("unknown application type %s\n", argv[1]);
		return -1;
	}
	
	strcpy(config.sip, argv[2]);
			
	strcpy(config.mngip, argv[3]);

	if(strcmp(argv[4], "NONBLOCKING") == 0){
		config.nonBlocking = 1;
	}
	else if(strcmp(argv[4], "BLOCKING") == 0){
		config.nonBlocking = 0;
	}
	else {
		printf("unknown blocking type %s\n", argv[5]);
		return -1;
	}
		
	if(strcmp(argv[5], "RECV") == 0){
		config.callbackReturn = RECV;
	}
	else if(strcmp(argv[5], "HOLD") == 0){
		config.callbackReturn = HOLD;
				}
	else if(strcmp(argv[5], "DROP") == 0){
		config.callbackReturn = DROP;
				}
	else {
		printf("unknown return operation %s\n", argv[6]);
		return -1;
	}

	return 0;
}

/****************************************
 *Function: print_config                *
 ****************************************/
void print_config(void)
{
  	printf("-----------------------------------------\n");
	printf("Is Server:                      %s\n", config.server ? "YES" : "NO");
	printf("Server IP                       %s\n", config.sip);
	printf("Management IP:                  %s\n", config.mngip);
	printf("Port Number:                    %d\n", config.port);
	printf("-----------------------------------------\n");
}





