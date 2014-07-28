/*
 * Copyright (c) 2006 Mellanox Technologies Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 *
 * $Id: config_parser.y 1.5 2005/06/29 11:39:27 eitan Exp $
 */


/*

*/
%{

/* header section */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vma/util/libvma.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

typedef enum
{
	CONF_RULE
} configuration_t;

#define YYERROR_VERBOSE 1

extern int yyerror(const char *msg);
extern int yylex(void);
static int parse_err = 0;

struct dbl_lst	__instance_list;

/* some globals to store intermidiate parser state */
static struct use_family_rule __vma_rule;
static struct address_port_rule *__vma_address_port_rule = NULL;
static int __vma_rule_push_head = 0;
static int current_role = 0;
static configuration_t current_conf_type = CONF_RULE;
static struct instance *curr_instance = NULL;

int __vma_config_empty()
{
	return ((__instance_list.head == NULL) && (__instance_list.tail == NULL));
}

/* define the address by 4 integers */
static void __vma_set_ipv4_addr(short a0, short a1, short a2, short a3)
{
	char buf[16];
	struct in_addr *p_ipv4 = NULL;
  
	p_ipv4 = &(__vma_address_port_rule->ipv4);
  
	sprintf(buf,"%d.%d.%d.%d", a0, a1, a2, a3);
	if (!inet_aton(buf, p_ipv4))
	{
		parse_err = 1;
		yyerror("provided address is not legal");
	}
}

static void __vma_set_inet_addr_prefix_len(unsigned char prefixlen)
{
	if (prefixlen > 32)
		prefixlen = 32;
	
	__vma_address_port_rule->prefixlen = prefixlen;
}

// SM: log part is  not used...
int __vma_min_level = 9;

void __vma_dump_address_port_rule_config_state(char *buf) {
	if (__vma_address_port_rule->match_by_addr) {
		if ( __vma_address_port_rule->prefixlen != 32 )
 			sprintf(buf+strlen(buf), " %s/%d", inet_ntoa( __vma_address_port_rule->ipv4 ), 
					__vma_address_port_rule->prefixlen);
		else
			sprintf(buf+strlen(buf), " %s", inet_ntoa( __vma_address_port_rule->ipv4 ));
	} else
		sprintf(buf+strlen(buf), " *");
	
	if (__vma_address_port_rule->match_by_port) {
		sprintf(buf+strlen(buf), ":%d",__vma_address_port_rule->sport);
		if (__vma_address_port_rule->eport > __vma_address_port_rule->sport) 
			sprintf(buf+strlen(buf), "-%d",__vma_address_port_rule->eport);
	}
	else
		sprintf(buf+strlen(buf), ":*");
}

/* dump the current state in readable format */
static void  __vma_dump_rule_config_state() {
	char buf[1024];
	sprintf(buf, "\tACCESS CONFIG: use %s %s %s ", 
			__vma_get_transport_str(__vma_rule.target_transport), 
			__vma_get_role_str(current_role),
			__vma_get_protocol_str(__vma_rule.protocol));
	__vma_address_port_rule = &(__vma_rule.first);
	__vma_dump_address_port_rule_config_state(buf);
	if (__vma_rule.use_second) {
		__vma_address_port_rule = &(__vma_rule.second);
		__vma_dump_address_port_rule_config_state(buf);
	}
	sprintf(buf+strlen(buf), "\n");
	__vma_log(1, buf);
}

/* dump configuration properites of new instance */
static void  __vma_dump_instance() {
	char buf[1024];
	
	if (curr_instance) {
		sprintf(buf, "CONFIGURATION OF INSTANCE ");
		if (curr_instance->id.prog_name_expr)
			sprintf(buf+strlen(buf), "%s ", curr_instance->id.prog_name_expr);
		if (curr_instance->id.user_defined_id)
			sprintf(buf+strlen(buf), "%s", curr_instance->id.user_defined_id);
		sprintf(buf+strlen(buf), ":\n");
		__vma_log(1, buf);
	}
}

static void __vma_add_dbl_lst_node_head(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
	
		node->prev = NULL;
		node->next = lst->head;
		
		if (!lst->head)
			lst->tail = node;
		else 
			lst->head->prev = node;	
					
		lst->head = node;
	}
}

static void __vma_add_dbl_lst_node(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
		node->prev = lst->tail;
	
		if (!lst->head) 
			lst->head = node;
		else 
			lst->tail->next = node;
		lst->tail = node;
	}
}

static struct dbl_lst_node* __vma_allocate_dbl_lst_node()
{
	struct dbl_lst_node *ret_val = NULL;
	
	ret_val = (struct dbl_lst_node*) malloc(sizeof(struct dbl_lst_node));
	if (!ret_val) {
		yyerror("fail to allocate new node");
		parse_err = 1;		
	}
	else
		memset((void*) ret_val, 0, sizeof(struct dbl_lst_node));	
	return ret_val;
}

/* use the above state for adding a new instance */
static void __vma_add_instance(char *prog_name_expr, char *user_defined_id) {
	struct dbl_lst_node *curr, *new_node;
	struct instance *new_instance;
  
	curr = __instance_list.head;
	while (curr) {
		struct instance *instance = (struct instance*)curr->data;
		if (!strcmp(prog_name_expr, instance->id.prog_name_expr) && !strcmp(user_defined_id, instance->id.user_defined_id)) {
			curr_instance = (struct instance*)curr->data;
			if (__vma_min_level <= 1) __vma_dump_instance();
			return;  		
		}
		curr = curr->next;
	}
  
	if (!(new_node = __vma_allocate_dbl_lst_node())) 
		return;
	
	new_instance = (struct instance*) malloc(sizeof(struct instance));
	if (!new_instance) {
		yyerror("fail to allocate new instance");
		parse_err = 1;
		return;
	}

	memset((void*) new_instance, 0, sizeof(struct instance));
	new_instance->id.prog_name_expr = strdup(prog_name_expr);
	new_instance->id.user_defined_id = strdup(user_defined_id);
  
	if (!new_instance->id.prog_name_expr || !new_instance->id.user_defined_id) {
		yyerror("failed to allocate memory");
		parse_err = 1;
		if (new_instance->id.prog_name_expr)
			free(new_instance->id.prog_name_expr);
		if (new_instance->id.user_defined_id)
			free(new_instance->id.user_defined_id);
		free(new_instance);
		return;
	}
	new_node->data = (void*)new_instance;
	__vma_add_dbl_lst_node(&__instance_list, new_node);
	curr_instance = new_instance;
	if (__vma_min_level <= 1) __vma_dump_instance();
}

static void __vma_add_inst_with_int_uid(char *prog_name_expr, int user_defined_id) {
	char str_id[50];
	sprintf(str_id, "%d", user_defined_id);
	__vma_add_instance(prog_name_expr, str_id);
}

/* use the above state for making a new rule */
static void __vma_add_rule() {
	struct dbl_lst *p_lst;
	struct use_family_rule *rule;
	struct dbl_lst_node *new_node;

	if (!curr_instance)
		__vma_add_instance("*", "*");
  	if (!curr_instance)
		return;
  
	if (__vma_min_level <= 1) __vma_dump_rule_config_state();
	switch (current_role) {
	case ROLE_TCP_SERVER:
		p_lst = &curr_instance->tcp_srv_rules_lst;
		break;
	case ROLE_TCP_CLIENT:
		p_lst = &curr_instance->tcp_clt_rules_lst;
		break;
	case ROLE_UDP_SENDER:
		p_lst = &curr_instance->udp_snd_rules_lst;
		break;
	case ROLE_UDP_RECEIVER:
		p_lst = &curr_instance->udp_rcv_rules_lst;
		break;
	case ROLE_UDP_CONNECT:
		p_lst = &curr_instance->udp_con_rules_lst;
		break;
	default:
		yyerror("ignoring unknown role");
		parse_err = 1;
		return;
		break;
	}

	if (!(new_node = __vma_allocate_dbl_lst_node())) 
		return;
	
	rule = (struct use_family_rule *)malloc(sizeof(*rule));
	if (!rule) {
		yyerror("fail to allocate new rule");
		parse_err = 1;
		return;
	}
	memset(rule, 0, sizeof(*rule));
	new_node->data = (void*)rule;
	*((struct use_family_rule *)new_node->data) = __vma_rule; 
	if (__vma_rule_push_head)
		__vma_add_dbl_lst_node_head(p_lst, new_node);
	else
		__vma_add_dbl_lst_node(p_lst, new_node);
}

%}


%union {
  int        ival;
  char      *sval;
}             

%token USE "use"
%token TCP_CLIENT "tcp client"
%token TCP_SERVER "tcp server"
%token UDP_SENDER "udp sender"
%token UDP_RECEIVER "udp receiver"
%token UDP_CONNECT "udp connect"
%token TCP "tcp"
%token UDP "udp"
%token OS "os"
%token VMA "vma"
%token SDP "sdp"
%token SA "sa"
%token INT "integer value"
%token APP_ID "application id"
%token PROGRAM "program name"
%token USER_DEFINED_ID_STR "userdefined id str"
%token LOG "log statement"
%token DEST "destination"
%token STDERR "ystderr"
%token SYSLOG "syslog"
%token FILENAME "yfile"
%token NAME "a name"
%token LEVEL "min-level"
%token LINE "new line"
%type <sval> NAME PROGRAM USER_DEFINED_ID_STR
%type <ival> INT LOG DEST STDERR SYSLOG FILENAME APP_ID USE OS VMA SDP TCP UDP TCP_CLIENT TCP_SERVER UDP_SENDER UDP_RECEIVER UDP_CONNECT LEVEL LINE 
%start config

%{
  long __vma_config_line_num;
%}
%%

NL:
	  LINE
	| NL LINE
	|;
    
ONL:
	| NL;
    
config: 
	ONL statements
	;

statements:
	| statements statement
	;

statement: 
 	log_statement
	| app_id_statement  
	| socket_statement
	;

log_statement: 
 	LOG log_opts NL
	;

log_opts:
	| log_opts log_dest
	| log_opts verbosity
	;

log_dest: 
 	  DEST STDERR			{ __vma_log_set_log_stderr(); }
	| DEST SYSLOG			{ __vma_log_set_log_syslog(); }
  	| DEST FILENAME NAME		{ __vma_log_set_log_file($3); }
	;
    
verbosity: 
	LEVEL INT { __vma_log_set_min_level($2); }
	;

app_id_statement:
	app_id NL
	;

app_id:
	  APP_ID PROGRAM USER_DEFINED_ID_STR	{__vma_add_instance($2, $3);	if ($2) free($2); if ($3) free($3);	}
	| APP_ID PROGRAM INT			{__vma_add_inst_with_int_uid($2, $3);	if ($2) free($2);		}
	;


socket_statement: 
    use transport role tuple NL { __vma_add_rule(); }
 	;
 	
use:
	USE { current_conf_type = CONF_RULE; }
 	; 

transport:
 	  OS	{ __vma_rule.target_transport = TRANS_OS;	}
	| VMA	{ __vma_rule.target_transport = TRANS_VMA;	}
	| SDP	{ __vma_rule.target_transport = TRANS_SDP;	}
	| SA	{ __vma_rule.target_transport = TRANS_SA;	}
	| '*'	{ __vma_rule.target_transport = TRANS_ULP;	}
	;


role:
	  TCP_SERVER	{ current_role = ROLE_TCP_SERVER; 	__vma_rule.protocol = PROTO_TCP; }
	| TCP_CLIENT 	{ current_role = ROLE_TCP_CLIENT; 	__vma_rule.protocol = PROTO_TCP; }
	| UDP_RECEIVER	{ current_role = ROLE_UDP_RECEIVER; __vma_rule.protocol = PROTO_UDP; }
	| UDP_SENDER 	{ current_role = ROLE_UDP_SENDER;	__vma_rule.protocol = PROTO_UDP; }
	| UDP_CONNECT 	{ current_role = ROLE_UDP_CONNECT;	__vma_rule.protocol = PROTO_UDP; }
	;

tuple:
	  three_tuple
	| five_tuple
	;

three_tuple:
	address_first ':' ports
	;

five_tuple:
	address_first ':' ports ':' address_second ':' ports
	;

address_first:
	{ __vma_address_port_rule = &(__vma_rule.first); __vma_rule.use_second = 0; } address
	;

address_second:
	{ __vma_address_port_rule = &(__vma_rule.second); __vma_rule.use_second = 1; } address
	;

address:
	  ipv4         { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 1; __vma_set_inet_addr_prefix_len(32); }
	| ipv4 '/' INT { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 1; __vma_set_inet_addr_prefix_len($3); }
	| '*'          { if (current_conf_type == CONF_RULE) __vma_address_port_rule->match_by_addr = 0; __vma_set_inet_addr_prefix_len(32); }
	;

ipv4:
	INT '.' INT '.' INT '.' INT { __vma_set_ipv4_addr($1,$3,$5,$7); }
 	;

ports:
	  INT         { __vma_address_port_rule->match_by_port = 1; __vma_address_port_rule->sport= $1; __vma_address_port_rule->eport= $1; }
	| INT '-' INT { __vma_address_port_rule->match_by_port = 1; __vma_address_port_rule->sport= $1; __vma_address_port_rule->eport= $3; }
	| '*'         { __vma_address_port_rule->match_by_port = 0; __vma_address_port_rule->sport= 0;  __vma_address_port_rule->eport= 0;  }
	;

%%

int yyerror(const char *msg)
{
	/* replace the $undefined and $end if exists */
	char *orig_msg = (char*)malloc(strlen(msg)+25);
	char *final_msg = (char*)malloc(strlen(msg)+25);

	strcpy(orig_msg, msg);
	
	char *word = strtok(orig_msg, " ");
	final_msg[0] = '\0';
	while (word != NULL) {
		if (!strncmp(word, "$undefined", 10)) {
			strcat(final_msg, "unrecognized-token ");
		} else if (!strncmp(word, "$end",4)) {
			strcat(final_msg, "end-of-file ");
		} else {
			strcat(final_msg, word);
			strcat(final_msg, " ");
		}
		word = strtok(NULL, " ");
	}
	
	__vma_log(9, "Error (line:%ld) : %s\n", __vma_config_line_num, final_msg);
	parse_err = 1;
	
	free(orig_msg);
	free(final_msg);
	return 1;
}

#include <unistd.h>
#include <errno.h>

/* parse apollo route dump file */
int __vma_parse_config_file (const char *fileName) {
	extern FILE * libvma_yyin;
   
	/* open the file */
	if (access(fileName, R_OK)) {
		printf("libvma Error: No access to open File:%s %s\n", 
				fileName, strerror(errno));
		return(1);
	}

	libvma_yyin = fopen(fileName,"r");
	if (!libvma_yyin) {
		printf("libvma Error: Fail to open File:%s\n", fileName);
		return(1);
	}
	__instance_list.head = NULL;
	__instance_list.tail = NULL;
	parse_err = 0;
	__vma_config_line_num = 1;

	/* parse it */
	yyparse();

	fclose(libvma_yyin);
	return(parse_err);
}

int __vma_parse_config_line (char *line) {
	extern FILE * libvma_yyin;
	
	__vma_rule_push_head = 1;
	
	libvma_yyin = fmemopen(line, strlen(line), "r");
	
	if (!libvma_yyin) {
		printf("libvma Error: Fail to parse line:%s\n", line);
		return(1);
	}
	
	parse_err = 0;
	yyparse();
	
	fclose(libvma_yyin);
	
	return(parse_err);
}
