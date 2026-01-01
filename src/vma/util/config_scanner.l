/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 *
 * $Id: ibnl_scanner.ll,v 1.4 2005/02/23 21:08:37 eitan Exp $
 */

%{

//#define DEBUG 1  

#define yyparse libvma_yyparse
#define yylex   libvma_yylex
#define yyerror libvma_yyerror
#define yylval  libvma_yylval
#define yychar  libvma_yychar
#define yydebug libvma_yydebug
#define yynerrs libvma_yynerrs

#define yywrap  libvma_yywrap

#include <string.h>
#include <stdio.h>
#include "config_parser.h"
extern long __vma_config_line_num;
%}
%option nounput
%option noinput
%s CANNAME APP_ID_S1 APP_ID_S2
%%

^[ \t]*#.* {}

application-id {
	yylval.ival = APP_ID;
#ifdef DEBUG 
	printf("APP_ID\n");
#endif
	BEGIN(APP_ID_S1);
	return APP_ID;
}

<APP_ID_S1>[^ \t\n]+ {
	yylval.sval = (char *)malloc(strlen(yytext) + 1);
	strcpy(yylval.sval, yytext);
#ifdef DEBUG
	printf("PROGRAM:%s\n",yylval.sval);
#endif
	BEGIN(APP_ID_S2);
	return (PROGRAM);
}

<APP_ID_S2>[^ \t\n]+ {
	yylval.sval = (char *)malloc(strlen(yytext) + 1);
	strcpy(yylval.sval, yytext);
#ifdef DEBUG
	printf("USER_DEFINED_ID_STR:%s\n",yylval.sval);
#endif
	BEGIN(0);
	return (USER_DEFINED_ID_STR);
}

([1-9][0-9]*|0) { 
	yylval.ival = atoi(yytext);
#ifdef DEBUG
	printf("INT:%d\n",yylval.ival);
#endif
	return INT;
}

log {
	yylval.ival = LOG;
#ifdef DEBUG
	printf("LOG\n");
#endif
	return LOG;
}

destination {
	yylval.ival = DEST;
#ifdef DEBUG
	printf("DEST\n");
#endif
	return DEST;
}

min-level {
	yylval.ival = LEVEL;
#ifdef DEBUG
	printf("LEVEL\n");
#endif
	return LEVEL;
}

ystderr {
	yylval.ival = STDERR;
#ifdef DEBUG
	printf("STDERR\n");
#endif
	return STDERR;
}

syslog {
	yylval.ival = SYSLOG;
#ifdef DEBUG
	printf("SYSLOG\n");
#endif
	return SYSLOG;
}

yfile {
	yylval.ival = FILENAME;
#ifdef DEBUG
	printf("FILENAME\n");
#endif
	BEGIN(CANNAME);
	return FILENAME;
}



use {
	yylval.ival = USE;
#ifdef DEBUG
	printf("USE\n");
#endif
	return USE;
}

tcp {
	yylval.ival = TCP;
#ifdef DEBUG
	printf("TCP\n");
#endif
	return TCP;
}

udp {
	yylval.ival = UDP;
#ifdef DEBUG
	printf("UDP\n");
#endif
	return UDP;
}

os {
	yylval.ival = OS;
#ifdef DEBUG
	printf("OS\n");
#endif
	return OS;
}

vma {
	yylval.ival = VMA;
#ifdef DEBUG
	printf("VMA\n");
#endif
	return VMA;
}

sdp {
	yylval.ival = SDP;
#ifdef DEBUG
	printf("SDP\n");
#endif
	return SDP;
}

sa {
	yylval.ival = SA;
#ifdef DEBUG
	printf("SA\n");
#endif
	return SA;
}

tcp_client {
	yylval.ival = TCP_CLIENT;
#ifdef DEBUG
	printf("TCP CLIENT\n");
#endif
	return TCP_CLIENT;
}

tcp_server {
	yylval.ival = TCP_SERVER;
#ifdef DEBUG
	printf("TCP SERVER\n");
#endif
	return TCP_SERVER;
}

udp_sender {
	yylval.ival = UDP_SENDER;
#ifdef DEBUG
	printf("UDP SENDER\n");
#endif
	return UDP_SENDER;
}

udp_receiver {
	yylval.ival = UDP_RECEIVER;
#ifdef DEBUG
	printf("UDP RECEIVER\n");
#endif
	return UDP_RECEIVER;
}

udp_connect {
	yylval.ival = UDP_CONNECT;
#ifdef DEBUG
	printf("UDP CONNECT\n");
#endif
	return UDP_CONNECT;
}

<CANNAME>[^ \t\n]+ {
	yylval.sval = (char *)malloc(strlen(yytext) + 1);
	strcpy(yylval.sval, yytext);
#ifdef DEBUG
	printf("NAME:%s\n",yylval.sval);
#endif
	BEGIN(0);
	return (NAME);
}

\n {
	__vma_config_line_num++;
#ifdef DEBUG
	printf("LINE\n");
#endif
	yylval.ival = LINE;
	return(LINE);
}

[#][^\n]* {
 	__vma_config_line_num++;
}

[ \t]+ {}

. {
#ifdef DEBUG
	printf("CHAR:%c\n",yytext[0]);
#endif
	return(yytext[0]);
}

%%

int yywrap ()
{
	return (1);
}

