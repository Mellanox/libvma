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


#ifndef VLOGGER_H
#define VLOGGER_H

#include <iostream>

using namespace std;

#include <fstream>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <vma/util/rdtsc.h>
#include "vma/util/bullseye.h"

#define TO_STR(a) TOSTR_HELPER(a)
#define TOSTR_HELPER(a) #a

#undef  MODULE_HDR
#define MODULE_HDR	 	MODULE_NAME "%d:%s() "

#undef  MODULE_HDR_INFO
#define MODULE_HDR_INFO 	MODULE_NAME "[%p]:%d:%s() "

#undef	MODULE_HDR_ENTRY
#define MODULE_HDR_ENTRY	"ENTER: "

#undef	MODULE_HDR_EXIT
#define MODULE_HDR_EXIT 	"EXIT: "

#undef	__INFO__
#define __INFO__		this

#define VLOG_PRINTF(     log_level, log_fmt, log_args...) 	vlog_printf(log_level, MODULE_HDR       log_fmt "\n",           __LINE__, __FUNCTION__, ##log_args)
#define VLOG_PRINTF_INFO(log_level, log_fmt, log_args...) 	vlog_printf(log_level, MODULE_HDR_INFO  log_fmt "\n", __INFO__, __LINE__, __FUNCTION__, ##log_args)
#define VLOG_PRINTF_ENTRY(log_level, log_fmt, log_args...)	vlog_printf(log_level, MODULE_HDR_ENTRY "%s(" log_fmt ")\n", __FUNCTION__, ##log_args)
#define VLOG_PRINTF_EXIT( log_level, log_fmt, log_args...)	vlog_printf(log_level, MODULE_HDR_EXIT  "%s() " log_fmt "\n", __FUNCTION__, ##log_args)


#define __log_panic(log_fmt, log_args...) 		do { VLOG_PRINTF(VLOG_PANIC, log_fmt, ##log_args); throw; } while (0)
#define __log_err(log_fmt, log_args...) 		do { VLOG_PRINTF(VLOG_ERROR, log_fmt, ##log_args); } while (0)
#define __log_warn(log_fmt, log_args...) 		do { VLOG_PRINTF(VLOG_WARNING, log_fmt, ##log_args); } while (0)
#define __log_info(log_fmt, log_args...) 		do { VLOG_PRINTF(VLOG_INFO, log_fmt, ##log_args); } while (0)
#define __log_dbg(log_fmt, log_args...) 		do { if (g_vlogger_level >= VLOG_DEBUG) 	VLOG_PRINTF(VLOG_DEBUG, log_fmt, ##log_args); } while (0)
#define __log_func(log_fmt, log_args...) 		do { if (g_vlogger_level >= VLOG_FUNC) 		VLOG_PRINTF(VLOG_FUNC, log_fmt, ##log_args); } while (0)
#define __log_funcall(log_fmt, log_args...) 		do { if (g_vlogger_level >= VLOG_FUNC_ALL) 	VLOG_PRINTF(VLOG_FUNC_ALL, log_fmt, ##log_args); } while (0)

#define __log_info_panic(log_fmt, log_args...) 		do { VLOG_PRINTF_INFO(VLOG_PANIC, log_fmt, ##log_args); throw; } while (0)
#define __log_info_err(log_fmt, log_args...) 		do { VLOG_PRINTF_INFO(VLOG_ERROR, log_fmt, ##log_args); } while (0)
#define __log_info_warn(log_fmt, log_args...) 		do { VLOG_PRINTF_INFO(VLOG_WARNING, log_fmt, ##log_args); } while (0)
#define __log_info_info(log_fmt, log_args...) 		do { VLOG_PRINTF_INFO(VLOG_INFO, log_fmt, ##log_args); } while (0)
#define __log_info_dbg(log_fmt, log_args...) 		do { if (g_vlogger_level >= VLOG_DEBUG) 	VLOG_PRINTF_INFO(VLOG_DEBUG, log_fmt, ##log_args); } while (0)
#define __log_info_func(log_fmt, log_args...) 		do { if (g_vlogger_level >= VLOG_FUNC) 		VLOG_PRINTF_INFO(VLOG_FUNC, log_fmt, ##log_args); } while (0)
#define __log_info_funcall(log_fmt, log_args...) 	do { if (g_vlogger_level >= VLOG_FUNC_ALL) 	VLOG_PRINTF_INFO(VLOG_FUNC_ALL, log_fmt, ##log_args); } while (0)

#define __log_entry_dbg(log_fmt, log_args...)       	do { if (g_vlogger_level >= VLOG_DEBUG) 	VLOG_PRINTF_ENTRY(VLOG_DEBUG, log_fmt, ##log_args); } while (0)
#define __log_entry_func(log_fmt, log_args...)      	do { if (g_vlogger_level >= VLOG_FUNC)		VLOG_PRINTF_ENTRY(VLOG_FUNC, log_fmt, ##log_args); } while (0)
#define __log_entry_funcall(log_fmt, log_args...)   	do { if (g_vlogger_level >= VLOG_FUNC_ALL) 	VLOG_PRINTF_ENTRY(VLOG_FUNC_ALL, log_fmt, ##log_args); } while (0)

#define __log_exit_dbg(log_fmt, log_args...)       	do { if (g_vlogger_level >= VLOG_DEBUG) 	VLOG_PRINTF_EXIT(VLOG_DEBUG, log_fmt, ##log_args); } while (0)
#define __log_exit_func(log_fmt, log_args...)      	do { if (g_vlogger_level >= VLOG_FUNC)		VLOG_PRINTF_EXIT(VLOG_FUNC, log_fmt, ##log_args); } while (0)
#define __log_exit_funcall(log_fmt, log_args...)   	do { if (g_vlogger_level >= VLOG_FUNC_ALL) 	VLOG_PRINTF_EXIT(VLOG_FUNC_ALL, log_fmt, ##log_args); } while (0)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef enum {
	VLOG_PANIC = 0,
	VLOG_ERROR,
	VLOG_WARNING,
	VLOG_INFO,
	VLOG_DEBUG,
	VLOG_FUNC,
	VLOG_FUNC_ALL
} vlog_levels_t;

#define VLOG_SINCE_YEAR 	1900
#define VLOG_MODULE_MAX_LEN 	10

#define VLOGGER_STR_COLOR_TERMINATION_STR     "\e[0m"
#define VLOGGER_STR_TERMINATION_SIZE          6

typedef void (*vma_log_cb_t)(int log_level, const char* str);

extern char         g_vlogger_module_name[VLOG_MODULE_MAX_LEN];
extern FILE*        g_vlogger_file;
extern int          g_vlogger_fd;
extern uint8_t      g_vlogger_level;
extern uint8_t*     g_p_vlogger_level;
extern uint8_t      g_vlogger_details;
extern uint8_t*     g_p_vlogger_details;
extern uint32_t     g_vlogger_usec_on_startup;
extern bool         g_vlogger_log_in_colors;
extern vma_log_cb_t g_vlogger_cb;

extern const char*	g_vlogger_level_names[];
extern const char*	g_vlogger_level_colors[];

#define vlog_func_enter()       vlog_printf(VLOG_FUNC,"ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_exit()	vlog_printf(VLOG_FUNC,"EXIT %s\n",__PRETTY_FUNCTION__);

#define vlog_func_all_enter()   vlog_printf(VLOG_FUNC_ALL,"ENTER %s\n", __PRETTY_FUNCTION__);
#define vlog_func_all_exit()    vlog_printf(VLOG_FUNC_ALL,"EXIT %s\n",__PRETTY_FUNCTION__);

pid_t gettid(void); // Check vlogger.cpp for implementation

void printf_backtrace(void);

void vlog_start(const char* log_module_name, int log_level = VLOG_INFO, const char* log_filename = NULL, int log_details = 0, bool colored_log = true);
void vlog_stop(void);

static inline uint32_t vlog_get_usec_since_start()
{
	struct timespec ts_now;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (gettime(&ts_now)) {
		printf("%s() gettime() Returned with Error (errno=%d %m)\n", __func__, errno);
		return (uint32_t)-1;
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	if (!g_vlogger_usec_on_startup) {
		g_vlogger_usec_on_startup = ts_to_usec(&ts_now);
	}

	return (ts_to_usec(&ts_now) - g_vlogger_usec_on_startup);
}

#define VLOGGER_STR_SIZE    512

static inline void vlog_printf(vlog_levels_t log_level, const char* fmt , ... )
{
	if (g_vlogger_level < log_level)
		return;

	int len = 0;
	char buf[VLOGGER_STR_SIZE];

	// Format header

	// Set color scheme
	if (g_vlogger_log_in_colors) 
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, "%s", g_vlogger_level_colors[log_level]);

	switch (g_vlogger_details) {
	case 3: // Time
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, " Time: %9.3f", ((float)vlog_get_usec_since_start())/1000);
	case 2: // Pid
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, " Pid: %5u", getpid());
	case 1: // Tid
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, " Tid: %5u", gettid());
	case 0: // Func
	default:
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, " %s %s: ", g_vlogger_module_name, g_vlogger_level_names[log_level]);
	}

	buf[len+1] = '\0';

	// Format body
	va_list ap;
	va_start(ap, fmt);
	if (fmt != NULL)
		len += vsnprintf(buf+len, VLOGGER_STR_SIZE-len, fmt, ap);
	va_end(ap);

	// Reset color scheme
	if (g_vlogger_log_in_colors) {
		// Save enough room for color code termination and EOL
	        if (len > VLOGGER_STR_SIZE - VLOGGER_STR_TERMINATION_SIZE) 
	                len = VLOGGER_STR_SIZE - VLOGGER_STR_TERMINATION_SIZE - 1;

		len += snprintf(buf+len, VLOGGER_STR_TERMINATION_SIZE, VLOGGER_STR_COLOR_TERMINATION_STR);
	}

	if (g_vlogger_cb)
	{
		g_vlogger_cb(log_level, buf);
	}
	else if (g_vlogger_file)
	{
		// Print out
		fprintf(g_vlogger_file, "%s", buf);
		fflush(g_vlogger_file);
	}
	else {
		printf("%s", buf);
	}

/*
	if (log_level <= VLOG_WARNING) {
		printf_backtrace();
	}
*/
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

static inline void vlog_print_buffer(vlog_levels_t log_level, const char* msg_header, const char* msg_tail, const char* buf_user, int buf_len)
{
	if (g_vlogger_level < log_level)
		return;

	int len = 0;
	char buf[VLOGGER_STR_SIZE];

	// Format header
	if (g_vlogger_level >= VLOG_DEBUG) {
		//vlog_time(log_level, log_msg);
		len = snprintf(buf, VLOGGER_STR_SIZE, " Tid: %11lx : %s %s: ",
			       pthread_self(), g_vlogger_module_name, g_vlogger_level_names[log_level]);
	} else {
		len = snprintf(buf, VLOGGER_STR_SIZE, "%s %s: ",
			       g_vlogger_module_name, g_vlogger_level_names[log_level]);
	}
	buf[len+1] = '\0';


	if (msg_header)
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, "%s", msg_header);

	for (int c = 0; c < buf_len && len < (VLOGGER_STR_SIZE-1-6); c++) {
		len += sprintf(buf+len, "%2.2X ", (unsigned char)buf_user[c]);
		if ((c % 8) == 7) 
			len += sprintf(buf+len, " ");
	}

	if (msg_tail)
		len += snprintf(buf+len, VLOGGER_STR_SIZE-len-1, "%s", msg_tail);

	buf[len+1] = '\0';

	// Print out
	if (g_vlogger_cb)
	{
		g_vlogger_cb(log_level, buf);
	}
	else if (g_vlogger_file)
	{
		fprintf(g_vlogger_file, "%s", buf);
		fflush(g_vlogger_file);
	}
	else
	{
		printf("%s", buf);
	}

}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

#ifdef __cplusplus
};
#endif //__cplusplus

#endif // VLOGGER_H
