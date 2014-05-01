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


#include "vlogger.h"

#include <sys/types.h>
#include <sys/syscall.h>
#include <execinfo.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include "vma/util/utils.h"
#include "vma/util/bullseye.h"

#define VLOG_DEFAULT_MODULE_NAME "VMA"
#define VMA_LOG_CB_ENV_VAR "VMA_LOG_CB_FUNC_PTR"

char         g_vlogger_module_name[VLOG_MODULE_MAX_LEN] = VLOG_DEFAULT_MODULE_NAME;
int          g_vlogger_fd = -1;
FILE*        g_vlogger_file = NULL;
uint8_t      g_vlogger_level = VLOG_INFO;
uint8_t*     g_p_vlogger_level = NULL;
uint8_t      g_vlogger_details = 0;
uint8_t*     g_p_vlogger_details = NULL;
uint32_t     g_vlogger_usec_on_startup = 0;
bool         g_vlogger_log_in_colors = MCE_DEFAULT_LOG_COLORS;
vma_log_cb_t g_vlogger_cb = NULL;

const char* 	g_vlogger_level_names[] = {
	"PANIC  ",
	"ERROR  ",
	"WARNING",
	"INFO   ",
	"DEBUG  ",
	"FUNC   ",
	"FUNC+  "
};

const char* 	g_vlogger_level_colors[] = {
	"\e[0;31m",	/* Panic   - Red     */
	"\e[0;31m",	/* Error   - Red     */
	"\e[2;35m",	/* Warrn   - Magenta */
	"\e[0m",	/* Info    - Default */
	"\e[0m",	/* Debug   - Default */
	"\e[2m",	/* Func    - Grey    */
	"\e[2m"		/* FuncAll - Grey    */
};

pid_t gettid(void)
{
	return syscall(__NR_gettid);
}

// Credit for the C++ de-mangler go to: http://tombarta.wordpress.com/2008/08/01/c-stack-traces-with-gcc/
#include <cxxabi.h>
void printf_backtrace(void)
{
	char **backtrace_strings;
	void* backtrace_addrs[10];
	int backtrace_depth = backtrace(backtrace_addrs, 10);
	printf("[tid: %d] ------ printf_backtrace ------ \n", gettid());
	backtrace_strings = backtrace_symbols(backtrace_addrs, backtrace_depth);
	for (int i = 1; i < backtrace_depth; i++) {
#if 0
		printf("[%d] %p: %s\n", i, backtrace_addrs[i], backtrace_strings[i]);
#else
		size_t sz = 1024; // just a guess, template names will go much wider
		char *function = static_cast<char*>(malloc(sz));
		char *begin = 0, *end = 0;
		// find the parentheses and address offset surrounding the mangled name
		for (char *j = backtrace_strings[i]; *j; ++j) {
			if (*j == '(') {
				begin = j;
			}
			else if (*j == '+') {
				end = j;
			}
		}
		if (begin && end) {
			*begin++ = '\0';
			*end = '\0';
			// found our mangled name, now in [begin, end)

			int status;
			char *ret = abi::__cxa_demangle(begin, function, &sz, &status);
			if (ret) {
				// return value may be a realloc() of the input
				function = ret;
			}
			else {
				// demangling failed, just pretend it's a C function with no args
				strncpy(function, begin, sz);
				strncat(function, "()", sz);
				function[sz-1] = '\0';
			}
			//	        fprintf(out, "    %s:%s\n", stack.backtrace_strings[i], function);
			printf("[%d] %p: %s:%s\n", i, backtrace_addrs[i], backtrace_strings[i], function);
		}
		else
		{
			// didn't find the mangled name, just print the whole line
			printf("[%d] %p: %s\n", i, backtrace_addrs[i], backtrace_strings[i]);
		}
		free(function);
#endif
	}
	free(backtrace_strings);
}

////////////////////////////////////////////////////////////////////////////////
// NOTE: this function matches 'bool vma_log_set_cb_func(vma_log_cb_t log_cb)' that
// we gave customers; hence, you must not change our side without considering their side
static vma_log_cb_t vma_log_get_cb_func()
{
	vma_log_cb_t log_cb = NULL;
	const char* const CB_STR = getenv(VMA_LOG_CB_ENV_VAR);
	if (!CB_STR || !*CB_STR) return NULL;

	if (1 != sscanf(CB_STR, "%p", &log_cb)) return NULL;
	return log_cb;
}

void vlog_start(const char* log_module_name, int log_level, const char* log_filename, int log_details, bool log_in_colors)
{
	g_vlogger_file = stderr;

	g_vlogger_cb = vma_log_get_cb_func();

	strncpy(g_vlogger_module_name, log_module_name, VLOG_MODULE_MAX_LEN);

	vlog_get_usec_since_start();

	char local_log_filename[255];
	if (log_filename != NULL && strcmp(log_filename,"")) {
		sprintf(local_log_filename, "%s", log_filename);
		g_vlogger_fd = open(local_log_filename, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if (g_vlogger_fd < 0) {
			vlog_printf(VLOG_PANIC, "Failed to open logfile: %s\n",local_log_filename);
			exit(1);
		}
		g_vlogger_file = fdopen(g_vlogger_fd, "w");

		BULLSEYE_EXCLUDE_BLOCK_START
		if (g_vlogger_file == NULL) {
			g_vlogger_file = stderr;
			vlog_printf(VLOG_PANIC, "Failed to open logfile: %s\n",local_log_filename);
			exit(1);
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}

	g_vlogger_level = log_level;
	g_p_vlogger_level = &g_vlogger_level;
	g_vlogger_details = log_details;
	g_p_vlogger_details = &g_vlogger_details;


	int file_fd = fileno(g_vlogger_file);
	if (file_fd >= 0 && isatty(file_fd) && log_in_colors)
		g_vlogger_log_in_colors = log_in_colors;
}

void vlog_stop(void)
{
	// Closing logger

	// Allow only really extreme (PANIC) logs to go out
	g_vlogger_level = VLOG_PANIC;
	
	//set default module name
	strcpy(g_vlogger_module_name, VLOG_DEFAULT_MODULE_NAME);

	// Close output stream
	if(g_vlogger_file && g_vlogger_file != stderr)
		fclose(g_vlogger_file);

	//fix for using LD_PRELOAD with LBM. Unset the pointer given by the parent process, so a child could get his own pointer without issues.
	unsetenv(VMA_LOG_CB_ENV_VAR);
}

