/*
 * Copyright (c) 2001-2019 Mellanox Technologies, Ltd. All rights reserved.
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#if HAVE_SYS_PRCTL_H
#  include <sys/prctl.h>
#endif

#include "hash.h"
#include "tc.h"
#include "daemon.h"


extern int proc_loop(void);

static void handle_signal(int signo);
static void daemonize(void);
static int config_def(void);
static int config_set(int argc, char **argv);
static void usage(void);

struct module_cfg daemon_cfg;

int main(int argc, char *argv[])
{
	int rc = 0;

	/* Setup syslog logging */
	openlog(MODULE_NAME, LOG_PID, LOG_LOCAL5);

	/* already a daemon */
	if (getppid() == 1) {
		return 0;
	}

	/* command line parsing... */
	config_def();
	log_info("Starting\n");

	config_set(argc, argv);

	/* Daemonize */
	if (0 == daemon_cfg.opt.mode) {
		daemonize();
	}

	/* Change the file mode mask */
	umask(0);

	/* Set name of the process */
#if HAVE_SYS_PRCTL_H
	if (prctl(PR_SET_NAME, MODULE_NAME, NULL, NULL, NULL) < 0) {
		log_error("cannot set process name to %s, errno=%d (%s)\n",
				MODULE_NAME, errno, strerror(errno));
		goto err;
	}
#endif

	/* Ensure only one copy */
	if (daemon_cfg.lock_file[0]) {
		char str[10];

		daemon_cfg.lock_fd = open(daemon_cfg.lock_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
		if (daemon_cfg.lock_fd < 0) {
			log_error("could not open PID lock file %s, errno=%d (%s)\n",
					daemon_cfg.lock_file, errno, strerror(errno));
			goto err;
		}

		if (lockf(daemon_cfg.lock_fd, F_TLOCK, 0) < 0) {
			log_error("could not lock PID lock file %s, errno=%d (%s)\n",
					daemon_cfg.lock_file, errno, strerror(errno));
			goto err;
		}

		/* Write pid to lockfile */
		sprintf(str,"%d\n", getpid());
		if (write(daemon_cfg.lock_fd, str, strlen(str)) < 0) {
			log_error("could not write to PID lock file %s, errno=%d (%s)\n",
					daemon_cfg.lock_file, errno, strerror(errno));
			goto err;
		}
	}

	/* Main loop */
	rc = proc_loop();

	/* Finish up */
	close(daemon_cfg.lock_fd);
	unlink(daemon_cfg.lock_file);

	log_info("Terminated with code %d\n", rc);
	closelog();

	return (rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
err:
	return EXIT_FAILURE;
}

static void handle_signal(int signo)
{
	log_debug("Getting signal (%d)\n", signo);

	switch (signo) {
	case SIGALRM:
	case SIGCHLD:
	case SIGUSR1:
		daemon_cfg.sig = SIGUSR1;
		_exit(EXIT_SUCCESS);
		break;
	default:
		daemon_cfg.sig = signo;
		return;
	}
}

static void daemonize(void)
{
	struct sigaction sa;
	pid_t pid, sid, parent;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		log_error("unable to fork daemon, code=%d (%s)\n", errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}
	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {

		/* Setup signal handling before we start */
		sa.sa_handler = &handle_signal;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		if (sigaction(SIGUSR1, &sa, NULL) < 0) {
			log_error("cannot register SIGUSR1 signal handler, errno=%d (%s)\n",
					errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (sigaction(SIGCHLD, &sa, NULL) < 0) {
			log_error("cannot register SIGCHLD signal handler, errno=%d (%s)\n",
					errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (sigaction(SIGALRM, &sa, NULL) < 0) {
			log_error("cannot register SIGALRM signal handler, errno=%d (%s)\n",
					errno, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Wait for confirmation from the child via SIGTERM or SIGCHLD, or
		 * for two seconds to elapse (SIGALRM).
		 * pause() should not return.
		 */
		alarm(2);
		pause();
		exit(EXIT_FAILURE);
	}

	/* At this point we are executing as the child process */
	parent = getppid();

	/* Cancel certain signals */
	signal(SIGTSTP, SIG_IGN); /* Various TTY signals */
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_DFL); /* A child process dies */
	signal(SIGTERM, SIG_DFL); /* Die on SIGTERM */

	/* Setup signal handling before we start */
	sa.sa_handler = &handle_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		log_error("cannot register SIGINT signal handler, errno=%d (%s)\n",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		log_error("unable to create a new session, errno %d (%s)\n", errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		log_error("unable to change directory to %s, errno %d (%s)\n", "/",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Redirect standard files to /dev/null */
	if (NULL == freopen("/dev/null", "r", stdin)) {
		log_error("unable redirect stdin, errno %d (%s)\n",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (NULL == freopen("/dev/null", "w", stdout)) {
		log_error("unable redirect stdout, errno %d (%s)\n",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (NULL == freopen("/dev/null", "w", stderr)) {
		log_error("unable redirect stderr, errno %d (%s)\n",
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Send a signal to the parent to it can terminate. */
	kill(parent, SIGUSR1);
}

static int config_def(void)
{
	int rc = 0;

	memset(&daemon_cfg, 0, sizeof(daemon_cfg));

	daemon_cfg.opt.mode = 0;
	daemon_cfg.opt.log_level = 4;
	daemon_cfg.opt.max_pid_num = PID_MAX;
	daemon_cfg.opt.max_fid_num = FID_MAX;
	daemon_cfg.opt.force_rst = 0;
	daemon_cfg.opt.retry_interval = 1000;


	daemon_cfg.lock_file = "/var/lock/" MODULE_NAME ".lock";
	daemon_cfg.lock_fd = -1;
	daemon_cfg.sock_file = VMA_AGENT_ADDR;
	daemon_cfg.sock_fd = -1;
	daemon_cfg.sig = 0;
	daemon_cfg.raw_fd = -1;
	daemon_cfg.notify_fd = -1;
	daemon_cfg.notify_dir = VMA_AGENT_PATH;
	daemon_cfg.ht = NULL;
	daemon_cfg.tc = NULL;

	return rc;
}

static int config_set(int argc, char **argv)
{
	int rc = 0;
	static struct option long_options[] = {
		{"console",        no_argument,       &daemon_cfg.opt.mode,           1},
		{"notify-dir",     required_argument, 0,                              'n'},
		{"verbose",        required_argument, 0,                              'v'},
		{"pid",            required_argument, 0,                              'p'},
		{"fid",            required_argument, 0,                              'f'},
		{"force-rst",      no_argument,       &daemon_cfg.opt.force_rst,      1},
		{"retry-interval", required_argument, &daemon_cfg.opt.retry_interval, 'r'},
		{"help",           no_argument,       0,                              'h'},
		{ 0, 0, 0, 0 }
	};
	int op;
	int option_index;

	while ((op = getopt_long(argc, argv, "v:n:p:f:r:h", long_options, &option_index)) != -1) {
		switch (op) {
			case 'v':
				errno = 0;
				daemon_cfg.opt.log_level = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
				}
				break;
			case 'n':
				errno = 0;
				daemon_cfg.notify_dir = optarg;
				if (0 != errno) {
					rc = -EINVAL;
				}
				break;
			case 'p':
				errno = 0;
				daemon_cfg.opt.max_pid_num = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
				}
				break;
			case 'f':
				errno = 0;
				daemon_cfg.opt.max_fid_num = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
				}
				break;
			case 'r':
				errno = 0;
				daemon_cfg.opt.retry_interval = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
				}
				break;
			case 'h':
				usage();
				break;
			case 0:
				/* getopt_long() set a variable, just keep going */
				break;
			case ':':
			case '?':
			default:
				rc = -EINVAL;
				break;
		}
	}

	log_debug("CONFIGURATION:\n");
	log_debug("package version: %s\n", PACKAGE_VERSION);
	log_debug("mode: %d\n", daemon_cfg.opt.mode);
	log_debug("log level: %d\n", daemon_cfg.opt.log_level);
	log_debug("max pid: %d\n", daemon_cfg.opt.max_pid_num);
	log_debug("max fid: %d\n", daemon_cfg.opt.max_fid_num);
	log_debug("force rst: %d\n", daemon_cfg.opt.force_rst);
	log_debug("retry interval: %d ms \n", daemon_cfg.opt.retry_interval);
	log_debug("lock file: %s\n", daemon_cfg.lock_file);
	log_debug("sock file: %s\n", daemon_cfg.sock_file);
	log_debug("notify dir: %s\n", daemon_cfg.notify_dir);
	log_debug("format version: 0x%X\n", VMA_AGENT_VER);

	if (0 != rc) {
		usage();
	}

	return rc;
}

static void usage(void)
{
	printf(MODULE_NAME " is a part of Mellanox's Messaging Accelerator (VMA) product\n"
		"that boosts performance for message-based and streaming applications.\n");
	printf("version: %s (0x%X)\n\n", PACKAGE_VERSION, VMA_AGENT_VER);

	printf("Usage: " MODULE_NAME " [options]\n"
		"\t--console                       Enable foreground mode (default: %s)\n"
		"\t--notify-dir                    Sets the outout dir used by vmad (default: %s)\n"
		"\t--pid,-p <num>                  Set prime number as maximum of processes per node. (default: %d).\n"
		"\t--fid,-f <num>                  Set prime number as maximum of sockets per process. (default: %d).\n"
		"\t--force-rst                     Force internal RST. (default: %s).\n"
		"\t--verbose,-v <level>            Output verbose level (default: %d).\n"
		"\t--retry-interval,-r <num>       Set SYN pkt retry interval in [ms] (default: %d).\n"
		"\t--help,-h                       Print help and exit\n",
			(daemon_cfg.opt.mode ? "on" : "off"),
			VMA_AGENT_PATH,
			daemon_cfg.opt.max_pid_num,
			daemon_cfg.opt.max_fid_num,
			(daemon_cfg.opt.force_rst ? "on" : "off"),
			daemon_cfg.opt.log_level,
			daemon_cfg.opt.retry_interval);

	exit(EXIT_SUCCESS);
}


void sys_log(int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (0 == daemon_cfg.opt.mode) {
		vsyslog(level, format, args);
	} else {
		vprintf(format, args);
	}
	va_end(args);
}

ssize_t sys_sendto(int sockfd,
		const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	char *data = (char *)buf;
	int n, nb;

	nb = 0;
	do {
		n = sendto(sockfd, data, len, flags, dest_addr, addrlen);
		if (n <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (flags & MSG_DONTWAIT) {
					break;
				}
				continue;
			}
			return -errno;
		}
		len -= n;
		data += n;
		nb += n;
	} while (!(flags & MSG_DONTWAIT) && (len > 0));

	return nb;
}

char *sys_exec(const char * format, ...)
{
	static __thread char outbuf[256];
	FILE *file = NULL;
	va_list va;
	char *cmd;
	int ret;

	/* calculate needed size for command buffer */
	va_start(va, format);
	ret = vsnprintf(NULL, 0, format, va);
	va_end(va);
	if (ret <= 0) {
		goto err;
	}

	/* allocate command buffer */
	ret += 1;
	cmd = malloc(ret);
	if (NULL == cmd) {
		goto err;
	}

	/* fill command buffer */
	va_start(va, format);
	ret = vsnprintf(cmd, ret, format, va);
	va_end(va);
	if (ret <= 0) {
		free(cmd);
		goto err;
	}

	/* execute command */
	file = popen(cmd, "r");
	log_trace("Run command: %s\n", cmd);
	free(cmd);
	if (NULL == file) {
		goto err;
	}

	/* save output */
	memset(outbuf, 0, sizeof(outbuf));
	if ((NULL == fgets(outbuf, sizeof(outbuf) - 1, file)) && (ferror(file))) {
		pclose(file);
		goto err;
	}
	pclose(file);

	return outbuf;
err:
	return NULL;
}
