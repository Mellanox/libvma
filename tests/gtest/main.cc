/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <getopt.h>

#include "googletest/include/gtest/gtest.h"

#include "common/tap.h"
#include "common/def.h"
#include "common/log.h"
#include "common/sys.h"


static int _set_config(int argc, char **argv);
static int _def_config(void);
static void _usage(void);

struct gtest_configure_t gtest_conf;


int main(int argc, char **argv) {
	// coverity[fun_call_w_exception]: uncaught exceptions cause nonzero exit anyway, so don't warn.
	::testing::InitGoogleTest(&argc, argv);

    char *str = getenv("GTEST_TAP");
    /* Append TAP Listener */
    if (str) {
        if (0 < strtol(str, NULL, 0)) {
            testing::TestEventListeners& listeners = testing::UnitTest::GetInstance()->listeners();
            if (1 == strtol(str, NULL, 0)) {
                delete listeners.Release(listeners.default_result_printer());
            }
            listeners.Append(new tap::TapListener());
        }
    }

    _def_config();
    _set_config(argc, argv);

    return RUN_ALL_TESTS();
}

static int _def_config(void)
{
	int rc = 0;

	memset(&gtest_conf, 0, sizeof(gtest_conf));
	gtest_conf.log_level = 4;
	gtest_conf.random_seed = time(NULL) % 32768;
	gtest_conf.client_addr.sin_family = PF_INET;
	gtest_conf.client_addr.sin_addr.s_addr = INADDR_ANY;
	gtest_conf.client_addr.sin_port = 0;
	gtest_conf.server_addr.sin_family = PF_INET;
	gtest_conf.server_addr.sin_addr.s_addr = INADDR_ANY;
	gtest_conf.server_addr.sin_port = 0;
	gtest_conf.remote_addr.sin_family = PF_INET;
	gtest_conf.remote_addr.sin_addr.s_addr = INADDR_ANY;
	gtest_conf.remote_addr.sin_port = 0;
	sys_gateway(&gtest_conf.remote_addr);
	gtest_conf.port = 55555;

	return rc;
}

static int _set_config(int argc, char **argv)
{
	int rc = 0;
	static struct option long_options[] = {
		{"addr",         required_argument, 0, 'a'},
		{"if",           required_argument, 0, 'i'},
		{"port",         required_argument, 0, 'p'},
		{"random",       required_argument, 0, 's'},
		{"debug",        required_argument, 0, 'd'},
		{"help",         no_argument,       0, 'h'},
	};
	int op;
	int option_index;

	while ((op = getopt_long(argc, argv, "a:i:p:d:h", long_options, &option_index)) != -1) {
		switch (op) {
			case 'a':
				{
					char *token1 = NULL;
					char *token2 = NULL;
					const char s[2] = ":";
					if (optarg) {
						if (optarg[0] != ':') {
							token1 = strtok(optarg, s);
							token2 = strtok(NULL, s);
						} else {
							token1 = NULL;
							token2 = strtok(optarg, s);
						}
					}

					if (token1) {
						rc = sys_get_addr(token1, &gtest_conf.client_addr);
						if (rc < 0) {
							rc = -EINVAL;
							log_fatal("Failed to resolve ip address %s\n", token1);
						}
					}
					if (token2) {
						rc = sys_get_addr(token2, &gtest_conf.server_addr);
						if (rc < 0) {
							rc = -EINVAL;
							log_fatal("Failed to resolve ip address %s\n", token2);
						}
					}
				}
				break;
			case 'i':
				{
					char *token1 = NULL;
					char *token2 = NULL;
					const char s[2] = ":";
					if (optarg) {
						if (optarg[0] != ':') {
							token1 = strtok(optarg, s);
							token2 = strtok(NULL, s);
						} else {
							token1 = NULL;
							token2 = strtok(optarg, s);
						}
					}

					if (token1) {
						rc = sys_dev2addr(token1, &gtest_conf.client_addr);
						if (rc < 0) {
							rc = -EINVAL;
							log_fatal("Failed to resolve ip address %s\n", token1);
						}
					}
					if (token2) {
						rc = sys_dev2addr(token2, &gtest_conf.server_addr);
						if (rc < 0) {
							rc = -EINVAL;
							log_fatal("Failed to resolve ip address %s\n", token2);
						}
					}
				}
				break;
			case 'p':
				errno = 0;
				gtest_conf.port = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 's':
				errno = 0;
				gtest_conf.random_seed = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'd':
				errno = 0;
				gtest_conf.log_level = strtol(optarg, NULL, 0);
				if (0 != errno) {
					rc = -EINVAL;
					log_error("Invalid option value <%s>\n", optarg);
				}
				break;
			case 'h':
				_usage();
				break;
			default:
				rc = -EINVAL;
				log_error("Unknown option <%c>\n", op);
				break;
		}
	}

	if (0 != rc) {
		_usage();
	} else {
	    srand(gtest_conf.random_seed);
	    gtest_conf.server_addr.sin_port = htons(gtest_conf.port);
		log_info("CONFIGURATION:\n");
		log_info("log level: %d\n", gtest_conf.log_level);
		log_info("seed: %d\n", gtest_conf.random_seed);
		log_info("client ip: %s\n", sys_addr2str(&gtest_conf.client_addr));
		log_info("server ip: %s\n", sys_addr2str(&gtest_conf.server_addr));
		log_info("remote ip: %s\n", sys_addr2str(&gtest_conf.remote_addr));
		log_info("port: %d\n", gtest_conf.port);
	}

	return rc;
}

static void _usage(void)
{
	printf("Usage: gtest [options]\n"
		"\t--addr,-a <ip:ip>       IP address client:server\n"
		"\t--if,-i <ip:ip>         Interface client:server\n"
		"\t--port,-p <num>         Listen/connect to port <num> (default %d).\n"
		"\t--random,-s <count>     Seed (default %d).\n"
		"\t--debug,-d <level>      Output verbose level (default: %d).\n"
		"\t--help,-h               Print help and exit\n",

		gtest_conf.port,
		gtest_conf.random_seed,
		gtest_conf.log_level);
	exit(0);
}
