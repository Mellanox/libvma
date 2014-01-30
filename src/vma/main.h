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


#ifndef MAIN_H
#define MAIN_H

#include <vma/util/vtypes.h>
#include <vma/util/sys_vars.h>
#include <vma/util/utils.h>
#include <vma/sock/sock-redirect.h>

void print_vma_global_settings();
void check_locked_mem();
void get_env_params();
void set_env_params();
void prepare_fork();

extern "C" void sock_redirect_main(void);
extern "C" void sock_redirect_exit(void);

extern bool g_init_ibv_fork_done;

#endif //MAIN_H
