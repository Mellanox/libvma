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


extern int main_init();
extern int main_destroy();

/*  library init function
-----------------------------------------------------------------------------
__attribute__((constructor)) causes the function to be called when
library is firsrt loaded */
int __attribute__((constructor)) sock_redirect_lib_load_constructor(void)
{
        return main_init();
}

int __attribute__((destructor)) sock_redirect_lib_load_destructor(void)
{
        return main_destroy();
}
