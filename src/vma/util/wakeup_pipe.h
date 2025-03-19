/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


#ifndef WAKEUP_PIPE_H
#define WAKEUP_PIPE_H

/**
 * wakeup class that adds a wakeup functionality to socket (tcp and udp) and epoll using a pipe.
 */
#include "wakeup.h"
#include "utils/atomic.h"

class wakeup_pipe : public wakeup
{
public:
	wakeup_pipe(void);
	~wakeup_pipe();
	virtual void do_wakeup();
	virtual inline bool is_wakeup_fd(int fd)
	{
		return fd == g_wakeup_pipes[0];
	};
	virtual void remove_wakeup_fd();

private:
	static int g_wakeup_pipes[2];
	static atomic_t ref_count;
};

#endif /* WAKEUP_PIPE_H */
