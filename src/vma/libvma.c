/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */


extern int vma_init(void);
extern int vma_exit(void);

int __attribute__((constructor)) sock_redirect_lib_load_constructor(void)
{
        return vma_init();
}

int __attribute__((destructor)) sock_redirect_lib_load_destructor(void)
{
        return vma_exit();
}
