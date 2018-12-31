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


#ifndef STATS_DATA_READER_H
#define STATS_DATA_READER_H

#include <map>
#include "utils/lock_wrapper.h"
#include "vma/event/timer_handler.h"

typedef std::map< void*, std::pair<void*, int> > stats_read_map_t;

typedef struct {
        int size;
        void* shm_addr;
} data_addr_and_size_t;

class stats_data_reader : public timer_handler
{
        public:
                stats_data_reader();
                void    handle_timer_expired(void *ctx);
                void    register_to_timer();
                void    add_data_reader(void* local_addr, void* shm_addr, int size);
                void*   pop_data_reader(void* local_addr);

        private:
                void*  m_timer_handler;
                stats_read_map_t m_data_map;
                lock_spin m_lock_data_map;
};

#endif //STATS_DATA_READER_H
