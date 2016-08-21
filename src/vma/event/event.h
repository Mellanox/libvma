/*
 * Copyright (c) 2001-2016 Mellanox Technologies, Ltd. All rights reserved.
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


#ifndef EVENT_H
#define EVENT_H

#include <typeinfo>
#include <stdio.h>
#include <stdint.h>
#include "utils/bullseye.h"
#include "vma/util/to_str.h"

class event : public tostr  {
        public:
		enum type{
			UNKNOWN_EVENT,
			SEND_EVENT,
			DROP_EVENT
		};

		type m_type;
                event(void* notifier=NULL) : m_type(UNKNOWN_EVENT), m_notifier(notifier) {}
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
                const void* get_notifier() { return m_notifier; }
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
                virtual ~event() {};
#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif
                virtual  const std::string to_str() const
                {
                	char outstr[1024];
                	sprintf(outstr, "EVENT_TYPE=%s NOTIFIER_PTR=%llu", typeid(*this).name(), (long long unsigned int)m_notifier);
                	return std::string(outstr);
                }
#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

        private:
                void* m_notifier;

};


#endif /* EVENT_H */
