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


#ifndef EVENT_H
#define EVENT_H

#include "vma/util/to_str.h"
#include <typeinfo>
#include <stdio.h>
#include <stdint.h>

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
