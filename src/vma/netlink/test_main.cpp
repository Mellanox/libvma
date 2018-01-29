/*
 * Copyright (c) 2001-2018 Mellanox Technologies, Ltd. All rights reserved.
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


#include "vma/infra/subject_observer.h"
#include "netlink_wrapper.h"
#include "neigh_info.h"
#include <stdio.h>
#include "errno.h"
#include <sys/epoll.h>
#include "vlogger/vlogger.h"
#include "vma/event/netlink_event.h"

extern uint8_t      g_vlogger_level;
#define MODULE_NAME "NETLINK_TEST"

class neigh_observer : public observer {
	virtual void 		notify_cb(event * ev) {
		if (ev) {
/*
			neigh_nl_event* net_ev = dynamic_cast <neigh_nl_event*> (ev);
			if (net_ev->neigh_dst_addr_str == "1.1.1.12") {
			//__log_info("!!! IN neigh_observer !!!");
				__log_info("%s", ev->to_str().c_str());
			}
*/
			__log_info("!!! IN neigh_observer !!!");
			neigh_nl_event* nlev = dynamic_cast<neigh_nl_event*>(ev);
			__log_info("%s", ev->to_str().c_str());
			netlink_neigh_info info;
			g_p_netlink_handler->get_neigh("1.1.1.1", 1, &info);
			__log_info("AFTER get_neigh");
			__log_info("NEIGH STATE=%s", nlev->get_neigh_info()->get_state2str().c_str());
		}
	}
};


class route_observer : public observer {
	virtual void 		notify_cb(event * ev) {
		if (ev) {
			__log_info("!!! IN route_observer !!!");
			//route_nl_event* nlev = dynamic_cast<route_nl_event*>(ev);
			__log_info("%s", ev->to_str().c_str());
		}
	}
};

class link_observer : public observer {
	virtual void 		notify_cb(event * ev) {
		if (ev) {
			__log_info("!!! IN link_observer !!!");
			__log_info("%s", ev->to_str().c_str());
		}
	}
};



void netlink_test()
{
	g_vlogger_level=3;
	netlink_wrapper* nl = new netlink_wrapper();
	g_p_netlink_handler=nl;
	neigh_observer neigh_obs;
	route_observer route_obs;
	link_observer link_obs;
	nl->register_event(nlgrpNEIGH, &neigh_obs);
	//nl->register_event(nlgrpROUTE, &route_obs);
	//nl->register_event(nlgrpLINK, &link_obs);
	int nevents;
	struct epoll_event events[32];

	if (nl->open_channel())	{
		printf("fail to open nl channel\n");
		exit(-1);
	}

	int fd = nl->get_channel();

	if (fd < 0) {
		printf("netlink channel is illegal\n");
		exit(-1);
	}
	int epfd = epoll_create(10);


	struct epoll_event* e = new struct epoll_event();
	e->data.fd=fd;
	e->data.ptr=NULL;
	e->events=EPOLLIN | EPOLLET;
	epoll_ctl(epfd, EPOLL_CTL_ADD, fd, e);

//	netlink_neigh_info* neigh_info = new netlink_neigh_info();
//	printf("GOING TO NIEGH QUERY\n");
//	int rc = nl->get_neigh("172.30.20.111", 1, neigh_info);
//	if (rc == 1) {
//		printf("NIEGH QUERY is:\n");
//		printf("NEIGH: ip=%s, lladdr=%s, state=%s\n", neigh_info->dst_addr_str.c_str(), neigh_info->lladdr_str.c_str(), neigh_info->get_state2str().c_str());
//		printf("NIEGH QUERY done\n");
//	}
//	else {
//		printf("NO NIEGH QUERY, rc=%d\n", rc);
//	}
//
	while (1) {

		/* Poll events from both main threads and the event channel */

		nevents =  epoll_wait(epfd, events,
				sizeof(events) / sizeof(events[0]), 2000);

		if (nevents < 0) {
			if (errno != EINTR) {
				printf("epoll_wait errno=%m\n");
			}
		} else if (nevents) {
			printf("*** --> going to handle events (n=%d)\n", nevents);
			nl->handle_events();
			printf("*** <-- handle events\n");
		}
	}
	printf("-------->>>>> event_processor thread stopped <<<<<--------");
	exit(1);
}


int main(int argc, char* argv[])
{
	g_vlogger_level = 3;
	if (argv && argc > 1) {
		int tracelevel = atoi(argv[1]);
		if (tracelevel > 0 && tracelevel <= 5)
			g_vlogger_level = tracelevel;
	}
	netlink_test();
	return 0;
}

