/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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


#include <vlogger/vlogger.h>
#include <stdio.h>
#include <stdlib.h>
#include "sm.h"
#include "sm_fifo.h"
#include <string.h>

#define MODULE_NAME			"SM_TEST: "

#define NOT_IN_USE(a)                   ((void)(a))

/* SM example */

typedef enum {
	SM_ST_A = 0,
	SM_ST_B,
	SM_ST_C,
	SM_ST_LAST
} sm_state_e;



typedef enum {
	SM_EV_1 = 0,
	SM_EV_2,
	SM_EV_3,
	SM_EV_4,
	SM_EV_LAST
} sm_event_e;

// Debug functions  definitions
const char *state_num_to_str_func(int state);
const char* event_num_to_str_func(int event);
void  print_event_info(int state, int event, void* app_hndl);

void sm_st_entry(const sm_info_t& info);
void sm_st_leave(const sm_info_t& info);
void sm_st_A_ev_1(const sm_info_t& info);
void sm_st_A_ev_2(const sm_info_t& info);
void sm_st_A_ev_3(const sm_info_t& info);
void sm_st_B_ev_1(const sm_info_t& info);
void sm_st_B_ev_2(const sm_info_t& info);
void sm_st_B_ev_3(const sm_info_t& info);
void sm_st_C_ev_1(const sm_info_t& info);
void sm_st_C_ev_2(const sm_info_t& info);
void sm_st_C_ev_3(const sm_info_t& info);

void sm_default_trans_func(const sm_info_t& info);


//// The short table
sm_short_table_line_t sm_short_table[] = {
// 	{curr state,	event, 		next state,	action func  }
	{ SM_ST_A,      SM_STATE_ENTRY, SM_NO_ST,       sm_st_entry}, 
	{ SM_ST_A,      SM_EV_1,        SM_ST_A,        sm_st_A_ev_1}, 
	{ SM_ST_A,      SM_EV_2,        SM_ST_B,sm_st_A_ev_2}, 
	{ SM_ST_A,      SM_EV_3,        SM_ST_C,       sm_st_A_ev_3}, 
	{ SM_ST_A,      SM_STATE_LEAVE, SM_NO_ST,      sm_st_leave}, 

	{ SM_ST_B,      SM_STATE_ENTRY, SM_NO_ST,      sm_st_entry}, 
	{ SM_ST_B,      SM_EV_1,        SM_ST_B,       sm_st_B_ev_1}, 
	{ SM_ST_B,      SM_EV_2,        SM_ST_C,       sm_st_B_ev_2}, 
	{ SM_ST_B,      SM_EV_3,        SM_ST_A,       sm_st_B_ev_3}, 
	{ SM_ST_B,      SM_STATE_LEAVE, SM_NO_ST,      sm_st_leave}, 

	{ SM_ST_C,      SM_STATE_ENTRY, SM_NO_ST,      sm_st_entry}, 
	{ SM_ST_C,      SM_EV_1,        SM_ST_C,       sm_st_C_ev_1}, 
	{ SM_ST_C,      SM_EV_2,        SM_ST_A,       sm_st_C_ev_2}, 
	{ SM_ST_C,      SM_EV_3,        SM_ST_B,       sm_st_C_ev_3},
	{ SM_ST_C,      SM_STATE_LEAVE, SM_NO_ST,      sm_st_leave},

	SM_TABLE_END
};

#if 0

typedef struct {
	int  event;             
	char* name;
} test_entry;

void fifo_test()
{
	sm_fifo my_fifo;
	int i=0;
	fifo_entry_t ret;

	test_entry arr_num[] = {
		{1, "one"},
		{2, "two"},
		{3, "three"},
		{4, "four"},
		{5, "five"},
		{6, "six"},
		{7, "seven"},
		{8, "eight"},
		{9, "nine"},
		{10,"ten"}
	};


	vlog_printf(VLOG_INFO, "fifo test\n");

	while (i<10) {
		my_fifo.push_back(arr_num[i].event, (void *) arr_num[i].name );
		vlog_printf(VLOG_ERROR, "element %d was inserted\n", arr_num[i]);
		my_fifo.debug_print_fifo();
		ret = my_fifo.get_front();
		vlog_printf(VLOG_ERROR, "element %d was removed (%s)\n", ret.event, ret.ev_data);
		my_fifo.debug_print_fifo();
		i++;
	}
	/*while (i>0) {
			ret = my_fifo.get_element();
			vlog_printf(VLOG_ERROR, "element %d was removeded\n", ret);
			my_fifo.debug_print_fifo();
			i--;
	}*/
}

#endif


#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif


state_machine* g_sm;

int main(int argc, char *argv[])
{
	vlog_levels_t log_level = VLOG_DETAILS;

	if (argc > 1) {
		log_level = log_level::from_str(argv[1], VLOG_INIT);
		if (log_level == VLOG_INIT ) {
			printf("illegal log level %s\n", argv[1]);
			return -1;
		}
	}
	vlog_start("SM_TEST", log_level, NULL, 0);
	//fifo_test();

	g_sm = new state_machine(NULL,
				 SM_ST_A,
				 SM_ST_LAST, 
				 SM_EV_LAST, 
				 sm_short_table, 
				 sm_default_trans_func, 
				 NULL, 
				 NULL,
				 print_event_info);

	g_sm->process_event(SM_EV_2,(void *)"event 2");

	delete g_sm;
}



//// Debug functions  definitions
const char* state_num_to_str_func(int state)
{
	switch (state) {
	case SM_ST_A:
		return "SM_ST_A";
	case SM_ST_B:
		return "SM_ST_B";
	case SM_ST_C:
		return "SM_ST_C";
	default:
		return "Undefined";
	} 

}

const char* event_num_to_str_func(int event)
{
	switch (event) {
	case SM_EV_1:
		return "SM_EV_1";
	case SM_EV_2:
		return "SM_EV_2";
	case SM_EV_3:
		return "SM_EV_3";
	case SM_EV_4:
		return "SM_EV_4";
	default:
		return "Undefined";
	} 
}

void print_event_info(int state, int event, void* app_hndl)
{
	NOT_IN_USE(app_hndl);
	printf(MODULE_NAME "Got event %s (%d) in state %s (%d)\n", 
	       event_num_to_str_func(event), event, state_num_to_str_func(state), state);
}

////////////////////////////////////////
// SM Entry Function       
void sm_st_entry(const sm_info_t& info)
{
	printf(MODULE_NAME "State changed %s (%d) => %s (%d)\n", 
	       state_num_to_str_func(info.old_state), info.old_state, 
	       state_num_to_str_func(info.new_state), info.new_state);
}

////////////////////////////////////////
// SM Leave Function
void sm_st_leave(const sm_info_t& info)
{
	printf(MODULE_NAME "State changing %s (%d) => %s (%d)\n", 
	       state_num_to_str_func(info.old_state), info.old_state, 
	       state_num_to_str_func(info.new_state), info.new_state);
}

////////////////////////////////////////
// SM Transition Functions                                        
void sm_default_trans_func(const sm_info_t& info)
{
	printf(MODULE_NAME "Default Transition: Handle event %s (%d) in state %s (%d)\n",
	       event_num_to_str_func(info.event), info.event,
	       state_num_to_str_func(info.old_state), info.old_state);
	if (info.new_state != SM_ST_STAY) {
		printf(MODULE_NAME "Default Transition: Moving to state %s (%d)\n", state_num_to_str_func(info.new_state), info.new_state);

	}
}

void sm_st_A_ev_1(const sm_info_t& info)
{
	printf(MODULE_NAME "Got event %s in state A\n", (char*)info.ev_data);
}

void sm_st_A_ev_2(const sm_info_t& info)
{
	printf(MODULE_NAME "Got event %s in state A\n", (char*)info.ev_data);
	g_sm->process_event(SM_EV_4, (void*)"event 4"); 
	g_sm->process_event(SM_EV_1, (void*)"event 1"); 
	g_sm->process_event(SM_EV_2, (void*)"event 2"); 
	g_sm->process_event(SM_EV_3, (void*)"event 3"); 
	g_sm->process_event(SM_EV_4, (void*)"event 4"); 
	//g_sm->m_sm_fifo.debug_print_fifo();
}

void sm_st_A_ev_3(const sm_info_t& info)
{
	printf(MODULE_NAME "Got event %s\n", (char*)info.ev_data);
}

void sm_st_B_ev_1(const sm_info_t& info)
{
	NOT_IN_USE(info);
	printf(MODULE_NAME "Got event %s\n", event_num_to_str_func(SM_EV_1));
}

void sm_st_B_ev_2(const sm_info_t& info)
{
	printf(MODULE_NAME "Got event %s\n", (char*)info.ev_data);
	g_sm->process_event(SM_EV_1, (void*)"event 1");   
}

void sm_st_B_ev_3(const sm_info_t& info)
{
	NOT_IN_USE(info);
	printf(MODULE_NAME "Got event %s\n", event_num_to_str_func(SM_EV_3));
}

void sm_st_C_ev_1(const sm_info_t& info)
{
	NOT_IN_USE(info);
	printf(MODULE_NAME "Got event %s\n", event_num_to_str_func(SM_EV_1));
}

void sm_st_C_ev_2(const sm_info_t& info)
{
	NOT_IN_USE(info);
	printf(MODULE_NAME "Got event %s\n", event_num_to_str_func(SM_EV_2));
	g_sm->process_event(SM_EV_4, (void*)"event 4");   
}

void sm_st_C_ev_3(const sm_info_t& info)
{
	NOT_IN_USE(info);
	printf(MODULE_NAME "Got event %s\n", event_num_to_str_func(SM_EV_3));
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
