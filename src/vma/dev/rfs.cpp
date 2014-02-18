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


#include "vma/dev/rfs.h"
#include "vma/dev/qp_mgr.h"
#include "vma/dev/ring.h"
#include "vma/util/bullseye.h"

#define MODULE_NAME 		"rfs"


rfs::rfs(flow_tuple *flow_spec_5t, ring *p_ring, rfs_rule_filter* rule_filter /*= NULL*/):
	m_flow_tuple(rule_filter ? rule_filter->m_flow_tuple : *flow_spec_5t), m_p_ring(p_ring),
	m_p_rule_filter(rule_filter), m_n_sinks_list_entries(0), m_n_sinks_list_max_length(RFS_SINKS_LIST_DEFAULT_LEN),
	m_b_tmp_is_attached(false)
{
	m_sinks_list = new pkt_rcvr_sink*[m_n_sinks_list_max_length];

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_sinks_list == NULL) {
		rfs_logpanic("sinks list allocation failed!");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	memset(m_sinks_list, 0, sizeof(pkt_rcvr_sink*)*m_n_sinks_list_max_length);
}

rfs::~rfs()
{
	// If filter, need to detach flow only if this is the last attached rule for this specific filter group (i.e. counter == 0)
	if (m_p_rule_filter) {
		rule_filter_map_t::iterator filter_iter = m_p_rule_filter->m_map.find(m_p_rule_filter->m_key);
		if (filter_iter !=  m_p_rule_filter->m_map.end() && (m_b_tmp_is_attached == true)) {
			filter_iter->second.counter = (filter_iter->second.counter > 0 ? ((filter_iter->second.counter) - 1) : 0);
			if (filter_iter->second.counter == 0) {
				destroy_ibv_flow();
				m_p_rule_filter->m_map.erase(m_p_rule_filter->m_key);
			}
		}
	} else {
		if (m_b_tmp_is_attached) {
			destroy_ibv_flow();
		}
	}

	if (m_p_rule_filter) {
		delete m_p_rule_filter;
		m_p_rule_filter = NULL;
	}
	delete[] m_sinks_list;

	while (m_attach_flow_data_vector.size() > 0) {
		delete m_attach_flow_data_vector.back();
		m_attach_flow_data_vector.pop_back();
	}
}

bool rfs::add_sink(pkt_rcvr_sink* p_sink)
{
	uint32_t i;

	rfs_logfunc("called with sink (%p)", p_sink);

	// Check all sinks list array if already exists.
	for (i = 0; i < m_n_sinks_list_entries; ++i) {
		if (m_sinks_list[i] == p_sink) {
			rfs_logdbg("sink (%p) already registered!!!", p_sink);
			return true;
		}
	}
	if (m_n_sinks_list_entries == m_n_sinks_list_max_length) {	// Sinks list array is full
		// Reallocate a new array with double size
		uint32_t tmp_sinks_list_length = 2*m_n_sinks_list_max_length;
		pkt_rcvr_sink** tmp_sinks_list = new pkt_rcvr_sink*[tmp_sinks_list_length];

		BULLSEYE_EXCLUDE_BLOCK_START
		if (tmp_sinks_list == NULL) {
			rfs_logpanic("sinks list allocation failed!");
		}
		BULLSEYE_EXCLUDE_BLOCK_END

		memcpy(tmp_sinks_list, m_sinks_list, sizeof(pkt_rcvr_sink*)*m_n_sinks_list_max_length);
		delete[] m_sinks_list;
		m_sinks_list = tmp_sinks_list;
		m_n_sinks_list_max_length = tmp_sinks_list_length;
	}

	m_sinks_list[m_n_sinks_list_entries] = p_sink;
	++m_n_sinks_list_entries;

	rfs_logdbg("Added new sink (%p), num of sinks is now: %d", p_sink, m_n_sinks_list_entries);
	return true;
}

bool rfs::del_sink(pkt_rcvr_sink* p_sink)
{
	uint32_t i;

	rfs_logdbg("called with sink (%p)", p_sink);

	// Find and remove sink
	for (i = 0; i < m_n_sinks_list_entries; ++i) {
		if (m_sinks_list[i] == p_sink) {

			// Found the sink location to remove
			// Remove this sink from list by shrinking it and keeping it in order
			for (/*continue i*/; i < (m_n_sinks_list_entries-1); ++i) {
				m_sinks_list[i] = m_sinks_list[i+1];
			}
			m_sinks_list[i] = NULL;

			m_n_sinks_list_entries--;
			rfs_logdbg("Removed sink (%p), num of sinks is now: %d", p_sink, m_n_sinks_list_entries);

			if (m_n_sinks_list_entries == 0) {
				rfs_logdbg("rfs sinks list is now empty");
			}
			return true;
		}
	}
	rfs_logdbg("sink (%p) not found", p_sink);
	return false;
}

bool rfs::attach_flow(pkt_rcvr_sink *sink)
{
	bool ret;
	int filter_counter = 1;
	rule_filter_map_t::iterator filter_iter;

	prepare_filter_attach(filter_counter, filter_iter);

	// We also check if this is the FIRST sink so we need to call ibv_attach_flow
	if ((m_n_sinks_list_entries == 0) && (!m_b_tmp_is_attached) && (filter_counter == 1)) {
		ret = create_ibv_flow();
		filter_keep_attached(filter_iter);
	}

	if (sink) {
		ret = add_sink(sink);
	} else {
		rfs_logdbg("rfs: Attach flow was called with sink == NULL");
		ret = true;
	}

	return ret;
}

bool rfs::detach_flow(pkt_rcvr_sink *sink)
{
	bool ret = false;
	int filter_counter = 0;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (sink) {
		ret = del_sink(sink);
	} else {
		rfs_logwarn("detach_flow() was called with sink == NULL");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	prepare_filter_detach(filter_counter);

	// We also need to check if this is the LAST sink so we need to call ibv_attach_flow
	if ((m_n_sinks_list_entries == 0) && (filter_counter == 0)) {
		ret = destroy_ibv_flow();
	}

	return ret;
}

bool rfs::create_ibv_flow()
{
	for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
		attach_flow_data_t* iter = m_attach_flow_data_vector[i];
		iter->ibv_flow = vma_ibv_create_flow(iter->p_qp_mgr->get_ibv_qp(), &(iter->ibv_flow_attr));
		if (!iter->ibv_flow) {
			rfs_logerr("Create of QP flow ID failed with flow %s", m_flow_tuple.to_str()); //TODO ALEXR - Add info about QP, spec, priority into log msg
			return false;
		}
	}

	m_b_tmp_is_attached = true;
	rfs_logdbg("ibv_create_flow succeeded with flow %s", m_flow_tuple.to_str());
	return true;
}

bool rfs::destroy_ibv_flow()
{
	for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
		attach_flow_data_t* iter = m_attach_flow_data_vector[i];
		if (unlikely(!iter->ibv_flow)) {
			rfs_logdbg("Destroy of QP flow ID failed - QP flow ID that was not created. This is OK for MC same ip diff port scenario."); //TODO ALEXR - Add info about QP, spec, priority into log msg
			return false;
		}
		IF_VERBS_FAILURE(vma_ibv_destroy_flow(iter->ibv_flow)) {
			rfs_logerr("Destroy of QP flow ID failed"); //TODO ALEXR - Add info about QP, spec, priority into log msg
			return false;
		} ENDIF_VERBS_FAILURE;
	}

	m_b_tmp_is_attached = false;
	rfs_logdbg("ibv_destroy_flow succeeded with flow %s", m_flow_tuple.to_str());
	return true;
}

inline void rfs::prepare_filter_attach(int& filter_counter, rule_filter_map_t::iterator& filter_iter)
{
	// If filter flow, need to attach flow only if this is the first request for this specific group (i.e. counter == 1)
	if (!m_p_rule_filter) return;

	filter_iter = m_p_rule_filter->m_map.find(m_p_rule_filter->m_key);
	if (filter_iter == m_p_rule_filter->m_map.end()) {
		rfs_logdbg("No matching counter for filter!!!");
		return;
	}

	filter_counter = filter_iter->second.counter;
	m_b_tmp_is_attached = (filter_counter > 1) || m_b_tmp_is_attached;
}

inline void rfs::filter_keep_attached(rule_filter_map_t::iterator& filter_iter)
{
	if (!m_p_rule_filter || filter_iter == m_p_rule_filter->m_map.end()) return;

	//save all ibv_flow rules only for filter
	for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
		filter_iter->second.ibv_flows.push_back(m_attach_flow_data_vector[i]->ibv_flow);
	}
}

inline void rfs::prepare_filter_detach(int& filter_counter)
{
	// If filter, need to detach flow only if this is the last attached rule for this specific group (i.e. counter == 0)
	if (!m_p_rule_filter) return;

	rule_filter_map_t::iterator filter_iter = m_p_rule_filter->m_map.find(m_p_rule_filter->m_key);
	if (filter_iter == m_p_rule_filter->m_map.end()) {
		rfs_logdbg("No matching counter for filter!!!");
		return;
	}

	filter_counter = filter_iter->second.counter;
	//if we do not need to detach_ibv_flow, still mark this rfs as detached
	m_b_tmp_is_attached = (filter_counter == 0) && m_b_tmp_is_attached;
	if (filter_counter != 0 || filter_iter->second.ibv_flows.empty()) return;

	BULLSEYE_EXCLUDE_BLOCK_START
	if (m_attach_flow_data_vector.size() != filter_iter->second.ibv_flows.size()) {
		//sanity check for having the same number of qps on all rfs objects
		rfs_logerr("all rfs objects in the ring should have the same number of elements");
	}
	BULLSEYE_EXCLUDE_BLOCK_END

	for (size_t i = 0; i < m_attach_flow_data_vector.size(); i++) {
		BULLSEYE_EXCLUDE_BLOCK_START
		if (m_attach_flow_data_vector[i]->ibv_flow && m_attach_flow_data_vector[i]->ibv_flow != filter_iter->second.ibv_flows[i]) {
			rfs_logerr("our assumption that there should be only one rule for filter group is wrong");
		} else if (filter_iter->second.ibv_flows[i]) {
			m_attach_flow_data_vector[i]->ibv_flow = filter_iter->second.ibv_flows[i];
		}
		BULLSEYE_EXCLUDE_BLOCK_END
	}
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

const char* rfs::to_str()
{
	return m_flow_tuple.to_str();
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif
