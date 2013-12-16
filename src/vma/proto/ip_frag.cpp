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


#include "ip_frag.h"

#include <assert.h>
#include <list>
#include <vma/event/event_handler_manager.h>
#include "vma/util/bullseye.h"
#include "mem_buf_desc.h"

//#define IP_FRAG_DEBUG 1

#ifdef IP_FRAG_DEBUG
#define frag_dbg(fmt, args...) \
	vlog_printf(VLOG_WARNING, "%s:%d : " fmt "\n", __FUNCTION__, __LINE__,  ##args)
#else
#define frag_dbg(fmt, args...)
#endif

#define frag_err(fmt, args...) \
	vlog_printf(VLOG_ERROR, "%s:%d : " fmt "\n", __FUNCTION__, __LINE__,  ##args)

#define frag_panic(fmt, args...) \
	{vlog_printf(VLOG_PANIC, "%s:%d : " fmt "\n", __FUNCTION__, __LINE__,  ##args); throw;}


#ifdef IP_FRAG_DEBUG
static int debug_drop_every_n_pkt=0; // 0 - Disabled, 1/N is the number of packet dropped
static int debug_drop_index=0;       // counter

static int g_ip_frag_count_check = 0;
  #define MEMBUF_DEBUG_REF_INC(__p_desc__)		{g_ip_frag_count_check++; if (__p_desc__->n_ref_count!=0) frag_panic("REF_INC: p=%p\n", __p_desc__); __p_desc__->n_ref_count++;}
  #define MEMBUF_DEBUG_REF_DEC(__p_desc__)      	{mem_buf_desc_t* frag_list = __p_desc__; while (frag_list) { MEMBUF_DEBUG_REF_DEC_1(frag_list); frag_list = frag_list->p_next_desc; }}
  #define MEMBUF_DEBUG_REF_DEC_1(__p_desc__)		{g_ip_frag_count_check--; __p_desc__->n_ref_count--; if (__p_desc__->n_ref_count!=0) frag_panic("REF_DEC: p=%p\n", __p_desc__);}
  #define PRINT_STATISTICS()				{print_statistics();}
#else
  #define MEMBUF_DEBUG_REF_INC(__p_desc__)
  #define MEMBUF_DEBUG_REF_DEC(__p_desc__)
  #define PRINT_STATISTICS()
#endif


ip_frag_manager * g_p_ip_frag_manager = NULL;

ip_frag_hole_desc *hole_base;
ip_frag_hole_desc *hole_free_list_head = NULL;
int hole_free_list_count = 0;

ip_frag_desc *desc_base;
ip_frag_desc *desc_free_list_head = NULL;
int desc_free_list_count = 0;


ip_frag_manager::ip_frag_manager() : lock_spin("ip_frag_manager")
{
	frag_dbg("");
	m_frag_counter = 0;
	int i;

	
	frag_dbg("NOTE: ip frag periodic timer is disabled until HW supports ip frag offload");
	// g_p_event_handler_manager->register_timer_event(IP_FRAG_CLEANUP_INT, this, PERIODIC_TIMER, 0);

	frag_dbg("Created new IPFRAG MANAGER instance");
	/* allocate hole list */
	desc_base = new ip_frag_desc_t [IP_FRAG_MAX_DESC];
	BULLSEYE_EXCLUDE_BLOCK_START
	if (!desc_base) {
		frag_panic("Failed to allocate fragment list");
	}
	hole_base = new ip_frag_hole_desc [IP_FRAG_MAX_HOLES];
	if (!hole_base) {
		frag_panic("Failed to allocate fragment list");
	}
	BULLSEYE_EXCLUDE_BLOCK_END
	for (i = 0; i < IP_FRAG_MAX_DESC; i++) {
		free_frag_desc(&desc_base[i]);
	}
	for (i = 0; i < IP_FRAG_MAX_HOLES; i++) {
		free_hole_desc(&hole_base[i]);
	}
}

ip_frag_manager::~ip_frag_manager()
{

        ip_frags_list_t::iterator i;
	ip_frag_desc_t *desc;

	frag_dbg("NOTE: ip frag periodic timer is disabled until HW supports ip frag offload");
	// g_p_event_handler_manager->unregister_timer_event(this, NULL);

	lock();

	while (m_frags.size() > 0) {
		i = m_frags.begin();
		desc = i->second;
		destroy_frag_desc(desc);
		free_frag_desc(desc);
		m_frags.erase(i);
	}

	owner_desc_map_t temp_buff_map = m_return_descs;
	m_return_descs.clear();

	unlock();

	// Must call cq_mgr outside the lock to avoid ABBA deadlock
	return_buffers_to_owners(temp_buff_map);

	delete [] desc_base;
	delete [] hole_base;
	frag_dbg("Deleted IPFRAG MANAGER instance");
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage off
#endif

void ip_frag_manager::print_statistics()
{
	frag_dbg("free desc=%d, free holes=%d, map size=%d, frags=%d", desc_free_list_count, hole_free_list_count, m_frags.size(), g_ip_frag_count_check);
}

#if _BullseyeCoverage
    #pragma BullseyeCoverage on
#endif

void ip_frag_manager::free_frag(mem_buf_desc_t *frag)
{
	mem_buf_desc_t *tail;

	// There are cases that we might not have a frag list at all to release
	// This is instead of checking the pointer before all calls to free_frag()
	if (!frag)
		return;

	// Change packet size - it will force packet to be discarded
	frag->sz_data = IP_FRAG_FREED;

	// Return to owner does post_recv() which deals with linked buffers automatically
	MEMBUF_DEBUG_REF_DEC(frag);

	tail = frag;
	while (tail->p_next_desc) {
		tail = tail->p_next_desc;
	}
	tail->p_next_desc = m_return_descs[frag->p_desc_owner];
	m_return_descs[frag->p_desc_owner] = frag;

}


//FIXME: use preallocated descriptors!!! instead of malloc
ip_frag_hole_desc* ip_frag_manager::alloc_hole_desc()
{
	struct ip_frag_hole_desc *ret;
	ret = hole_free_list_head;
	if (!ret)
		return NULL;

	// unlink from hole's free list
	hole_free_list_head = ret->next;
	hole_free_list_count--;

	// clear hole struct
	ret->data_first = 0;
	ret->data_last  = 0;
	ret->next = 0;
	return ret;
}

void ip_frag_manager::free_hole_desc(struct ip_frag_hole_desc *p)
{
	// link in head of free list
	p->next = hole_free_list_head;
	hole_free_list_head = p;
	++hole_free_list_count;
}

ip_frag_desc_t *ip_frag_manager::alloc_frag_desc()
{
	ip_frag_desc_t *ret;
	ret = desc_free_list_head;
	if (!ret)
		return NULL;

	// unlink from hole's free list
	desc_free_list_head = ret->next;
	--desc_free_list_count;

	ret->next = 0;
	return ret;
}

void ip_frag_manager::free_frag_desc(ip_frag_desc_t *p)
{
	// link in head of free list
	p->next = desc_free_list_head;
	desc_free_list_head = p;
	desc_free_list_count++;
}

void ip_frag_manager::destroy_frag_desc(ip_frag_desc_t *desc)
{
	struct ip_frag_hole_desc *phole, *pphole;

	// free holes
	phole = desc->hole_list;
	while (phole) {
		pphole = phole;
		phole = phole->next;
		free_hole_desc(pphole);
	}

	// free frags
	free_frag(desc->frag_list);
}


/**
 * first fragment for given address is detected - setup
 */
ip_frag_desc_t *ip_frag_manager::new_frag_desc(ip_frag_key_t &key)
{
	ip_frag_desc_t *desc = NULL;
	struct ip_frag_hole_desc *hole = NULL;

	hole = alloc_hole_desc();
	if (!hole){
		frag_dbg("NULL hole");
		return NULL;
	}
	hole->first = IP_FRAG_NINF;
	hole->last  = IP_FRAG_INF;

	desc = alloc_frag_desc();
	if (!desc) {
		frag_dbg("NULL desc");
		free_hole_desc(hole);
		return NULL;
	}
	desc->ttl = IP_FRAG_TTL;
	desc->frag_list = 0;
	desc->hole_list = hole;
	desc->frag_counter = m_frag_counter;

	m_frags[key]  = desc;
	return desc;
}

/**
 * Complexity of the algorithm:
 * O(1) if packets are coming in order or reverse order
 * O(n^2) for random fragments, where n is number of fragments
 * returns: 0 if finished OK (if the packet is complete - put it in ret)
 * 		   -1 if finished not OK and this packet needs to be droped
 */
int ip_frag_manager::add_frag(iphdr *hdr, mem_buf_desc_t *frag, mem_buf_desc_t **ret)
{
	ip_frag_key_t key;
	ip_frags_list_t::iterator i;
	ip_frag_desc_t *desc;
	struct ip_frag_hole_desc *phole, *phole_prev;
	struct ip_frag_hole_desc *new_hole;
	uint16_t frag_off, frag_first, frag_last;
	bool more_frags;

	assert(hdr);
	assert(frag);

	key.ip_id       = hdr->id;  //id is in network order!
	key.src_ip      = hdr->saddr;
	key.dst_ip      = hdr->daddr;
	key.ipproto     = hdr->protocol;

	frag_dbg("Fragment: %d.%d.%d.%d->%d.%d.%d.%d id=%x size=%d",
		 NIPQUAD(key.src_ip),
		 NIPQUAD(key.dst_ip),
		 (int)key.ip_id, (int)ntohs(hdr->tot_len));

#ifdef IP_FRAG_DEBUG
	if (debug_drop_every_n_pkt && ((++debug_drop_index) % debug_drop_every_n_pkt == 0)) {
		frag_dbg("XXX debug force dropped XXX");
		return -1;
	}
#endif

	lock();

	MEMBUF_DEBUG_REF_INC(frag);
	PRINT_STATISTICS();

	frag_off = ntohs(hdr->frag_off);
	more_frags = frag_off & MORE_FRAGMENTS_FLAG;
	frag_first = (frag_off & FRAGMENT_OFFSET) * 8;
	frag_last = frag_first + ntohs(hdr->tot_len) - (hdr->ihl<<2) - 1; // frag starts from 0!!!
	frag_dbg("> fragment: %d-%d, %s more frags", frag_first, frag_last, more_frags?"pending":"no");

	m_frag_counter++;

	i = m_frags.find(key);

	if (i == m_frags.end()) {
		/* new fragment */
		frag_dbg("> new fragmented packet");
		desc = new_frag_desc(key);
	}
	else {
		desc = i->second;
		if ((m_frag_counter - desc->frag_counter) > IP_FRAG_SPACE) {
			// discard this packet
			frag_dbg("expiring packet fragments id=%x", i->first);
			destroy_frag_desc(desc);
			free_frag_desc(desc);
			m_frags.erase(i);
			i = m_frags.end();
			// Add new fregment
			frag_dbg("> new fragmented packet");
			desc = new_frag_desc(key);
		}
		else {
			frag_dbg("> old fragmented packet");
	}
	}
	if (desc==NULL) {
		MEMBUF_DEBUG_REF_DEC(frag);
		PRINT_STATISTICS();
		unlock();
		return -1;
	}

	//desc->last_frag_counter = m_frag_counter;

	/* 8 step reassembly algorithm as described in RFC 815 */
	//step 1
	phole_prev = 0; phole = desc->hole_list;
	while (phole) {
		//step 2 and step 3
		if (frag_first >= phole->first && frag_last <= phole->last) {
			break;
		}
		phole_prev = phole;
		phole = phole->next;
	}
	if (!phole) {   // the right hole wasn't found
		MEMBUF_DEBUG_REF_DEC(frag);
		PRINT_STATISTICS();
		unlock();
		return -1;
	}

	frag_dbg("> found hole: %d-%d", phole->first, phole->last);

	// step 4 - remove hole from list
	if (phole_prev)
		phole_prev->next = phole->next;
	else
		desc->hole_list	= phole->next;

	// step 5
	if (frag_first > phole->first) {
		new_hole                = alloc_hole_desc();
		if (!new_hole) {
			free_hole_desc(phole); // phole was removed from the list in step 4!
			MEMBUF_DEBUG_REF_DEC(frag);
			PRINT_STATISTICS();
			unlock();
			return -1;
		}
		new_hole->first         = phole->first;
		new_hole->last          = frag_first-1;
		new_hole->data_first    = phole->data_first;
		new_hole->data_last     = frag;

		new_hole->next = phole->next;
		if (phole_prev)
			phole_prev->next = new_hole;
		else
			desc->hole_list	= new_hole;

		phole_prev = new_hole;
	}

	//step 6
	if (frag_last < phole->last && more_frags) {
		new_hole                = alloc_hole_desc();
		if (!new_hole) {
			free_hole_desc(phole);  // phole was removed from the list in step 4!
			MEMBUF_DEBUG_REF_DEC(frag);
			PRINT_STATISTICS();
			unlock();
			return -1;
		}

		new_hole->first         = frag_last + 1;
		new_hole->last          = phole->last;
		new_hole->data_first    = frag;
		new_hole->data_last     = phole->data_last;

		new_hole->next = phole->next;
		if (phole_prev)
			phole_prev->next = new_hole;
		else
			desc->hole_list	= new_hole;
	}

	// link frag
	if (phole->data_first)
		phole->data_first->p_next_desc = frag;
	else
		desc->frag_list	= frag;
	frag->p_next_desc = phole->data_last;

	free_hole_desc(phole);

	if (!desc->hole_list) {
		//step 8 - datagram assembly completed
		if (i == m_frags.end())
			i = m_frags.find(key);
		if (i == m_frags.end()){
			MEMBUF_DEBUG_REF_DEC(frag);
			frag_panic("frag desc lost from map???");
			//coverity unreachable
			/*unlock();
			return -1;*/
		}
		MEMBUF_DEBUG_REF_DEC(desc->frag_list);
		m_frags.erase(i);
		*ret = desc->frag_list;
		free_frag_desc(desc);
		frag_dbg("> PACKET ASSEMBLED");
		PRINT_STATISTICS();
		unlock();
		return 0;
	}
	frag_dbg("> need more packets");

	*ret = NULL;
	PRINT_STATISTICS();
	unlock();
	return 0;
}

void ip_frag_manager::return_buffers_to_owners(const owner_desc_map_t &buff_map)
{
	// Assume locked !!!
	owner_desc_map_t::const_iterator iter;

	for (iter = buff_map.begin(); iter != buff_map.end(); ++iter) {
		if(g_buffer_pool_rx)
			g_buffer_pool_rx->put_buffers_thread_safe(iter->second);
	}
}


void ip_frag_manager::handle_timer_expired(void* user_data)
{
	NOT_IN_USE(user_data);
	ip_frags_list_t::iterator iter, iter_temp;
	ip_frag_desc_t *desc;
	uint64_t delta =0;

	lock();
	if (m_frag_counter > IP_FRAG_SPACE) {
		delta = m_frag_counter - IP_FRAG_SPACE;
		m_frag_counter -= delta;
	}

	frag_dbg("calling handle_timer_expired, m_frag_counter=%ld, delta=%ld", m_frag_counter, delta);
	PRINT_STATISTICS();

	iter = m_frags.begin();
	while (iter != m_frags.end()) {
		desc = iter->second;
		desc->frag_counter -= delta;
		if (desc->frag_counter<0 || (desc->ttl <= 0)) {	//discard this packet
			frag_dbg("expiring packet fragments desc=%p (frag_counter=%d, ttl=%d)", desc, desc->frag_counter, desc->ttl);
			destroy_frag_desc(desc);
			free_frag_desc(desc);
			iter_temp = iter++;
			m_frags.erase(iter_temp);
		}
		else {
			iter++;
		}

		--desc->ttl;
	}

	owner_desc_map_t temp_buff_map = m_return_descs;
	m_return_descs.clear();

	PRINT_STATISTICS();
	unlock();

	// Must call cq_mgr outside the lock to avoid ABBA deadlock
	return_buffers_to_owners(temp_buff_map);
}

