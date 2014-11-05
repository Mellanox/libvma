/* OPTIONAL: Pools to replace heap allocation
 * Optional: Pools can be used instead of the heap for mem_malloc. If
 * so, these should be defined here, in increasing order according to
 * the pool element size.
 *
 * LWIP_MALLOC_MEMPOOL(number_elements, element_size)
 */
#if MEM_USE_POOLS
/*
#ifndef CUSTOM_POOL_SIZE
// was 1544: we had to increase it to support tot_len in pbuf of 32 bit (instead of 16); TODO: try optimize size!
#define CUSTOM_POOL_SIZE 1552
#define CUSTOM_POOL_NUM  130000
#define CUSTOM_POOL_NAME MEMP_POOL_##CUSTOM_POOL_SIZE
LWIP_MALLOC_MEMPOOL_START
LWIP_MALLOC_MEMPOOL(CUSTOM_POOL_NUM, CUSTOM_POOL_SIZE)
LWIP_MALLOC_MEMPOOL_END
#endif
*/
#ifndef CUSTOM_POOL_SIZE
#define CUSTOM_POOL_SIZE 0
#define CUSTOM_POOL_NUM  0
#define CUSTOM_POOL_NAME MEMP_POOL_##CUSTOM_POOL_SIZE
#endif
LWIP_MALLOC_MEMPOOL_START
LWIP_MALLOC_MEMPOOL(CUSTOM_POOL_NUM, CUSTOM_POOL_SIZE)
LWIP_MALLOC_MEMPOOL_END
#endif /* MEM_USE_POOLS */


