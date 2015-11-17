/*
 * rte_persistent.c
 *
 *  Created on: Jun 23, 2015
 *      Author: leeopop
 */

#include <rte_persistent_mem.h>
#include <rte_persistent.h>
#include <rte_hash.h>
#include <rte_memory.h>

#include <memory.h>
#include <string.h>
#include <rte_common.h>
#include <rte_random.h>
#include <rte_log.h>
#include <assert.h>

#define ALLOC_UNIT RTE_PGSIZE_4K
#define MAX_CONT_MEMORY RTE_EAL_PERSISTENT_MEM_UNIT
#define MAX_ALLOC_COUNT (RTE_EAL_PERSISTENT_MEM_COUNT*(RTE_EAL_PERSISTENT_MEM_UNIT/ALLOC_UNIT))
#define SEGMENT_COUNT (RTE_EAL_PERSISTENT_MEM_COUNT)
#define SUBSEGMENT_COUNT (RTE_EAL_PERSISTENT_MEM_UNIT/ALLOC_UNIT)

static struct rte_hash* allocated_segments = 0;

struct alloc_info
{
	void* addr; //0 if not allocated
	phys_addr_t hw_addr;
	int seg_index;
	int sub_index;
	int seg_count;
};

struct alloc_info info_array[MAX_ALLOC_COUNT];
char alloc_array[SEGMENT_COUNT][SUBSEGMENT_COUNT+1];

#define ALLOCATED 'a'
#define FREE 'f'

static int __initialized = 0;

int rte_persistent_init(void)
{
	if(!__initialized)
	{
		struct rte_hash_parameters hash_param =
		{
				.name = "Persistent memory segments",
				.entries = MAX_ALLOC_COUNT,
				.reserved = 0,
				.key_len = sizeof(void*),
				.hash_func = 0, //DEFAULT_HASH_FUNC,
				.hash_func_init_val = 0,
				.socket_id = SOCKET_ID_ANY,
				.extra_flag = 0,
		};
		allocated_segments = rte_hash_create(&hash_param);
		memset(info_array, 0, sizeof(info_array));
		memset(alloc_array, (int)FREE, sizeof(alloc_array));

		int k;
		for(k=0; k<SEGMENT_COUNT; k++)
			alloc_array[k][SUBSEGMENT_COUNT] = 0;
		__initialized = 1;
	}
	return 0;
}

static int global_to_local_start(int total_numa, int numa)
{
	return ((RTE_EAL_PERSISTENT_MEM_COUNT/total_numa)*numa);
}

static int global_to_local_range(int total_numa)
{
	return ((RTE_EAL_PERSISTENT_MEM_COUNT/total_numa));
}

void* rte_persistent_alloc(size_t size, int socket)
{
	int num_numa = rte_persistent_memory_num_numa();
	if(socket == SOCKET_ID_ANY)
	{
		socket = rte_rand() % num_numa;
	}

	int l_start = global_to_local_start(num_numa, socket);
	int l_range = global_to_local_range(num_numa);

	int num_page = (size / ALLOC_UNIT);
	if(size % ALLOC_UNIT)
		num_page++;

	char find_str[SUBSEGMENT_COUNT+1];
	int k;
	for(k=0; k<num_page; k++)
	{
		find_str[k] = FREE;
	}
	find_str[k] = 0;

	void* found_buffer = 0;
	for(k=l_start; k<(l_start + l_range); k++)
	{
		char* start = alloc_array[k];
		char* found = strstr(start, find_str);

		if(found)
		{
			int offset = found - start;
			found_buffer = persistent_allocated_memory[socket][k];
			assert(found_buffer);
			found_buffer = RTE_PTR_ADD(found_buffer, ALLOC_UNIT*offset);
			int j;
			for(j=0; j<num_page; j++)
			{
				found[j] = ALLOCATED;
			}
			int index = rte_hash_add_key(allocated_segments, &found_buffer);
			assert(index >= 0);
			assert(info_array[index].addr == 0);
			info_array[index].addr = found_buffer;
			info_array[index].hw_addr = rte_mem_virt2phy(found_buffer);
			info_array[index].seg_count = num_page;
			info_array[index].seg_index = k;
			info_array[index].sub_index = offset;
			memset(found_buffer, 0, num_page*ALLOC_UNIT);


			void* user = found_buffer;
			uint64_t hw = rte_mem_virt2phy(user);
			size_t diff = RTE_MAX((uint64_t)user, hw) - RTE_MIN((uint64_t)user, hw);
			for(j = 0; j < num_page; j++)
			{
				size_t shift = ALLOC_UNIT * j;
				void* cur_user = ((char*)user + shift);
				uint64_t cur_hw = rte_mem_virt2phy(cur_user);
				size_t cur_diff = RTE_MAX((uint64_t)cur_user, cur_hw) - RTE_MIN((uint64_t)cur_user, cur_hw);

				if(cur_diff != diff)
				{
					RTE_LOG(ERR, EAL, "Hugepage is not contiguous, curdiff: %lX, expected: %lX\n", cur_diff, diff);
					assert(0);
				}
			}
			break;
		}
	}
	if(!found_buffer)
		RTE_LOG(ERR, EAL, "Cannot allocate persistent memory, size: %lu, socket: %d\n", size, socket);
	return found_buffer;
}

phys_addr_t rte_persistent_hw_addr(const void* addr)
{
	if(addr == 0)
		return 0;
	int index = rte_hash_lookup(allocated_segments, (const void*)&addr);
	assert(index >= 0);
	assert(info_array[index].addr);
	assert(info_array[index].addr == addr);
	return info_array[index].hw_addr;
}

size_t rte_persistent_mem_length(const void* addr)
{
	int index = rte_hash_lookup(allocated_segments, (const void*)&addr);
	assert(index >= 0);
	assert(info_array[index].addr);
	assert(info_array[index].addr == addr);
	return info_array[index].seg_count * ALLOC_UNIT;
}

void rte_persistent_free(void* addr)
{
	int index = rte_hash_lookup(allocated_segments, (const void*)&addr);
	assert(index >= 0);
	assert(info_array[index].addr);
	assert(info_array[index].addr == addr);

	int seg_index = info_array[index].seg_index;
	int sub_index = info_array[index].sub_index;
	int len = info_array[index].seg_count;

	info_array[index].seg_index = 0;
	info_array[index].sub_index = 0;
	info_array[index].seg_count = 0;
	info_array[index].addr = 0;
	info_array[index].hw_addr = 0;

	rte_hash_del_key(allocated_segments, (const void*)&addr);

	int k;
	for(k=0; k<len; k++)
		alloc_array[seg_index][sub_index+k] = FREE;
}
