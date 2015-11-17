/*
 * eal_persistent_mem.c
 *
 *  Created on: Jun 22, 2015
 *      Author: leeopop
 */


/*
 * dma_memory.c
 *
 *  Created on: Oct 4, 2014
 *      Author: leeopop
 */


#include <rte_persistent_mem.h>

#include <sys/io.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <numa.h>
#include <numaif.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <rte_log.h>
#include <rte_eal.h>
#include <rte_memory.h>
#include <rte_common.h>
#include <rte_atomic.h>

#define SHM_SIZE RTE_EAL_PERSISTENT_MEM_UNIT
#define SHM_COUNT RTE_EAL_PERSISTENT_MEM_COUNT

#define SHM_KEY_BASE (0x861591B)
#define SHM_KEY ((SHM_KEY_BASE / SHM_COUNT)*SHM_COUNT)

static void* reserve_shared_zone(int subindex, uint32_t len, int socket_id)
{
	assert(subindex < SHM_COUNT);
	uint32_t shared_key = SHM_KEY_BASE + subindex;

	int shmget_flag = IPC_CREAT | SHM_R | SHM_W | IPC_EXCL; // | SHM_LOCKED;
	int shmid = -1;
	int err;
	if((len / RTE_PGSIZE_4K) > 1)
	{
		shmget_flag |= SHM_HUGETLB;
	}

	shmid = shmget(shared_key, len, shmget_flag);
	void* addr = 0;
	int clear = 1;
	if(shmid < 0)
	{
		//Reuse existing
		shmid = shmget(shared_key, len, shmget_flag &= ~IPC_EXCL);
		assert(shmid >= 0);
		clear = 0;
	}
	addr = shmat(shmid, 0, SHM_RND);
	assert(addr);

	if(socket_id != SOCKET_ID_ANY)
	{
		struct bitmask * mask = numa_bitmask_alloc(RTE_MAX_NUMA_NODES);
		mask = numa_bitmask_clearall(mask);
		mask = numa_bitmask_setbit(mask, socket_id);
		long ret = mbind(addr, len, MPOL_BIND,
				mask->maskp, RTE_MAX_NUMA_NODES,
				MPOL_MF_MOVE_ALL | MPOL_MF_STRICT);
		if(ret < 0)
		{
			RTE_LOG(WARNING, EAL, "Cannot mbind memory. Are you running with root?\n");
		}
		numa_bitmask_free(mask);
	}
	rte_mb();

	if(clear)
	{
		memset(addr, 0, len);
	}

	size_t size;
	volatile uint8_t reader = 0; //this prevents from being optimized out
	volatile uint8_t* readp = (uint8_t*)addr;
	for(size = 0; size < len; size++)
	{
		reader += *readp;
		readp++;
	}

	rte_mb();
	err = shmctl(shmid, SHM_LOCK, 0);
	assert(err == 0);
	return addr;
}

void* persistent_allocated_memory[RTE_MAX_NUMA_NODES][SHM_COUNT];

static int numa_count = 0;

int rte_persistent_memory_num_numa(void)
{
	return numa_count;
}

int rte_persistent_memory_init(void)
{
	assert(SHM_SIZE == RTE_PGSIZE_2M); //XXX considering only 2MB pages.
	int num_numa = numa_num_configured_nodes();
	if(num_numa == 0)
		num_numa = 1;
	numa_count = num_numa;
	int node;
	int k;
	for(node = 0; node < RTE_MAX_NUMA_NODES; node++)
		for(k=0; k<SHM_COUNT; k++)
			persistent_allocated_memory[node][k] = 0;

	for(node = 0; node < num_numa; node++)
	{
		int cur_socket = num_numa > 1 ? node : SOCKET_ID_ANY;
		for(k=0; k<SHM_COUNT/num_numa; k++)
		{
			int zone_index = ((SHM_COUNT/num_numa)*node + k);
			persistent_allocated_memory[node][k] = reserve_shared_zone(zone_index,
					SHM_SIZE, cur_socket);
			if(persistent_allocated_memory[node][k] == 0)
			{
				RTE_LOG(ERR, EAL, "Cannot allocate shared zone index %d."
						"node: %d, local index: %d\n", zone_index, node, k);
				return -1;
			}
		}
		RTE_LOG(INFO, EAL, "Initialized %lu bytes shared zone on socket %d.\n",
				((uint64_t)(SHM_COUNT/num_numa)) * ((uint64_t)(SHM_SIZE)),
				cur_socket);
	}
	return 0;
}
