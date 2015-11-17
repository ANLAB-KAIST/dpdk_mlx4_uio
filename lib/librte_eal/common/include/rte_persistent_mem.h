/*
 * rte_persistent_memory.h
 *
 *  Created on: Jun 22, 2015
 *      Author: leeopop
 */

#ifndef LIBRTE_EAL_COMMON_INCLUDE_RTE_PERSISTENT_MEM_H_
#define LIBRTE_EAL_COMMON_INCLUDE_RTE_PERSISTENT_MEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <exec-env/rte_persistent_mem.h>

int rte_persistent_memory_init(void);
int rte_persistent_memory_num_numa(void);

extern void* persistent_allocated_memory[RTE_MAX_NUMA_NODES][RTE_EAL_PERSISTENT_MEM_COUNT];

#ifdef __cplusplus
}
#endif

#endif /* LIBRTE_EAL_COMMON_INCLUDE_RTE_PERSISTENT_MEM_H_ */
