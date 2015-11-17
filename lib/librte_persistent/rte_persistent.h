/*
 * rte_persistent.h
 *
 *  Created on: Jun 23, 2015
 *      Author: leeopop
 */

#ifndef LIBRTE_PERSISTENT_RTE_PERSISTENT_H_
#define LIBRTE_PERSISTENT_RTE_PERSISTENT_H_

#include <rte_common.h>
#include <rte_memory.h>

int rte_persistent_init(void);
void* rte_persistent_alloc(size_t size, int socket);
phys_addr_t rte_persistent_hw_addr(const void* addr);
void rte_persistent_free(void* addr);
size_t rte_persistent_mem_length(const void* addr);

#endif /* LIBRTE_PERSISTENT_RTE_PERSISTENT_H_ */
