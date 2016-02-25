/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RTE_ETH_NULL_H_
#define RTE_ETH_NULL_H_

#include <rte_mbuf.h>

int eth_dev_void_create(const char *name, const unsigned numa_node);
typedef unsigned (*eth_dev_void_size_generator)(void* aux);
typedef void* (*eth_dev_void_packet_rx_generator)(void* buf, unsigned length, void* aux);
typedef void (*eth_dev_void_packet_tx_consumer)(const void* data, unsigned length, void* packet_aux, void* aux);

void eth_dev_void_set_size_generator(unsigned dev_idx, unsigned queue_idx,
		eth_dev_void_size_generator f, void* aux);
void eth_dev_void_set_packet_rx_generator(unsigned dev_idx, unsigned queue_idx,
		eth_dev_void_packet_rx_generator f, void* aux);
void eth_dev_void_set_packet_tx_consumer(unsigned dev_idx, unsigned queue_idx,
		eth_dev_void_packet_tx_consumer f, void* aux);


unsigned void_default_min_size(void* aux __rte_unused);
unsigned void_default_max_size(void* aux __rte_unused);
void void_default_consumer(const void* data, unsigned length, void* packet_aux, void* aux);

#endif /* RTE_ETH_NULL_H_ */
