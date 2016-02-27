/*
 * common.h
 *
 *  Created on: Feb 26, 2016
 *      Author: khlee
 */

#ifndef DRIVERS_NET_VOID_COMMON_H_
#define DRIVERS_NET_VOID_COMMON_H_

#include <stdint.h>

typedef unsigned (*eth_dev_void_size_generator)(void* aux);
typedef void* (*eth_dev_void_packet_rx_generator)(void* buf, unsigned length, void* aux);
typedef void (*eth_dev_void_packet_tx_consumer)(const void* data, unsigned length, void* packet_aux, void* aux);
typedef void* (*eth_dev_void_aux_generator)(unsigned queue_idx, void* dev_aux);


enum protocol_type
{
	IPv4,
	IPv6,
	TRACE,
};

#define RANDOM_STATE_LEN 128

#include <stdlib.h>

struct device_aux
{
	enum protocol_type proto_type;
	unsigned packet_size;
	unsigned numa_node;
	const void* trace;
	const void* trace_end;
};

struct queue_aux
{
	struct device_aux device_aux;
	uint64_t random_seed;
	char _random_state[RANDOM_STATE_LEN];
	struct random_data rand_data;
	const void* trace_ptr;
	const void* trace_start;
	const void* trace_end;
	int trace_byteorder;
};

void* void_aux_generator(unsigned queue_idx, void* dev_aux);
unsigned void_fixed_size(void* aux);
void void_tx_nothing(const void* data, unsigned length, void* packet_aux, void* aux);
void* void_default_rx_ipv4(void* buf, unsigned length, void* aux);
void* void_default_rx_ipv6(void* buf, unsigned length, void* aux);


#endif /* DRIVERS_NET_VOID_COMMON_H_ */
