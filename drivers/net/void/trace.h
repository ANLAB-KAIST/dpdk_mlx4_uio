/*
 * trace.h
 *
 *  Created on: Feb 27, 2016
 *      Author: khlee
 */

#ifndef DRIVERS_NET_VOID_TRACE_H_
#define DRIVERS_NET_VOID_TRACE_H_

#include <stdlib.h>

int pcap_begin(const void* content, const void** next);
unsigned pcap_current_length(const void* const * next, int endian);
unsigned pcap_next(void* buffer, unsigned buffer_len,
		struct random_data* random_data, const void** next, int endian);
void* void_pcap_rx(void* buf, unsigned length, void* aux);
unsigned void_pcap_size(void* aux);

#endif /* DRIVERS_NET_VOID_TRACE_H_ */
