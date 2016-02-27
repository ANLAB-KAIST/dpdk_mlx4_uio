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
unsigned pcap_next(void* buffer, unsigned buffer_len,
		struct random_data* random_data, const void** next, int endian);

#endif /* DRIVERS_NET_VOID_TRACE_H_ */
