/*
 * common.c
 *
 *  Created on: Feb 26, 2016
 *      Author: khlee
 */


#include "common.h"
#include "trace.h"
#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <stdlib.h>

void* void_aux_generator(unsigned queue_idx __rte_unused, void* dev_aux)
{
	struct device_aux* aux = (struct device_aux*)dev_aux;
	struct queue_aux* aux_ret = (struct queue_aux*)rte_zmalloc_socket(NULL, sizeof(struct queue_aux), 0, aux->numa_node);
	rte_memcpy(&aux_ret->device_aux, aux, sizeof(struct device_aux));

	aux_ret->random_seed = rte_rand();
	initstate_r(aux_ret->random_seed, aux_ret->_random_state, RANDOM_STATE_LEN, &aux_ret->rand_data);

	if(aux->trace)
	{
		const void* start = 0;
		int byteorder = pcap_begin(aux->trace, &start);
		aux_ret->trace_byteorder = byteorder;
		aux_ret->trace_ptr = aux_ret->trace_start = start;
		aux_ret->trace_end = aux->trace_end;
	}
	else
	{
		aux_ret->trace_start = NULL;
		aux_ret->trace_ptr = NULL;
		aux_ret->trace_end = NULL;
		aux_ret->trace_byteorder = 0;
	}
	return aux_ret;
}

unsigned void_fixed_size(void* aux)
{
	struct queue_aux* queue_aux = (struct queue_aux*)aux;
	return queue_aux->device_aux.packet_size;
}

void void_tx_nothing(const void* data __rte_unused, unsigned length __rte_unused, void* packet_aux __rte_unused, void* aux __rte_unused)
{
	return;
}

void* void_default_rx_ipv4(void* buf, unsigned length, void* aux)
{
	struct queue_aux* queue_aux = (struct queue_aux*)aux;

	struct ether_hdr *eth;
	struct ipv4_hdr *ip;
	struct udp_hdr *udp;

	/* Build an ethernet header */
	eth = (struct ether_hdr *)buf;
	memset(&eth->s_addr, 0, ETHER_ADDR_LEN);
	memset(&eth->d_addr, 0, ETHER_ADDR_LEN);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

	/* Note: eth->h_source and eth->h_dest are written at send_packets(). */

	/* Build an IPv4 header. */
	ip = (struct ipv4_hdr *)((char*)buf + sizeof(*eth));

	ip->version_ihl = (4 << 4) | 5;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(length - sizeof(*eth));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 4;
	ip->next_proto_id = 17; //UDP
	/* Currently we do not test source-routing. */
	int32_t temp_int;
	random_r(&queue_aux->rand_data, &temp_int);
	ip->src_addr = rte_cpu_to_be_32((uint32_t)temp_int);
	random_r(&queue_aux->rand_data, &temp_int);
	ip->dst_addr = rte_cpu_to_be_32((uint32_t)temp_int);

	/* Prevent generation of multicast packets, though its probability is very low. */
	unsigned char *addr = (unsigned char*)(&ip->dst_addr);
	addr[0] &= 0x7F;
	addr = (unsigned char*)(&ip->src_addr);
	addr[0] &= 0x7F;

	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	udp = (struct udp_hdr *)((char *)ip + sizeof(*ip));

	random_r(&queue_aux->rand_data, &temp_int);
	udp->src_port = rte_cpu_to_be_16(((uint16_t)temp_int) & 0xFFFF);
	random_r(&queue_aux->rand_data, &temp_int);
	udp->dst_port = rte_cpu_to_be_16(((uint16_t)temp_int) & 0xFFFF);
	udp->dgram_len   = rte_cpu_to_be_16(length - sizeof(*eth) - sizeof(*ip));
	udp->dgram_cksum = 0;

	/* For debugging, we fill the packet content with a random number. */
	random_r(&queue_aux->rand_data, &temp_int);
	char *content = (char *)((char *)udp + sizeof(*udp));
	memset(content, temp_int, length - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return NULL;
}

void* void_default_rx_ipv6(void* buf, unsigned length, void* aux)
{
	struct queue_aux* queue_aux = (struct queue_aux*)aux;
	struct ether_hdr *eth;
	struct ipv6_hdr *ip;
	struct udp_hdr *udp;
	int32_t temp_int;

	/* Build an ethernet header. */
	eth = (struct ether_hdr *)buf;
	memset(&eth->s_addr, 0, ETHER_ADDR_LEN);
	memset(&eth->d_addr, 0, ETHER_ADDR_LEN);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

	/* Note: eth->h_source and eth->h_dest are written at send_packets(). */

	/* Build an IPv6 header. */
	ip = (struct ipv6_hdr *)((char*)buf + sizeof(*eth));

	/* 4 bits: version, 8 bits: traffic class, 20 bits: flow label. */
	ip->vtc_flow = rte_cpu_to_be_32(6 << 28);
	ip->payload_len = rte_cpu_to_be_16(length - sizeof(*eth) - sizeof(*ip)); /* The minimum is 10 bytes. */
	ip->proto = 17; //UDP
	ip->hop_limits = 4;
	/* Currently we do not test source-routing. */
	int _k;
	for(_k=0; _k<4; ++_k)
	{
		random_r(&queue_aux->rand_data, &temp_int);
		ip->src_addr[_k] = rte_cpu_to_be_32((uint32_t)temp_int);
		random_r(&queue_aux->rand_data, &temp_int);
		ip->dst_addr[_k] = rte_cpu_to_be_32((uint32_t)temp_int);
	}

	// TODO: implement randomize flag for IPv6 too.

	/* Prevent generation of multicast packets. */
	unsigned char *addr = (unsigned char*)(&ip->dst_addr[0]);
	addr[0] &= 0x7F;
	addr = (unsigned char*)(&ip->src_addr[0]);
	addr[0] &= 0x7F;

	udp = (struct udp_hdr *)((char *)ip + sizeof(*ip));

	random_r(&queue_aux->rand_data, &temp_int);
	udp->src_port = rte_cpu_to_be_16(((uint16_t)temp_int) & 0xFFFF);
	random_r(&queue_aux->rand_data, &temp_int);
	udp->dst_port = rte_cpu_to_be_16(((uint16_t)temp_int) & 0xFFFF);
	udp->dgram_len   = rte_cpu_to_be_16(length - sizeof(*eth) - sizeof(*ip));
	udp->dgram_cksum = 0;

	//* For debugging, we fill the packet content with a random number. */
	random_r(&queue_aux->rand_data, &temp_int);
	char *content = (char *)((char *)udp + sizeof(*udp));
	memset(content, temp_int, length - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
	udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip, udp);
	return NULL;
}
