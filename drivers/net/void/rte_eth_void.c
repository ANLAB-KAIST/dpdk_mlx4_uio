/*-
 *   BSD LICENSE
 *
 *   Copyright (C) IGEL Co.,Ltd.
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
 *     * Neither the name of IGEL Co.,Ltd. nor the names of its
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


#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_dev.h>
#include <rte_kvargs.h>
#include <rte_spinlock.h>
#include <rte_common.h>
#include <stdio.h>
#include <assert.h>

#include "common.h"
#include "trace.h"

struct pmd_internals;

struct void_queue {
	struct pmd_internals *internals;

	struct rte_mempool *mb_pool;

	rte_atomic64_t rx_pkts;
	rte_atomic64_t tx_pkts;
	rte_atomic64_t err_pkts;

	uint8_t in_port;
	void* size_aux;
	void* rx_aux;
	void* tx_aux;
	void* general_aux;
};

struct pmd_internals {
	unsigned numa_node;

	unsigned nb_rx_queues;
	unsigned nb_tx_queues;

	struct void_queue rx_void_queues[RTE_MAX_QUEUES_PER_PORT];
	struct void_queue tx_void_queues[RTE_MAX_QUEUES_PER_PORT];

	/** Bit mask of RSS offloads, the bit offset also means flow type */
	uint64_t flow_type_rss_offloads;

	rte_spinlock_t rss_lock;

	uint16_t reta_size;
	struct rte_eth_rss_reta_entry64 reta_conf[ETH_RSS_RETA_SIZE_128 /
			RTE_RETA_GROUP_SIZE];

	uint8_t rss_key[40];                /**< 40-byte hash key. */

	eth_dev_void_size_generator size_generator;
	eth_dev_void_packet_rx_generator rx_generator;
	eth_dev_void_packet_tx_consumer tx_consumer;

	eth_dev_void_aux_generator size_aux_gen;
	eth_dev_void_aux_generator rx_aux_gen;
	eth_dev_void_aux_generator tx_aux_gen;

	void* device_aux;
};


static struct ether_addr eth_addr = { .addr_bytes = {0} };
static const char *drivername = "void PMD";
static struct rte_eth_link pmd_link = {
	.link_speed = 10000,
	.link_duplex = ETH_LINK_FULL_DUPLEX,
	.link_status = 0
};

static uint16_t
eth_void_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	int i;
	struct void_queue *h = q;
	unsigned packet_size;

	if ((q == NULL) || (bufs == NULL))
		return 0;

	int breakpoint = nb_bufs;
	struct queue_aux* general_aux = h->general_aux;
	if(general_aux->device_aux.slow_read)
	{
		int32_t rand_val;
		random_r(&general_aux->rand_data, &rand_val);
		breakpoint = rand_val % (nb_bufs * 2);
	}

	for (i = 0; i < nb_bufs; i++) {
		if(i == breakpoint)
			break;
		bufs[i] = rte_pktmbuf_alloc(h->mb_pool);
		if (!bufs[i])
			break;
		packet_size = h->internals->size_generator(h->size_aux);
		bufs[i]->data_len = (uint16_t)packet_size;
		bufs[i]->pkt_len = packet_size;
		bufs[i]->nb_segs = 1;
		bufs[i]->next = NULL;

		void* buf = rte_pktmbuf_mtod(bufs[i], void*);
		void* ret = h->internals->rx_generator(buf, packet_size, h->rx_aux);
		bufs[i]->userdata = ret;
		bufs[i]->port = h->in_port;

	}

	rte_atomic64_add(&(h->rx_pkts), i);

	return i;
}

static uint16_t
eth_void_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	int i;
	struct void_queue *h = q;

	if ((q == NULL) || (bufs == NULL))
		return 0;

	int breakpoint = nb_bufs;
	struct queue_aux* general_aux = h->general_aux;
	if(general_aux->device_aux.slow_write)
	{
		int32_t rand_val;
		random_r(&general_aux->rand_data, &rand_val);
		breakpoint = rand_val % (nb_bufs * 2);
	}

	for (i = 0; i < nb_bufs; i++)
	{
		if(i == breakpoint)
			break;
		void* buf = rte_pktmbuf_mtod(bufs[i], void*);
		unsigned len = rte_pktmbuf_pkt_len(bufs[i]);
		h->internals->tx_consumer(buf, len, bufs[i]->userdata, h->tx_aux);
		rte_pktmbuf_free(bufs[i]);
	}

	rte_atomic64_add(&(h->tx_pkts), i);

	return i;
}

static int
eth_dev_configure(struct rte_eth_dev *dev) {
	struct pmd_internals *internals;

	internals = dev->data->dev_private;
	internals->nb_rx_queues = dev->data->nb_rx_queues;
	internals->nb_tx_queues = dev->data->nb_tx_queues;

	return 0;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	if (dev == NULL)
		return -EINVAL;

	dev->data->dev_link.link_status = 1;
	return 0;
}

static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	if (dev == NULL)
		return;

	dev->data->dev_link.link_status = 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		uint16_t nb_rx_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_rxconf *rx_conf __rte_unused,
		struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals;

	if ((dev == NULL) || (mb_pool == NULL))
		return -EINVAL;

	internals = dev->data->dev_private;

	if (rx_queue_id >= internals->nb_rx_queues)
		return -ENODEV;
	internals->rx_void_queues[rx_queue_id].general_aux = void_aux_generator(rx_queue_id, internals->device_aux);
	internals->rx_void_queues[rx_queue_id].rx_aux = internals->rx_aux_gen(rx_queue_id, internals->device_aux);
	internals->rx_void_queues[rx_queue_id].size_aux = internals->size_aux_gen(rx_queue_id, internals->device_aux);

	internals->rx_void_queues[rx_queue_id].mb_pool = mb_pool;
	dev->data->rx_queues[rx_queue_id] =
		&internals->rx_void_queues[rx_queue_id];

	internals->rx_void_queues[rx_queue_id].internals = internals;
	internals->rx_void_queues[rx_queue_id].in_port = dev->data->port_id;

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		uint16_t nb_tx_desc __rte_unused,
		unsigned int socket_id __rte_unused,
		const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals;

	if (dev == NULL)
		return -EINVAL;

	internals = dev->data->dev_private;

	if (tx_queue_id >= internals->nb_tx_queues)
		return -ENODEV;

	internals->tx_void_queues[tx_queue_id].general_aux = void_aux_generator(tx_queue_id, internals->device_aux);
	internals->tx_void_queues[tx_queue_id].tx_aux = internals->tx_aux_gen(tx_queue_id, internals->device_aux);

	dev->data->tx_queues[tx_queue_id] =
		&internals->tx_void_queues[tx_queue_id];

	internals->tx_void_queues[tx_queue_id].internals = internals;

	return 0;
}


static void
eth_dev_info(struct rte_eth_dev *dev,
		struct rte_eth_dev_info *dev_info)
{
	struct pmd_internals *internals;

	if ((dev == NULL) || (dev_info == NULL))
		return;

	internals = dev->data->dev_private;
	dev_info->driver_name = drivername;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = RTE_DIM(internals->rx_void_queues);
	dev_info->max_tx_queues = RTE_DIM(internals->tx_void_queues);
	dev_info->min_rx_bufsize = 0;
	dev_info->pci_dev = NULL;
	dev_info->reta_size = internals->reta_size;
	dev_info->flow_type_rss_offloads = internals->flow_type_rss_offloads;
}

static void
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *igb_stats)
{
	unsigned i, num_stats;
	unsigned long rx_total = 0, tx_total = 0, tx_err_total = 0;
	const struct pmd_internals *internal;

	if ((dev == NULL) || (igb_stats == NULL))
		return;

	internal = dev->data->dev_private;
	num_stats = RTE_MIN((unsigned)RTE_ETHDEV_QUEUE_STAT_CNTRS,
			RTE_MIN(internal->nb_rx_queues,
				RTE_DIM(internal->rx_void_queues)));
	for (i = 0; i < num_stats; i++) {
		igb_stats->q_ipackets[i] =
			internal->rx_void_queues[i].rx_pkts.cnt;
		rx_total += igb_stats->q_ipackets[i];
	}

	num_stats = RTE_MIN((unsigned)RTE_ETHDEV_QUEUE_STAT_CNTRS,
			RTE_MIN(internal->nb_tx_queues,
				RTE_DIM(internal->tx_void_queues)));
	for (i = 0; i < num_stats; i++) {
		igb_stats->q_opackets[i] =
			internal->tx_void_queues[i].tx_pkts.cnt;
		igb_stats->q_errors[i] =
			internal->tx_void_queues[i].err_pkts.cnt;
		tx_total += igb_stats->q_opackets[i];
		tx_err_total += igb_stats->q_errors[i];
	}

	igb_stats->ipackets = rx_total;
	igb_stats->opackets = tx_total;
	igb_stats->oerrors = tx_err_total;
}

static void
eth_stats_reset(struct rte_eth_dev *dev)
{
	unsigned i;
	struct pmd_internals *internal;

	if (dev == NULL)
		return;

	internal = dev->data->dev_private;
	for (i = 0; i < RTE_DIM(internal->rx_void_queues); i++)
		internal->rx_void_queues[i].rx_pkts.cnt = 0;
	for (i = 0; i < RTE_DIM(internal->tx_void_queues); i++) {
		internal->tx_void_queues[i].tx_pkts.cnt = 0;
		internal->tx_void_queues[i].err_pkts.cnt = 0;
	}
}

static void
eth_queue_release(void *q)
{
	//struct void_queue *nq;

	if (q == NULL)
		return;

	//nq = q;
	//rte_free(nq->dummy_packet);
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused) { return 0; }

static int
eth_rss_reta_update(struct rte_eth_dev *dev,
		struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
{
	int i, j;
	struct pmd_internals *internal = dev->data->dev_private;

	if (reta_size != internal->reta_size)
		return -EINVAL;

	rte_spinlock_lock(&internal->rss_lock);

	/* Copy RETA table */
	for (i = 0; i < (internal->reta_size / RTE_RETA_GROUP_SIZE); i++) {
		internal->reta_conf[i].mask = reta_conf[i].mask;
		for (j = 0; j < RTE_RETA_GROUP_SIZE; j++)
			if ((reta_conf[i].mask >> j) & 0x01)
				internal->reta_conf[i].reta[j] = reta_conf[i].reta[j];
	}

	rte_spinlock_unlock(&internal->rss_lock);

	return 0;
}

static int
eth_rss_reta_query(struct rte_eth_dev *dev,
		struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size)
{
	int i, j;
	struct pmd_internals *internal = dev->data->dev_private;

	if (reta_size != internal->reta_size)
		return -EINVAL;

	rte_spinlock_lock(&internal->rss_lock);

	/* Copy RETA table */
	for (i = 0; i < (internal->reta_size / RTE_RETA_GROUP_SIZE); i++) {
		for (j = 0; j < RTE_RETA_GROUP_SIZE; j++)
			if ((reta_conf[i].mask >> j) & 0x01)
				reta_conf[i].reta[j] = internal->reta_conf[i].reta[j];
	}

	rte_spinlock_unlock(&internal->rss_lock);

	return 0;
}

static int
eth_rss_hash_update(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf)
{
	struct pmd_internals *internal = dev->data->dev_private;

	rte_spinlock_lock(&internal->rss_lock);

	if ((rss_conf->rss_hf & internal->flow_type_rss_offloads) != 0)
		dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf =
				rss_conf->rss_hf & internal->flow_type_rss_offloads;

	if (rss_conf->rss_key)
		rte_memcpy(internal->rss_key, rss_conf->rss_key, 40);

	rte_spinlock_unlock(&internal->rss_lock);

	return 0;
}

static int
eth_rss_hash_conf_get(struct rte_eth_dev *dev,
		struct rte_eth_rss_conf *rss_conf)
{
	struct pmd_internals *internal = dev->data->dev_private;

	rte_spinlock_lock(&internal->rss_lock);

	rss_conf->rss_hf = dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf;
	if (rss_conf->rss_key)
		rte_memcpy(rss_conf->rss_key, internal->rss_key, 40);

	rte_spinlock_unlock(&internal->rss_lock);

	return 0;
}

static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
	.reta_update = eth_rss_reta_update,
	.reta_query = eth_rss_reta_query,
	.rss_hash_update = eth_rss_hash_update,
	.rss_hash_conf_get = eth_rss_hash_conf_get
};

static int
eth_dev_void_create(const char *name, const unsigned numa_node, const struct device_aux* aux)
{
	const unsigned nb_rx_queues = 1;
	const unsigned nb_tx_queues = 1;
	struct rte_eth_dev_data *data = NULL;
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev *eth_dev = NULL;

	static const uint8_t default_rss_key[40] = {
		0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2, 0x41, 0x67, 0x25, 0x3D,
		0x43, 0xA3, 0x8F, 0xB0, 0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
		0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C, 0x6A, 0x42, 0xB7, 0x3B,
		0xBE, 0xAC, 0x01, 0xFA
	};

	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Creating void ethdev on numa socket %u\n",
			numa_node);

	/* now do all data allocation - for eth_dev structure, dummy pci driver
	 * and internal (private) data
	 */
	data = rte_zmalloc_socket(name, sizeof(*data), 0, numa_node);
	if (data == NULL)
		goto error;

	internals = rte_zmalloc_socket(name, sizeof(*internals), 0, numa_node);
	if (internals == NULL)
		goto error;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocate(name, RTE_ETH_DEV_VIRTUAL);
	if (eth_dev == NULL)
		goto error;

	/* now put it all together
	 * - store queue data in internals,
	 * - store numa_node info in ethdev data
	 * - point eth_dev_data to internals
	 * - and point eth_dev structure to new eth_dev_data structure
	 */
	/* NOTE: we'll replace the data element, of originally allocated eth_dev
	 * so the nulls are local per-process */

	internals->nb_rx_queues = nb_rx_queues;
	internals->nb_tx_queues = nb_tx_queues;
	internals->numa_node = numa_node;
	internals->device_aux = rte_malloc_socket(NULL, sizeof(struct device_aux), 0, numa_node);
	rte_memcpy(internals->device_aux, aux, sizeof(struct device_aux));

	internals->size_generator = void_fixed_size;
	if(aux->proto_type == IPv4)
		internals->rx_generator = void_default_rx_ipv4;
	else if(aux->proto_type == IPv6)
		internals->rx_generator = void_default_rx_ipv6;
	else if(aux->proto_type == TRACE)
	{
		internals->rx_generator = void_pcap_rx;
		internals->size_generator = void_pcap_size;
	}


	internals->tx_consumer = void_tx_nothing;
	internals->size_aux_gen = void_aux_generator;
	internals->rx_aux_gen = void_aux_generator;
	internals->tx_aux_gen = void_aux_generator;

	internals->flow_type_rss_offloads =  ETH_RSS_PROTO_MASK;
	internals->reta_size = RTE_DIM(internals->reta_conf) * RTE_RETA_GROUP_SIZE;

	rte_memcpy(internals->rss_key, default_rss_key, 40);

	data->dev_private = internals;
	data->port_id = eth_dev->data->port_id;
	data->nb_rx_queues = (uint16_t)nb_rx_queues;
	data->nb_tx_queues = (uint16_t)nb_tx_queues;
	data->dev_link = pmd_link;
	data->mac_addrs = &eth_addr;
	strncpy(data->name, eth_dev->data->name, strlen(eth_dev->data->name));

	eth_dev->data = data;
	eth_dev->dev_ops = &ops;

	TAILQ_INIT(&eth_dev->link_intr_cbs);

	eth_dev->driver = NULL;
	eth_dev->data->dev_flags = RTE_ETH_DEV_DETACHABLE;
	eth_dev->data->kdrv = RTE_KDRV_NONE;
	eth_dev->data->drv_name = drivername;
	eth_dev->data->numa_node = numa_node;

	/* finally assign rx and tx ops */

	eth_dev->rx_pkt_burst = eth_void_rx;
	eth_dev->tx_pkt_burst = eth_void_tx;

	return 0;

error:
	rte_free(data);
	rte_free(internals);

	return -1;
}

#define MAX_ARG 1024

static inline int
get_string_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	char *buffer = extra_args;

	if ((value == NULL) || (extra_args == NULL))
		return -EINVAL;

	strncpy(buffer, value, MAX_ARG);

	return 0;
}

static const char *valid_arguments[] = {
	"size",
	"protocol",
	"node",
	"trace",
	"slow",
	NULL
};

static int
rte_pmd_void_devinit(const char *name, const char *params)
{
	struct rte_kvargs *kvlist = NULL;
	int ret;
	char str_temp[MAX_ARG];
	struct device_aux dev_aux;
	dev_aux.numa_node = 0;
	dev_aux.packet_size = 64;
	dev_aux.proto_type = IPv4;
	dev_aux.slow_read = 0;
	dev_aux.slow_write = 0;
	dev_aux.trace = NULL;
	dev_aux.trace_end = NULL;

	FILE* trace = NULL;

	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Initializing pmd_null for %s\n", name);

	if (params != NULL) {
		kvlist = rte_kvargs_parse(params, valid_arguments);
		if (kvlist == NULL)
			return -1;

		if (rte_kvargs_count(kvlist, "node") == 1) {

			ret = rte_kvargs_process(kvlist,
					"node",
					get_string_arg, str_temp);
			if (ret < 0)
				goto free_kvlist;

			dev_aux.numa_node = strtoul(str_temp, 0, 0);
		}

		if (rte_kvargs_count(kvlist, "protocol") == 1) {

			ret = rte_kvargs_process(kvlist,
					"protocol",
					get_string_arg, str_temp);
			if (ret < 0)
				goto free_kvlist;

			if(strncmp(str_temp, "ipv4", MAX_ARG) == 0)
			{
				dev_aux.proto_type = IPv4;
			}
			else if(strncmp(str_temp, "ipv6", MAX_ARG) == 0)
			{
				dev_aux.proto_type = IPv6;
			}
			else if(strncmp(str_temp, "trace", MAX_ARG) == 0)
			{
				dev_aux.proto_type = TRACE;
			}
			else
			{
				RTE_LOG(INFO, PMD, "Unsupported protocol type: %s\n", str_temp);
				ret = -EINVAL;
				goto free_kvlist;
			}
		}

		if (rte_kvargs_count(kvlist, "size") == 1) {

			ret = rte_kvargs_process(kvlist,
					"size",
					get_string_arg, str_temp);
			if (ret < 0)
				goto free_kvlist;

			dev_aux.packet_size = strtoul(str_temp, 0, 0);
			dev_aux.packet_size = RTE_MIN(dev_aux.packet_size, 1514u);
			dev_aux.packet_size = RTE_MAX(dev_aux.packet_size, 64u);
		}

		if (rte_kvargs_count(kvlist, "trace") == 1) {

			ret = rte_kvargs_process(kvlist,
					"trace",
					get_string_arg, str_temp);
			if (ret < 0)
				goto free_kvlist;

			trace = fopen(str_temp, "rb");
		}

		if (rte_kvargs_count(kvlist, "slow") == 1) {

			ret = rte_kvargs_process(kvlist,
					"slow",
					get_string_arg, str_temp);
			if (ret < 0)
				goto free_kvlist;
			if(strstr(str_temp, "r") != NULL)
				dev_aux.slow_read = 1;
			if(strstr(str_temp, "w") != NULL)
				dev_aux.slow_write = 1;
		}
	}

	if(trace != NULL)
	{
		if(dev_aux.proto_type != TRACE)
		{
			RTE_LOG(INFO, PMD, "Protocol is not TRACE\n");
			ret = -EINVAL;
			goto free_kvlist;
		}
		fseek(trace, 0L, SEEK_END);
		size_t length = ftell(trace);
		void* buf = rte_malloc_socket("PCAP TRACE", length, RTE_CACHE_LINE_SIZE, dev_aux.numa_node);
		assert(buf != NULL);
		fseek(trace, 0L, SEEK_SET);

		int _ret = fread(buf, length, 1, trace);
		assert(_ret == 1);
		dev_aux.trace = buf;
		dev_aux.trace_end = RTE_PTR_ADD(buf, length);
		fclose(trace);
		trace = NULL;
	}
	else if(dev_aux.proto_type == TRACE)
	{
		RTE_LOG(INFO, PMD, "Trace file is not given\n");
		ret = -EINVAL;
		goto free_kvlist;
	}

	RTE_LOG(INFO, PMD, "device[%s] node is set to %u\n", name, dev_aux.numa_node);
	ret = eth_dev_void_create(name, dev_aux.numa_node, &dev_aux);

free_kvlist:
	if (kvlist)
		rte_kvargs_free(kvlist);
	return ret;
}

static int
rte_pmd_void_devuninit(const char *name)
{
	struct rte_eth_dev *eth_dev = NULL;

	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Closing void ethdev on numa socket %u\n",
			rte_socket_id());

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return -1;

	rte_free(eth_dev->data->dev_private);
	rte_free(eth_dev->data);

	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_driver pmd_void_drv = {
	.name = "eth_void",
	.type = PMD_VDEV,
	.init = rte_pmd_void_devinit,
	.uninit = rte_pmd_void_devuninit,
};

PMD_REGISTER_DRIVER(pmd_void_drv);
