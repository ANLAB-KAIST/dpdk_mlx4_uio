/*
 * mlx4_uio.c
 *
 *  Created on: Jun 30, 2015
 *      Author: leeopop
 */

#include "kmod.h"
#include "mlx4_uio.h"
#include "mlnx/mlx4/mlx4_en.h"
#include "dcbnl.h"
#include "mlx4/device.h"

#include "mlx4_uio_helper.h"
#include "log2.h"
#include "mlx4_en_special.h"
#include <rte_mbuf.h>

#ifdef CONFIG_INFINIBAND_WQE_FORMAT
	#define INIT_OWNER_BIT	cpu_to_be32(1 << 30)
#else
	#define INIT_OWNER_BIT  0xffffffff
#endif

void mlx4_eth_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct mlx4_en_priv* priv = rtedev_priv(dev);
	int port = priv->port;
	struct mlx4_en_dev* mdev = priv->mdev;
	struct mlx4_en_port_profile* prof = priv->prof;

	uint64_t rss_offloads = ETH_RSS_IPV4 | ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV6_TCP;
	if(mdev->dev->caps.flags & MLX4_DEV_CAP_FLAG_UDP_RSS)
		rss_offloads |= (ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_NONFRAG_IPV6_UDP);
	if(mdev->dev->caps.flags & MLX4_DEV_CAP_FLAG_RSS_IP_FRAG)
		rss_offloads |= (ETH_RSS_FRAG_IPV4 | ETH_RSS_FRAG_IPV6);


	struct rte_eth_dev_info rte_info = {
			.pci_dev = mdev->rte_pdev,
			.driver_name = "mlx4_uio",
			.if_index = 0,
			.min_rx_bufsize = MLX4_EN_SMALL_PKT_SIZE,
			.max_rx_pktlen = mdev->dev->caps.eth_mtu_cap[priv->port],
			.max_rx_queues = MAX_RX_RINGS,
			.max_tx_queues = MAX_TX_RINGS,
			.max_mac_addrs = (1 << mdev->dev->caps.log_num_macs),
			.max_hash_mac_addrs = MLX4_EN_MAC_HASH_SIZE,
			.max_vfs = MLX4_MAX_NUM_VF_P_PORT,
			.max_vmdq_pools = 0, //MLX4_MFUNC_EQ_NUM, //XXX
			.rx_offload_capa = DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM | DEV_RX_OFFLOAD_TCP_CKSUM,
			.tx_offload_capa = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM,
			.reta_size = mdev->dev->caps.max_rss_tbl_sz,
			.hash_key_size = MLX4_EN_RSS_KEY_SIZE * sizeof(uint32_t),
			.flow_type_rss_offloads = rss_offloads,
			.default_rxconf = {.rx_drop_en = 1},
			.default_txconf = {0,},
			.vmdq_pool_base = 0,
			.vmdq_queue_base = 0,
			.vmdq_queue_num = 0,
			.rx_desc_lim = {
					.nb_max = MLX4_EN_MAX_RX_SIZE,
					.nb_min = MLX4_EN_MIN_RX_SIZE,
					.nb_align = 1,
			},
			.tx_desc_lim = {
					.nb_max = MLX4_EN_MAX_TX_SIZE,
					.nb_min = MLX4_EN_MIN_TX_SIZE,
					.nb_align = 1,
			},
	};

	memcpy(dev_info, &rte_info, sizeof(struct rte_eth_dev_info));
}

static int mlx4_eth_dev_configure(struct rte_eth_dev *dev)
{
	if(rte_persistent_init() < 0)
		return -1;
	/*
	 * Initialize driver private data
	 */

	struct mlx4_en_priv* priv = rtedev_priv(dev);
	priv->counter_index = 0xff;
	spin_lock_init(&priv->stats_lock);
#ifdef HAVE_VXLAN_ENABLED
	INIT_WORK(&priv->vxlan_add_task, mlx4_en_add_vxlan_offloads);
	INIT_WORK(&priv->vxlan_del_task, mlx4_en_del_vxlan_offloads);
#endif
#ifdef CONFIG_RFS_ACCEL
	INIT_LIST_HEAD(&priv->filters);
	spin_lock_init(&priv->filters_lock);
#endif

	int port = priv->port;
	struct mlx4_en_dev* mdev = priv->mdev;
	struct mlx4_en_port_profile* prof = priv->prof;
	priv->rte_dev = dev;
	//priv->mdev = mdev;
	//priv->prof = prof;
	//priv->port = port;
	priv->port_up = false;
	priv->flags = prof->flags;
	//priv->pflags = MLX4_EN_PRIV_FLAGS_BLUEFLAME;
	priv->pflags = 0; //disable blueflame
	priv->ctrl_flags = cpu_to_be32(MLX4_WQE_CTRL_CQ_UPDATE |
			MLX4_WQE_CTRL_SOLICITED);

	priv->cqe_factor = (mdev->dev->caps.cqe_size == 64) ? 1 : 0;
	priv->cqe_size = mdev->dev->caps.cqe_size;
	priv->mac_index = -1;
	priv->msg_enable = 0xFFFFFFFF;//MLX4_EN_MSG_LEVEL;

	int i, err;
	for (i = 0; i < MLX4_EN_MAC_HASH_SIZE; ++i)
		INIT_HLIST_HEAD(&priv->mac_hash[i]);

	/* Query for default mac and max mtu */
	priv->max_mtu = mdev->dev->caps.eth_mtu_cap[priv->port];

	if (mdev->dev->caps.rx_checksum_flags_port[priv->port] &
			MLX4_RX_CSUM_MODE_VAL_NON_TCP_UDP)
		priv->flags |= MLX4_EN_FLAG_RX_CSUM_NON_TCP_UDP;

	priv->stride = prof->inline_scatter_thold >= MIN_INLINE_SCATTER ?
			prof->inline_scatter_thold :
			roundup_pow_of_two(sizeof(struct mlx4_en_rx_desc) +
					DS_SIZE * MLX4_EN_MAX_RX_FRAGS);

	priv->allocated = 0;

	mdev->rte_pndev[port] = dev;
	mdev->rte_upper[port] = NULL;

	if(dev->data->dev_conf.rxmode.jumbo_frame)
		dev->data->mtu = dev->data->dev_conf.rxmode.max_rx_pkt_len;
	dev->data->mtu = RTE_MIN(priv->max_mtu, dev->data->mtu);
	int eff_mtu = dev->data->mtu + ETH_HLEN + VLAN_HLEN;
	priv->eff_mtu = eff_mtu;


	return 0;
}

int mlx4_eth_rx_queue_setup(struct rte_eth_dev *dev,
		uint16_t rx_queue_id,
		uint16_t nb_rx_desc,
		unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool)
{
	struct mlx4_en_priv* priv = rtedev_priv(dev);
	int port = priv->port;
	struct mlx4_en_dev* mdev = priv->mdev;
	struct mlx4_en_rx_ring* rxq = rte_zmalloc_socket("mlx4_rx_ring",
			sizeof(struct mlx4_en_rx_ring), RTE_CACHE_LINE_SIZE, dev->pci_dev->numa_node);
	rxq->mb_pool = mb_pool;
	int ret = mlx4_en_create_cq(priv, &rxq->rx_cq, nb_rx_desc, rx_queue_id, RX, dev->pci_dev->numa_node);
	if(ret < 0)
		return ret;

	{
		int stride = priv->stride;
		int size = nb_rx_desc;

		rxq->prod = 0;
		rxq->cons = 0;
		rxq->size = size;
		rxq->size_mask = size - 1;
		rxq->stride = stride;
		rxq->log_stride = ffs(rxq->stride) - 1;
		rxq->buf_size = rxq->size * rxq->stride + TXBB_SIZE;

		/* Allocate HW buffers on provided NUMA node */
		//set_dev_node(&mdev->dev->persist->pdev->dev, node);
		ret = mlx4_alloc_hwq_res(mdev->dev, &rxq->wqres,
				rxq->buf_size, 2 * PAGE_SIZE);
		//set_dev_node(&mdev->dev->persist->pdev->dev, mdev->dev->numa_node);
		if (ret)
			return ret;

		ret = mlx4_en_map_buffer(&rxq->wqres.buf);
		if (ret) {
			en_err(priv, "Failed to map RX buffer\n");
			return ret;
		}
		rxq->buf = rxq->wqres.buf.direct.buf;

		rxq->enable_hwtstamp = 0;
	}
	{
		int tmp;
		size_t frag_size = rte_pktmbuf_data_room_size(mb_pool) - RTE_PKTMBUF_HEADROOM;
		int eff_mtu = priv->eff_mtu;

		int buf_size = 0;
		int i = 0;

		while (buf_size < eff_mtu) {
			buf_size += frag_size;
			i++;
		}
		assert(i<=MLX4_EN_MAX_RX_FRAGS);
		rxq->num_frags = i;
		rxq->frag_size = frag_size;

		assert(rte_mempool_count(mb_pool) >= (rxq->num_frags * rxq->size));

		tmp = nb_rx_desc * sizeof(struct rte_mbuf*) * i;
		rxq->rx_info = rte_zmalloc_socket("mlx4_rx_info",
				tmp, RTE_CACHE_LINE_SIZE, dev->pci_dev->numa_node);
		if (!rxq->rx_info) {
			ret = -ENOMEM;
			return ret;
		}

		en_dbg(DRV, priv, "Allocated rx_info ring at addr:%p size:%d\n",
				rxq->rx_info, tmp);

		en_dbg(DRV, priv, "Rx buffer scatter-list (Q idx:%d effective-mtu:%d num_frags:%d):\n",
				rx_queue_id, eff_mtu, i);
	}
	dev->data->rx_queues[rx_queue_id] = rxq;
	return ret;
}

int mlx4_eth_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t tx_queue_id,
		uint16_t nb_tx_desc,
		unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf)
{
	int ret;

	struct mlx4_en_priv* priv = rtedev_priv(dev);
	int port = priv->port;
	struct mlx4_en_dev* mdev = priv->mdev;
	struct mlx4_en_tx_ring* txq = rte_zmalloc_socket("mlx4_tx_ring",
			sizeof(struct mlx4_en_tx_ring), RTE_CACHE_LINE_SIZE, dev->pci_dev->numa_node);
	ret = mlx4_en_create_cq(priv, &txq->tx_cq, nb_tx_desc, tx_queue_id, TX, dev->pci_dev->numa_node);
	if(ret < 0)
		return ret;

	{
		struct mlx4_en_dev *mdev = priv->mdev;
		struct mlx4_en_tx_ring *ring = txq;
		int tmp;
		int size = nb_tx_desc;
		int stride = TXBB_SIZE;
		int queue_index = tx_queue_id;

		ring->size = size;
		ring->size_mask = size - 1;
		ring->stride = stride;

		tmp = size * sizeof(struct mlx4_en_tx_info);
		ring->tx_info = rte_zmalloc_socket("mlx4_tx_info",
				tmp, RTE_CACHE_LINE_SIZE, dev->pci_dev->numa_node);
		if (!ring->tx_info) {
			ret = -ENOMEM;
			return ret;
		}

		en_dbg(DRV, priv, "Allocated tx_info ring at addr:%p size:%d\n",
				ring->tx_info, tmp);

		ring->bounce_buf = rte_zmalloc_socket("mlx4_tx_bounce",
				MAX_DESC_SIZE, RTE_CACHE_LINE_SIZE, dev->pci_dev->numa_node);
		if (!ring->bounce_buf) {
			ret = -ENOMEM;
			return ret;
		}
		ring->buf_size = ALIGN(size * ring->stride, MLX4_EN_PAGE_SIZE);

		/* Allocate HW buffers on provided NUMA node */
		//set_dev_node(&mdev->dev->persist->pdev->dev, node);
		ret = mlx4_alloc_hwq_res(mdev->dev, &ring->wqres, ring->buf_size,
				2 * PAGE_SIZE);
		//set_dev_node(&mdev->dev->persist->pdev->dev, mdev->dev->numa_node);
		if (ret) {
			en_err(priv, "Failed allocating hwq resources\n");
			return ret;
		}

		ret = mlx4_en_map_buffer(&ring->wqres.buf);
		if (ret) {
			en_err(priv, "Failed to map TX buffer\n");
			return ret;
		}

		ring->buf = ring->wqres.buf.direct.buf;

		en_dbg(DRV, priv, "Allocated TX ring (addr:%p) - buf:%p size:%d buf_size:%d dma:%llx\n",
				ring, ring->buf, ring->size, ring->buf_size,
				(unsigned long long) ring->wqres.buf.direct.map);

		ret = mlx4_qp_reserve_range(mdev->dev, 1, 1, &ring->qpn,
				MLX4_RESERVE_ETH_BF_QP);
		if (ret) {
			en_err(priv, "failed reserving qp for TX ring\n");
			return ret;
		}

		ret = mlx4_qp_alloc(mdev->dev, ring->qpn, &ring->qp, GFP_KERNEL);
		if (ret) {
			en_err(priv, "Failed allocating qp %d\n", ring->qpn);
			return ret;
		}
		ring->qp.event = mlx4_en_sqp_event;

		//ret = mlx4_bf_alloc(mdev->dev, &ring->bf, node);
		//if (ret)
		{
			en_dbg(DRV, priv, "working without blueflame (%d)\n", ret);
			ring->bf.uar = &mdev->priv_uar;
			ring->bf.uar->map = mdev->uar_map;
			ring->bf_enabled = false;
			ring->bf_alloced = false;
			priv->pflags &= ~MLX4_EN_PRIV_FLAGS_BLUEFLAME;
		}
		//else {
		//	ring->bf_alloced = true;
		//	ring->bf_enabled = !!(priv->pflags &
		//			MLX4_EN_PRIV_FLAGS_BLUEFLAME);
		//}

		//ring->hwtstamp_tx_type = priv->hwtstamp_config.tx_type;
		ring->enable_hwtstamp = 0;
		ring->queue_index = queue_index;

		//if (queue_index < priv->num_tx_rings_p_up && cpu_online(queue_index))
		//	cpumask_set_cpu(queue_index, &ring->affinity_mask);
	}
	dev->data->tx_queues[tx_queue_id] = txq;
	return ret;
}

uint16_t
mlx4_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct mlx4_en_rx_ring* ring = rx_queue;
	return mlx4_en_process_rx_cq(ring, rx_pkts, nb_pkts);
}

int mlx4_en_xmit(struct rte_mbuf *mbuf, struct mlx4_en_tx_ring *ring)
{
	struct rte_eth_dev* dev = ring->tx_cq.rte_dev;
	struct mlx4_en_priv *priv = rtedev_priv(dev);
	struct mlx4_en_tx_desc *tx_desc;
	struct mlx4_wqe_data_seg *data;
	struct mlx4_en_tx_info *tx_info;
	int nr_txbb;
	int desc_size;
	int real_size;
	u32 index;
	__be32 op_own;
	//u16 vlan_tag = 0;
	int i_frag;
	bool bounce = false;
	bool stop_queue;
	//u32 ring_cons;
	__be32 owner_bit;

	owner_bit = (ring->prod & ring->size) ?
		cpu_to_be32(MLX4_EN_BIT_DESC_OWN) : 0;

	/* fetch ring->cons far ahead before needing it to avoid stall */
	//ring_cons = ACCESS_ONCE(ring->cons);

	real_size = CTRL_SIZE + (mbuf->nb_segs) * DS_SIZE;

	/* Align descriptor to TXBB size */
	desc_size = ALIGN(real_size, TXBB_SIZE);
	nr_txbb = desc_size / TXBB_SIZE;
	if (unlikely(nr_txbb > MAX_DESC_TXBBS)) {
		en_warn(priv, "Oversized header or SG list\n");
		goto tx_drop;
	}

	//vlan_tag = mbuf->vlan_tci;



	/* Packet is good - grab an index and transmit it */
	index = ring->prod & ring->size_mask;

	/* See if we have enough space for whole descriptor TXBB for setting
	 * SW ownership on next descriptor; if not, use a bounce buffer. */
	if (likely(index + nr_txbb <= ring->size)) {
		tx_desc = ring->buf + index * TXBB_SIZE;
	} else {
		tx_desc = (struct mlx4_en_tx_desc *) ring->bounce_buf;
		bounce = true;
	}

	/* Save skb in tx_info ring */
	tx_info = &ring->tx_info[index];
	tx_info->mbuf = mbuf;
	tx_info->nr_txbb = nr_txbb;

	data = &tx_desc->data;


	{
		struct mlx4_wqe_data_seg * data_iter;
		struct rte_mbuf* mbuf_iter;
		dma_addr_t dma = 0;
		u32 byte_count = 0;

		/* Map fragments if any */
		mbuf_iter = mbuf;
		data_iter = data;
		for(i_frag = 0; i_frag < mbuf->nb_segs; i_frag++)
		{
			byte_count = rte_pktmbuf_data_len(mbuf_iter);
			dma = mbuf_iter->buf_physaddr + mbuf_iter->data_off;
			data_iter->addr = cpu_to_be64(dma);
			data_iter->lkey = ring->mr_key;
			wmb();
			data_iter->byte_count = SET_BYTE_COUNT(byte_count);
			++data_iter;
			mbuf_iter = mbuf_iter->next;
		}

		/* tx completion can avoid cache line miss for common cases */
		//tx_info->map0_dma = dma;
		//tx_info->map0_byte_count = byte_count;
	}


	/* Prepare ctrl segement apart opcode+ownership, which depends on
	 * whether LSO is used */
	tx_desc->ctrl.srcrb_flags = priv->ctrl_flags;
	if (mbuf->ol_flags & (PKT_TX_L4_MASK | PKT_TX_IP_CKSUM)) {
		tx_desc->ctrl.srcrb_flags |= cpu_to_be32(MLX4_WQE_CTRL_IP_CSUM |
							 MLX4_WQE_CTRL_TCP_UDP_CSUM);
	}

	if (priv->flags & MLX4_EN_FLAG_ENABLE_HW_LOOPBACK) {
		struct ethhdr *ethh;

		/* Copy dst mac address to wqe. This allows loopback in eSwitch,
		 * so that VFs and PF can communicate with each other
		 */
		ethh = rte_pktmbuf_mtod(mbuf, struct ethhdr *);
		tx_desc->ctrl.srcrb_flags16[0] = cpu_to_be16(*((__be16 *)ethh->h_dest));
		tx_desc->ctrl.imm = cpu_to_be32(*((__be32 *)(ethh->h_dest + 2)));
	}

	{
		/* Normal (Non LSO) packet */
		op_own = cpu_to_be32(MLX4_OPCODE_SEND);
	}

	op_own |= owner_bit;

	ring->prod += nr_txbb;

	/* If we used a bounce buffer then copy descriptor back into place */
	if (unlikely(bounce))
		tx_desc = mlx4_en_bounce_to_desc(priv, ring, index, desc_size);



	real_size = (real_size / 16) & 0x3f;

	{
		tx_desc->ctrl.vlan_tag = 0;//cpu_to_be16(vlan_tag);
		//tx_desc->ctrl.ins_vlan = MLX4_WQE_CTRL_INS_VLAN *
//			!!mbuf->vlan_tci;
		tx_desc->ctrl.ins_vlan = 0;
		tx_desc->ctrl.fence_size = real_size;

		/* Ensure new descriptor hits memory
		 * before setting ownership of this descriptor to HW
		 */
		wmb();
		tx_desc->ctrl.owner_opcode = op_own;

	}
	return 1;

tx_drop:
	rte_pktmbuf_free(mbuf);
	return 1;
}



uint16_t
mlx4_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	struct mlx4_en_tx_ring* ring = tx_queue;

	uint16_t sent = 0;
	mlx4_en_process_tx_cq(ring);
	while(sent < nb_pkts)
	{
		if(mlx4_txq_is_full(ring))
			break;
		sent += mlx4_en_xmit(tx_pkts[sent], ring);
	}
	if(sent > 0)
	{
		wmb();
		/* Since there is no iowrite*_native() that writes the
		 * value as is, without byteswapping - using the one
		 * the doesn't do byteswapping in the relevant arch
		 * endianness.
		 */
		write32(
				ring->doorbell_qpn,
				ring->bf.uar->map + MLX4_SEND_DOORBELL);
	}
	return sent;
}


int mlx4_en_dev_link_update(struct rte_eth_dev *eth_dev, int wait_to_complete)
{
	struct mlx4_en_priv *en_priv = rtedev_priv(eth_dev);
	int ret = mlx4_en_QUERY_PORT(en_priv->mdev, en_priv->port);
	assert(ret == 0);

	eth_dev->data->dev_link.link_status = en_priv->port_state.link_state;
	eth_dev->data->dev_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	switch(en_priv->port_state.link_speed)
	{
	case SPEED_100:
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_100;
		break;
	case SPEED_1000:
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_1000;
		break;
	case SPEED_10000:
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_10G;
		break;
	case SPEED_20000:
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_20G;
		break;
	case SPEED_40000:
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_40G;
		break;
	case SPEED_56000:
		RTE_LOG(WARNING, EAL, "56G is not recognized in DPDK, assume as 40G");
		eth_dev->data->dev_link.link_speed = ETH_LINK_SPEED_40G;
		break;
	case -1:
		msleep(500);
		break;
	default:
		RTE_LOG(ERR, EAL, "Unknown link type %d", en_priv->port_state.link_speed);
		break;
	}

	return 0;
}

void mlx4_en_dev_promiscuous_enable(struct rte_eth_dev *eth_dev)
{
	struct mlx4_en_priv *priv = rtedev_priv(eth_dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	{
		int err = 0;

		if (!(priv->flags & MLX4_EN_FLAG_PROMISC)) {
			//if (netif_msg_rx_status(priv))
			en_warn(priv, "Entering promiscuous mode\n");
			priv->flags |= MLX4_EN_FLAG_PROMISC;

			/* Enable promiscouos mode */
			switch (mdev->dev->caps.steering_mode) {
			case MLX4_STEERING_MODE_DEVICE_MANAGED:
				err = mlx4_flow_steer_promisc_add(mdev->dev,
						priv->port,
						priv->base_qpn,
						MLX4_FS_ALL_DEFAULT);
				if (err)
					en_err(priv, "Failed enabling promiscuous mode\n");
				priv->flags |= MLX4_EN_FLAG_MC_PROMISC;
				break;

			case MLX4_STEERING_MODE_B0:
				err = mlx4_unicast_promisc_add(mdev->dev,
						priv->base_qpn,
						priv->port);
				if (err)
					en_err(priv, "Failed enabling unicast promiscuous mode\n");

				/* Add the default qp number as multicast
				 * promisc
				 */
				if (!(priv->flags & MLX4_EN_FLAG_MC_PROMISC)) {
					err = mlx4_multicast_promisc_add(mdev->dev,
							priv->base_qpn,
							priv->port);
					if (err)
						en_err(priv, "Failed enabling multicast promiscuous mode\n");
					priv->flags |= MLX4_EN_FLAG_MC_PROMISC;
				}
				break;

			case MLX4_STEERING_MODE_A0:
				err = mlx4_SET_PORT_qpn_calc(mdev->dev,
						priv->port,
						priv->base_qpn,
						1);
				if (err)
					en_err(priv, "Failed enabling promiscuous mode\n");
				break;
			}

			/* Disable port multicast filter (unconditionally) */
			err = mlx4_SET_MCAST_FLTR(mdev->dev, priv->port, 0,
					0, MLX4_MCAST_DISABLE);
			if (err)
				en_err(priv, "Failed disabling multicast filter\n");
		}
	}
}
void mlx4_en_dev_promiscuous_disable(struct rte_eth_dev *eth_dev)
{
	struct mlx4_en_priv *priv = rtedev_priv(eth_dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	{
		int err = 0;

		//if (netif_msg_rx_status(priv))
		en_warn(priv, "Leaving promiscuous mode\n");
		priv->flags &= ~MLX4_EN_FLAG_PROMISC;

		/* Disable promiscouos mode */
		switch (mdev->dev->caps.steering_mode) {
		case MLX4_STEERING_MODE_DEVICE_MANAGED:
			err = mlx4_flow_steer_promisc_remove(mdev->dev,
					priv->port,
					MLX4_FS_ALL_DEFAULT);
			if (err)
				en_err(priv, "Failed disabling promiscuous mode\n");
			priv->flags &= ~MLX4_EN_FLAG_MC_PROMISC;
			break;

		case MLX4_STEERING_MODE_B0:
			err = mlx4_unicast_promisc_remove(mdev->dev,
					priv->base_qpn,
					priv->port);
			if (err)
				en_err(priv, "Failed disabling unicast promiscuous mode\n");
			/* Disable Multicast promisc */
			if (priv->flags & MLX4_EN_FLAG_MC_PROMISC) {
				err = mlx4_multicast_promisc_remove(mdev->dev,
						priv->base_qpn,
						priv->port);
				if (err)
					en_err(priv, "Failed disabling multicast promiscuous mode\n");
				priv->flags &= ~MLX4_EN_FLAG_MC_PROMISC;
			}
			break;

		case MLX4_STEERING_MODE_A0:
			err = mlx4_SET_PORT_qpn_calc(mdev->dev,
					priv->port,
					priv->base_qpn, 0);
			if (err)
				en_err(priv, "Failed disabling promiscuous mode\n");
			break;
		}
	}
}

static unsigned long en_stats_adder(__be64 *start, __be64 *next, int num)
{
	__be64 *curr = start;
	unsigned long ret = 0;
	int i;
	int offset = next - start;

	for (i = 0; i < num; i++) {
		ret += be64_to_cpu(*curr);
		curr += offset;
	}

	return ret;
}

void mlx4_en_dev_stats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_stats *igb_stats)
{
	struct mlx4_en_priv *priv = rtedev_priv(eth_dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int port = priv->port;
	int reset = priv->stat_reset;
	{
		priv->stat_reset = 0;
		struct mlx4_en_vport_stats tmp_vport_stats;
		struct mlx4_en_stat_out_mbox *mlx4_en_stats;
		struct mlx4_en_stat_out_flow_control_mbox *flowstats;
		struct mlx4_en_vport_stats *vport_stats = &priv->vport_stats;
		struct mlx4_cmd_mailbox *mailbox;
		u64 in_mod = reset << 8 | port;
		int err;
		int i, read_counters = 0;;

		mailbox = mlx4_alloc_cmd_mailbox(mdev->dev);
		if (IS_ERR(mailbox))
			return;// PTR_ERR(mailbox);
		err = mlx4_cmd_box(mdev->dev, 0, mailbox->dma, in_mod, 0,
				MLX4_CMD_DUMP_ETH_STATS, MLX4_CMD_TIME_CLASS_B,
				MLX4_CMD_NATIVE);
		if (err)
			goto out;

		mlx4_en_stats = mailbox->buf;


		/* net device stats */
		igb_stats->ierrors = be64_to_cpu(mlx4_en_stats->PCS) +
				be32_to_cpu(mlx4_en_stats->RJBBR) +
				be32_to_cpu(mlx4_en_stats->RCRC) +
				be32_to_cpu(mlx4_en_stats->RRUNT) +
				be64_to_cpu(mlx4_en_stats->RInRangeLengthErr) +
				be64_to_cpu(mlx4_en_stats->ROutRangeLengthErr) +
				be32_to_cpu(mlx4_en_stats->RSHORT) +
				en_stats_adder(&mlx4_en_stats->RGIANT_prio_0,
						&mlx4_en_stats->RGIANT_prio_1,
						NUM_PRIORITIES);
		igb_stats->oerrors = en_stats_adder(&mlx4_en_stats->TGIANT_prio_0,
				&mlx4_en_stats->TGIANT_prio_1,
				NUM_PRIORITIES);
		igb_stats->imcasts = en_stats_adder(&mlx4_en_stats->MCAST_prio_0,
				&mlx4_en_stats->MCAST_prio_1,
				NUM_PRIORITIES);
		igb_stats->imissed = be32_to_cpu(mlx4_en_stats->RDROP);
		igb_stats->ibadlen = be32_to_cpu(mlx4_en_stats->RdropLength);
		igb_stats->ibadcrc = be32_to_cpu(mlx4_en_stats->RCRC);
		igb_stats->oerrors += be32_to_cpu(mlx4_en_stats->TDROP);

		/* RX stats */
		igb_stats->ipackets = en_stats_adder(&mlx4_en_stats->RTOT_prio_0,
				&mlx4_en_stats->RTOT_prio_1,
				NUM_PRIORITIES);
		igb_stats->ibytes = en_stats_adder(&mlx4_en_stats->ROCT_prio_0,
				&mlx4_en_stats->ROCT_prio_1,
				NUM_PRIORITIES);


		/* Tx stats */
		igb_stats->opackets = en_stats_adder(&mlx4_en_stats->TTOT_prio_0,
				&mlx4_en_stats->TTOT_prio_1,
				NUM_PRIORITIES);
		igb_stats->obytes = en_stats_adder(&mlx4_en_stats->TOCT_prio_0,
				&mlx4_en_stats->TOCT_prio_1,
				NUM_PRIORITIES);


		out:
		mlx4_free_cmd_mailbox(mdev->dev, mailbox);
	}
}

void mlx4_en_dev_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct mlx4_en_priv *priv = rtedev_priv(eth_dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int port = priv->port;
	int reset = 1;
	if(priv->stat_reset)
	{
		priv->stat_reset = 0;
		struct mlx4_cmd_mailbox *mailbox;
		u64 in_mod = reset << 8 | port;

		mailbox = mlx4_alloc_cmd_mailbox(mdev->dev);
		if (IS_ERR(mailbox))
			return;// PTR_ERR(mailbox);
		mlx4_cmd_box(mdev->dev, 0, mailbox->dma, in_mod, 0,
				MLX4_CMD_DUMP_ETH_STATS, MLX4_CMD_TIME_CLASS_B,
				MLX4_CMD_NATIVE);
		mlx4_free_cmd_mailbox(mdev->dev, mailbox);
	}
	else
		priv->stat_reset = 1;
}

int mlx4_en_dev_start(struct rte_eth_dev *dev)
{
	struct mlx4_en_priv *priv = rtedev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_cq *cq;
	struct mlx4_en_tx_ring *tx_ring;
	struct mlx4_en_rx_ring *rx_ring;
	int rx_index = 0;
	int tx_index = 0;
	int err = 0;
	int i;
	int j;
	u8 mc_list[16] = {0};

	if (priv->port_up) {
		en_dbg(DRV, priv, "start port called while port already up\n");
		return 0;
	}

	INIT_LIST_HEAD(&priv->mc_list);
	INIT_LIST_HEAD(&priv->curr_list);
	INIT_LIST_HEAD(&priv->ethtool_list);
	memset(&priv->ethtool_rules[0], 0,
	       sizeof(struct ethtool_flow_id) * MAX_NUM_OF_FS_RULES);

	/* Calculate Rx buf size */
	//dev->data->mtu = min(dev->data->mtu, priv->max_mtu);
	//mlx4_en_calc_rx_buf(dev);
	//en_dbg(DRV, priv, "Rx buf size:%d\n", priv->rx_skb_size);

	/* Configure rx cq's and rings */
	err = mlx4_en_activate_rx_rings(priv);
	if (err) {
		en_err(priv, "Failed to activate RX rings\n");
		return err;
	}
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rx_ring = dev->data->rx_queues[i];
		cq = &rx_ring->rx_cq;

		err = mlx4_en_activate_cq(priv, cq, i, rx_ring->enable_hwtstamp);
		if (err) {
			en_err(priv, "Failed activating Rx CQ\n");
			//mlx4_en_free_affinity_hint(priv, i);
			return err;
		}

		for (j = 0; j < cq->size; j++) {
			struct mlx4_cqe *cqe = NULL;

			cqe = mlx4_en_get_cqe(cq->buf, j, priv->cqe_size) +
			      priv->cqe_factor;
			cqe->owner_sr_opcode = MLX4_CQE_OWNER_MASK;
		}

		err = mlx4_en_set_cq_moder(priv, cq);
		if (err) {
			en_err(priv, "Failed setting cq moderation parameters\n");
			mlx4_en_deactivate_cq(priv, cq);
			//mlx4_en_free_affinity_hint(priv, i);
			return err;
		}
		//mlx4_en_arm_cq(priv, cq);
		//priv->rx_ring[i]->cqn = cq->mcq.cqn;
		++rx_index;
	}

	/* Set qp number */
	en_dbg(DRV, priv, "Getting qp number for port %d\n", priv->port);
	err = mlx4_en_get_qp(priv);
	if (err) {
		en_err(priv, "Failed getting eth qp\n");
		return err;
	}
	mdev->mac_removed[priv->port] = 0;

	/* gets default allocated counter index from func cap */
	/* or sink counter index if no resources */
	priv->counter_index = mdev->dev->caps.def_counter_index[priv->port - 1];

	en_dbg(DRV, priv, "%s: default counter index %d for port %d\n",
	       __func__, priv->counter_index, priv->port);

	err = mlx4_en_config_rss_steer(dev);
	if (err) {
		en_err(priv, "Failed configuring rss steering\n");
		return err;
	}

	err = mlx4_en_create_drop_qp(priv);
	if (err)
		return err;

	/* Configure tx cq's and rings */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		/* Configure cq */
		tx_ring = dev->data->tx_queues[i];
		cq = &tx_ring->tx_cq;
		err = mlx4_en_activate_cq(priv, cq, i, tx_ring->enable_hwtstamp);
		if (err) {
			en_err(priv, "Failed allocating Tx CQ\n");
			return err;
		}
		err = mlx4_en_set_cq_moder(priv, cq);
		if (err) {
			en_err(priv, "Failed setting cq moderation parameters\n");
			mlx4_en_deactivate_cq(priv, cq);
			return err;
		}
		en_dbg(DRV, priv, "Resetting index of collapsed CQ:%d to -1\n", i);
		cq->buf->wqe_index = cpu_to_be16(0xffff);

		/* Configure ring */
		//tx_ring = priv->tx_ring[i];
#ifdef HAVE_NEW_TX_RING_SCHEME
		err = mlx4_en_activate_tx_ring(priv, tx_ring, cq->mcq.cqn,
			i / priv->num_tx_rings_p_up);
#else
		err = mlx4_en_activate_tx_ring(priv, tx_ring, cq->mcq.cqn);
#endif
		if (err) {
			en_err(priv, "Failed allocating Tx ring\n");
			mlx4_en_deactivate_cq(priv, cq);
			return err;
		}
		//tx_ring->tx_queue = netdev_get_tx_queue(dev, i);

		/* Arm CQ for TX completions */
		//mlx4_en_arm_cq(priv, cq);

		/* Set initial ownership of all Tx TXBBs to SW (1) */
		for (j = 0; j < tx_ring->buf_size; j += STAMP_STRIDE)
			*((u32 *) (tx_ring->buf + j)) = INIT_OWNER_BIT;
		++tx_index;
	}

	/* Configure port */
	err = mlx4_SET_PORT_general(mdev->dev, priv->port,
				    priv->eff_mtu + ETH_FCS_LEN,
				    priv->prof->tx_pause,
				    priv->prof->tx_ppp,
				    priv->prof->rx_pause,
				    priv->prof->rx_ppp);
	if (err) {
		en_err(priv, "Failed setting port general configurations for port %d, with error %d\n",
		       priv->port, err);
		return err;
	}
	/* Set default qp number */
	err = mlx4_SET_PORT_qpn_calc(mdev->dev, priv->port, priv->base_qpn, 0);
	if (err) {
		en_err(priv, "Failed setting default qp numbers\n");
		return err;
	}

	if (mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN) {
		err = mlx4_SET_PORT_VXLAN(mdev->dev, priv->port, VXLAN_STEER_BY_OUTER_MAC, 1);
		if (err) {
			en_err(priv, "Failed setting port L2 tunnel configuration, err %d\n",
			       err);
			return err;
		}
	}

	/* Init port */
	en_dbg(HW, priv, "Initializing port\n");
	err = mlx4_INIT_PORT(mdev->dev, priv->port);
	if (err) {
		en_err(priv, "Failed Initializing port\n");
		return err;
	}

	/* Attach rx QP to bradcast address */
	memset(&mc_list[10], 0xff, ETH_ALEN);
	mc_list[5] = priv->port; /* needed for B0 steering support */
	if (mlx4_multicast_attach(mdev->dev, &priv->rss_map.indir_qp, mc_list,
				  priv->port, 0, MLX4_PROT_ETH,
				  &priv->broadcast_id))
		mlx4_warn(mdev, "Failed Attaching Broadcast\n");

	/* Must redo promiscuous mode setup. */
	priv->flags &= ~(MLX4_EN_FLAG_PROMISC | MLX4_EN_FLAG_MC_PROMISC);

	/* Schedule multicast task to populate multicast list */
	//queue_work(mdev->workqueue, &priv->rx_mode_task);

#ifdef HAVE_VXLAN_DYNAMIC_PORT
	if (priv->mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN)
		vxlan_get_rx_port(dev);
#endif

	priv->port_up = true;
	//netif_tx_start_all_queues(dev);
	//netif_device_attach(dev);
	assert(dev->data->nb_rx_queues == rx_index);
	assert(dev->data->nb_tx_queues == tx_index);

	return 0;
}


const struct eth_dev_ops mlx4_eth_dev_ops = {
		.dev_configure = mlx4_eth_dev_configure,
		.dev_infos_get = mlx4_eth_dev_infos_get,
		.rx_queue_setup = mlx4_eth_rx_queue_setup,
		.tx_queue_setup = mlx4_eth_tx_queue_setup,
		.link_update = mlx4_en_dev_link_update,
		.promiscuous_enable = mlx4_en_dev_promiscuous_enable,
		.promiscuous_disable = mlx4_en_dev_promiscuous_disable,
		.stats_get = mlx4_en_dev_stats_get,
		.stats_reset = mlx4_en_dev_stats_reset,
		.dev_start = mlx4_en_dev_start,
};


int mlx4_set_tx_timestamp(int port, int queue_id, int use)
{
	struct mlx4_en_tx_ring* ring = rte_eth_devices[port].data->tx_queues[queue_id];
	ring->enable_hwtstamp = !!use;
	return 0;
}
int mlx4_set_rx_timestamp(int port, int queue_id, int use)
{
	struct mlx4_en_rx_ring* ring = rte_eth_devices[port].data->rx_queues[queue_id];
	ring->enable_hwtstamp = !!use;
	return 0;
}

int mlx4_poll_tx_cq(int port, int txq)
{
	struct mlx4_en_tx_ring* ring = rte_eth_devices[port].data->tx_queues[txq];
	return mlx4_en_process_tx_cq(ring);
}
int mlx4_set_tx_completion_callback(int port, int queue_id, mlx4_tx_completion_callback_t callback, void* arg)
{
	struct mlx4_en_tx_ring* ring = rte_eth_devices[port].data->tx_queues[queue_id];
	ring->tx_tstamp_callback = callback;
	ring->tx_tstamp_callback_arg = arg;
	return 0;
}
uint64_t mlx4_read_dev_clock_hz(int port)
{
	struct mlx4_en_priv* priv = rte_eth_devices[port].data->dev_private;
	return priv->mdev->dev->caps.hca_core_clock * 1000000UL; //MHz
}
uint64_t mlx4_read_dev_clock(int port)
{
	struct mlx4_en_priv* priv = rte_eth_devices[port].data->dev_private;
	return mlx4_read_clock(priv->mdev->dev);
}
