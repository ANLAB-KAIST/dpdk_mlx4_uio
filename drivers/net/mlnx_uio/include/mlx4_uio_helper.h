/*
 * mlx4_uio_helper.h
 *
 *  Created on: Jul 1, 2015
 *      Author: leeopop
 */

#ifndef DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_HELPER_H_
#define DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_HELPER_H_

#include "kmod.h"
#include "mlnx/mlx4/mlx4_en.h"
#include "log2.h"

static void mlx4_en_u64_to_mac(unsigned char dst_mac[ETH_ALEN], u64 src_mac)
{
	int i;
	for (i = ETH_ALEN - 1; i >= 0; --i) {
		dst_mac[i] = src_mac & 0xff;
		src_mac >>= 8;
	}
}

static int mlx4_en_uc_steer_add(struct mlx4_en_priv *priv,
				unsigned char *mac, int *qpn, u64 *reg_id)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	int err;

	switch (dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_B0: {
		struct mlx4_qp qp;
		u8 gid[16] = {0};

		qp.qpn = *qpn;
		memcpy(&gid[10], mac, ETH_ALEN);
		gid[5] = priv->port;

		err = mlx4_unicast_attach(dev, &qp, gid, 0, MLX4_PROT_ETH);
		break;
	}
	case MLX4_STEERING_MODE_DEVICE_MANAGED: {
		struct mlx4_spec_list spec_eth = { {NULL} };
		__be64 mac_mask = cpu_to_be64(MLX4_MAC_MASK << 16);

		struct mlx4_net_trans_rule rule = {
			.queue_mode = MLX4_NET_TRANS_Q_FIFO,
			.exclusive = 0,
			.allow_loopback = 1,
			.promisc_mode = MLX4_FS_REGULAR,
			.priority = MLX4_DOMAIN_NIC,
		};

		rule.port = priv->port;
		rule.qpn = *qpn;
		INIT_LIST_HEAD(&rule.list);

		spec_eth.id = MLX4_NET_TRANS_RULE_ID_ETH;
		memcpy(spec_eth.eth.dst_mac, mac, ETH_ALEN);
		memcpy(spec_eth.eth.dst_mac_msk, &mac_mask, ETH_ALEN);
		list_add_tail(&spec_eth.list, &rule.list);

		err = mlx4_flow_attach(dev, &rule, reg_id);
		break;
	}
	default:
		return -EINVAL;
	}
	if (err)
		en_warn(priv, "Failed Attaching Unicast\n");

	return err;
}

static int mlx4_en_tunnel_steer_add(struct mlx4_en_priv *priv, unsigned char *addr,
				    int qpn, u64 *reg_id)
{
	int err;

	if (priv->mdev->dev->caps.tunnel_offload_mode != MLX4_TUNNEL_OFFLOAD_MODE_VXLAN ||
	    priv->mdev->dev->caps.dmfs_high_steer_mode == MLX4_STEERING_DMFS_A0_STATIC)
		return 0; /* do nothing */

	err = mlx4_tunnel_steer_add(priv->mdev->dev, addr, priv->port, qpn,
				    MLX4_DOMAIN_NIC, reg_id);
	if (err) {
		en_err(priv, "failed to add vxlan steering rule, err %d\n", err);
		return err;
	}
	en_dbg(DRV, priv, "added vxlan steering rule, mac %pM reg_id %llx\n", addr, *reg_id);
	return 0;
}

static void mlx4_en_uc_steer_release(struct mlx4_en_priv *priv,
				     unsigned char *mac, int qpn, u64 reg_id)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;

	switch (dev->caps.steering_mode) {
	case MLX4_STEERING_MODE_B0: {
		struct mlx4_qp qp;
		u8 gid[16] = {0};

		qp.qpn = qpn;
		memcpy(&gid[10], mac, ETH_ALEN);
		gid[5] = priv->port;

		mlx4_unicast_detach(dev, &qp, gid, MLX4_PROT_ETH);
		break;
	}
	case MLX4_STEERING_MODE_DEVICE_MANAGED: {
		mlx4_flow_detach(dev, reg_id);
		break;
	}
	default:
		en_err(priv, "Invalid steering mode.\n");
	}
}


static int mlx4_en_get_qp(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_dev *dev = mdev->dev;
	struct mlx4_mac_entry *entry;
	int index = 0;
	int err = 0;
	u64 reg_id = 0;
	int *qpn = &priv->base_qpn;
	u64 mac = mlx4_mac_to_u64(priv->current_mac);

	en_dbg(DRV, priv, "Registering MAC: %pM for adding\n",
			priv->current_mac);
	index = mlx4_register_mac(dev, priv->port, mac);
	if (index < 0) {
		err = index;
		en_err(priv, "Failed adding MAC: %pM\n",
				priv->current_mac);
		return err;
	}

	if (dev->caps.steering_mode == MLX4_STEERING_MODE_A0) {
		int base_qpn = mlx4_get_base_qpn(dev, priv->port);
		*qpn = base_qpn + index;
		return 0;
	}

	err = mlx4_qp_reserve_range(dev, 1, 1, qpn, MLX4_RESERVE_A0_QP);
	en_dbg(DRV, priv, "Reserved qp %d\n", *qpn);
	if (err) {
		en_err(priv, "Failed to reserve qp for mac registration\n");
		goto qp_err;
	}

	err = mlx4_en_uc_steer_add(priv, priv->current_mac, qpn, &reg_id);
	if (err)
		goto steer_err;

	err = mlx4_en_tunnel_steer_add(priv, priv->current_mac, *qpn,
				       &priv->tunnel_reg_id);
	if (err)
		goto tunnel_err;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		err = -ENOMEM;
		goto alloc_err;
	}
	memcpy(entry->mac, priv->current_mac, sizeof(entry->mac));
	memcpy(priv->current_mac, entry->mac, sizeof(priv->current_mac));
	entry->reg_id = reg_id;

	hlist_add_head(&entry->hlist,
			   &priv->mac_hash[entry->mac[MLX4_EN_MAC_HASH_IDX]]);

	return 0;

alloc_err:
	if (priv->tunnel_reg_id)
		mlx4_flow_detach(priv->mdev->dev, priv->tunnel_reg_id);
tunnel_err:
	mlx4_en_uc_steer_release(priv, priv->current_mac, *qpn, reg_id);

steer_err:
	mlx4_qp_release_range(dev, *qpn, 1);

qp_err:
	mlx4_unregister_mac(dev, priv->port, mac);
	return err;
}

static inline void mlx4_en_update_rx_prod_db(struct mlx4_en_rx_ring *ring)
{
	*ring->wqres.db.db = cpu_to_be32(ring->prod & 0xffff);
}

static int mlx4_en_config_rss_qp(struct mlx4_en_priv *priv, int qpn,
				 struct mlx4_en_rx_ring *ring,
				 enum mlx4_qp_state *state,
				 struct mlx4_qp *qp)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_qp_context *context;
	int err = 0;

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;

	err = mlx4_qp_alloc(mdev->dev, qpn, qp, GFP_KERNEL);
	if (err) {
		en_err(priv, "Failed to allocate qp #%x\n", qpn);
		goto out;
	}
	qp->event = mlx4_en_sqp_event;

	memset(context, 0, sizeof *context);
#ifdef HAVE_NEW_TX_RING_SCHEME
	mlx4_en_fill_qp_context(priv, ring->actual_size, ring->stride, 0, 0,
				qpn, ring->cqn, -1, context);
#else
	mlx4_en_fill_qp_context(priv, ring->actual_size, ring->stride, 0, 0,
				qpn, ring->rx_cq.mcq.cqn, context);
#endif
	context->db_rec_addr = cpu_to_be64(ring->wqres.db.dma);

	/* Cancel FCS removal if FW allows */
	if (mdev->dev->caps.flags & MLX4_DEV_CAP_FLAG_FCS_KEEP) {
		context->param3 |= cpu_to_be32(1 << 29);
#ifdef HAVE_NETIF_F_RXFCS
		if (priv->dev->features & NETIF_F_RXFCS)
#else
		//if (priv->pflags & MLX4_EN_PRIV_FLAGS_RXFCS)
#endif
			ring->fcs_del = 0;
		//else
		//	ring->fcs_del = ETH_FCS_LEN;
	} else
		ring->fcs_del = 0;

	err = mlx4_qp_to_ready(mdev->dev, &ring->wqres.mtt, context, qp, state);
	if (err) {
		mlx4_qp_remove(mdev->dev, qp);
		mlx4_qp_free(mdev->dev, qp);
	}
	mlx4_en_update_rx_prod_db(ring);
out:
	kfree(context);
	return err;
}

/* Allocate rx qp's and configure them according to rss map */
static int mlx4_en_config_rss_steer(struct rte_eth_dev *dev)
{
	struct mlx4_en_priv* priv = rtedev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rss_map *rss_map = &priv->rss_map;
	struct mlx4_qp_context context;
	struct mlx4_rss_context *rss_context;
	int rss_rings;
	void *ptr;
	u8 rss_mask = (MLX4_RSS_IPV4 | MLX4_RSS_TCP_IPV4 | MLX4_RSS_IPV6 |
			MLX4_RSS_TCP_IPV6);
	int i, qpn;
	int err = 0;
	int good_qps = 0;
#ifndef HAVE_NETDEV_RSS_KEY_FILL
	static const u32 rsskey[MLX4_EN_RSS_KEY_SIZE] = { 0xD181C62C, 0xF7F4DB5B, 0x1983A2FC,
		0x943E1ADB, 0xD9389E6B, 0xD1039C2C, 0xA74499AD,
		0x593D56D9, 0xF3253C06, 0x2ADC1FFC};
#endif

	en_dbg(DRV, priv, "Configuring rss steering\n");
	err = mlx4_qp_reserve_range(mdev->dev, dev->data->nb_rx_queues,
				    dev->data->nb_rx_queues,
				    &rss_map->base_qpn, 0);
	if (err) {
		en_err(priv, "Failed reserving %d qps\n", dev->data->nb_rx_queues);
		return err;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		qpn = rss_map->base_qpn + i;
		err = mlx4_en_config_rss_qp(priv, qpn, dev->data->rx_queues[i],
					    &rss_map->state[i],
					    &rss_map->qps[i]);
		if (err)
			goto rss_err;

		++good_qps;
	}

	/* Configure RSS indirection qp */
	err = mlx4_qp_alloc(mdev->dev, priv->base_qpn, &rss_map->indir_qp, GFP_KERNEL);
	if (err) {
		en_err(priv, "Failed to allocate RSS indirection QP\n");
		goto rss_err;
	}
	rss_map->indir_qp.event = mlx4_en_sqp_event;
#ifdef HAVE_NEW_TX_RING_SCHEME
	mlx4_en_fill_qp_context(priv, 0, 0, 0, 1, priv->base_qpn,
				priv->rx_ring[0]->cqn, -1, &context);
#else
	mlx4_en_fill_qp_context(priv, 0, 0, 0, 1, priv->base_qpn,
				((struct mlx4_en_rx_ring*)(dev->data->rx_queues[0]))->rx_cq.mcq.cqn, &context);
#endif

	rss_rings = dev->data->nb_rx_queues;
	/*
	if (!priv->prof->rss_rings || priv->prof->rss_rings > dev->data->nb_rx_queues)
		rss_rings = dev->data->nb_rx_queues;
	else
		rss_rings = priv->prof->rss_rings;
		*/

	ptr = ((void *) &context) + offsetof(struct mlx4_qp_context, pri_path)
					+ MLX4_RSS_OFFSET_IN_QPC_PRI_PATH;
	rss_context = ptr;
	rss_context->base_qpn = cpu_to_be32(ilog2(rss_rings) << 24 |
					    (rss_map->base_qpn));
	rss_context->default_qpn = cpu_to_be32(rss_map->base_qpn);
	if (priv->mdev->profile.udp_rss) {
		rss_mask |=  MLX4_RSS_UDP_IPV4 | MLX4_RSS_UDP_IPV6;
		rss_context->base_qpn_udp = rss_context->default_qpn;
	}

	if (mdev->dev->caps.tunnel_offload_mode == MLX4_TUNNEL_OFFLOAD_MODE_VXLAN) {
		en_info(priv, "Setting RSS context tunnel type to RSS on inner headers\n");
		rss_mask |= MLX4_RSS_BY_INNER_HEADERS;
	}

	rss_context->flags = rss_mask;
	rss_context->hash_fn = MLX4_RSS_HASH_TOP;
#ifdef HAVE_ETH_SS_RSS_HASH_FUNCS
	if (priv->rss_hash_fn == ETH_RSS_HASH_XOR) {
		rss_context->hash_fn = MLX4_RSS_HASH_XOR;
	} else if (priv->rss_hash_fn == ETH_RSS_HASH_TOP) {
		rss_context->hash_fn = MLX4_RSS_HASH_TOP;
		memcpy(rss_context->rss_key, priv->rss_key,
		       MLX4_EN_RSS_KEY_SIZE);
#ifdef HAVE_NETDEV_RSS_KEY_FILL
		netdev_rss_key_fill(rss_context->rss_key,
				    MLX4_EN_RSS_KEY_SIZE);
#else
		for (i = 0; i < MLX4_EN_RSS_KEY_SIZE; i++)
			rss_context->rss_key[i] = cpu_to_be32(rsskey[i]);
#endif
	} else {
		en_err(priv, "Unknown RSS hash function requested\n");
		err = -EINVAL;
		goto indir_err;
	}
#else
#ifndef HAVE_NETDEV_RSS_KEY_FILL
	for (i = 0; i < MLX4_EN_RSS_KEY_SIZE; i++)
		rss_context->rss_key[i] = cpu_to_be32(rsskey[i]);
#else
	memcpy(rss_context->rss_key, priv->rss_key, MLX4_EN_RSS_KEY_SIZE);
#endif
#endif
	err = mlx4_qp_to_ready(mdev->dev, &priv->res.mtt, &context,
			       &rss_map->indir_qp, &rss_map->indir_state);
	if (err)
		goto indir_err;

	return 0;

indir_err:
	mlx4_qp_modify(mdev->dev, NULL, rss_map->indir_state,
		       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->indir_qp);
	mlx4_qp_remove(mdev->dev, &rss_map->indir_qp);
	mlx4_qp_free(mdev->dev, &rss_map->indir_qp);
rss_err:
	for (i = 0; i < good_qps; i++) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[i],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[i]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[i]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[i]);
	}
	mlx4_qp_release_range(mdev->dev, rss_map->base_qpn, dev->data->nb_rx_queues);
	return err;
}

static int mlx4_en_create_drop_qp(struct mlx4_en_priv *priv)
{
	int err;
	u32 qpn;

	err = mlx4_qp_reserve_range(priv->mdev->dev, 1, 1, &qpn,
				    MLX4_RESERVE_A0_QP);
	if (err) {
		en_err(priv, "Failed reserving drop qpn\n");
		return err;
	}
	err = mlx4_qp_alloc(priv->mdev->dev, qpn, &priv->drop_qp, GFP_KERNEL);
	if (err) {
		en_err(priv, "Failed allocating drop qp\n");
		mlx4_qp_release_range(priv->mdev->dev, qpn, 1);
		return err;
	}

	return 0;
}

static struct mlx4_en_tx_desc *mlx4_en_bounce_to_desc(struct mlx4_en_priv *priv,
						      struct mlx4_en_tx_ring *ring,
						      u32 index,
						      unsigned int desc_size)
{
	u32 copy = (ring->size - index) * TXBB_SIZE;
	int i;
#ifdef CONFIG_INFINIBAND_WQE_FORMAT
	__be32 owner_bit = (ring->prod & ring->size) ?
			   cpu_to_be32(MLX4_EN_BIT_DESC_OWN) : 0;
#endif

	for (i = desc_size - copy - 4; i >= 0; i -= 4) {
		if ((i & (TXBB_SIZE - 1)) == 0) {
			wmb();
#ifdef CONFIG_INFINIBAND_WQE_FORMAT
			*((u32 *) (ring->buf + i)) =
				(*((u32 *) (ring->bounce_buf + copy + i)) &
				 WQE_FORMAT_1_MASK) |
				  owner_bit;
			continue;
#endif
		}

		*((u32 *) (ring->buf + i)) =
			*((u32 *) (ring->bounce_buf + copy + i));
	}

	for (i = copy - 4; i >= 4; i -= 4) {
		if ((i & (TXBB_SIZE - 1)) == 0)
			wmb();

		*((u32 *) (ring->buf + index * TXBB_SIZE + i)) =
			*((u32 *) (ring->bounce_buf + i));
	}

	/* Return real descriptor location */
	return ring->buf + index * TXBB_SIZE;
}

static int mlx4_txq_is_full(struct mlx4_en_tx_ring* ring)
{
	int stop_queue = (int)(ring->prod - ring->cons) > (ring->size - HEADROOM - MAX_DESC_TXBBS);
	return stop_queue;
}

static u32 mlx4_en_free_tx_desc(struct mlx4_en_tx_ring *ring,
				int index, u8 owner, u64 timestamp)
{
	struct mlx4_en_tx_info *tx_info = &ring->tx_info[index];
	struct mlx4_en_tx_desc *tx_desc = ring->buf + index * TXBB_SIZE;
	struct mlx4_wqe_data_seg *data = &tx_desc->data;
	void *end = ring->buf + ring->buf_size;
	struct rte_mbuf* mbuf = tx_info->mbuf;
	int i;

	if(timestamp)
	{
		if(ring->tx_tstamp_callback)
		{
			ring->tx_tstamp_callback(timestamp, mbuf, ring->tx_tstamp_callback_arg);
		}
	}

	rte_pktmbuf_free(mbuf);
	return tx_info->nr_txbb;
}

static void mlx4_en_stamp_wqe(struct mlx4_en_priv *priv,
			      struct mlx4_en_tx_ring *ring, int index,
			      u8 owner)
{
	__be32 stamp = cpu_to_be32(STAMP_VAL | (!!owner << STAMP_SHIFT));
	struct mlx4_en_tx_desc *tx_desc = ring->buf + index * TXBB_SIZE;
	struct mlx4_en_tx_info *tx_info = &ring->tx_info[index];
	void *end = ring->buf + ring->buf_size;
	__be32 *ptr = (__be32 *)tx_desc;
	int i;

	/* Optimize the common case when there are no wraparounds */
	if (likely((void *)tx_desc + tx_info->nr_txbb * TXBB_SIZE <= end)) {
		/* Stamp the freed descriptor */
		for (i = 0; i < tx_info->nr_txbb * TXBB_SIZE;
		     i += STAMP_STRIDE) {
			*ptr = stamp;
			ptr += STAMP_DWORDS;
		}
	} else {
		/* Stamp the freed descriptor */
		for (i = 0; i < tx_info->nr_txbb * TXBB_SIZE;
		     i += STAMP_STRIDE) {
			*ptr = stamp;
			ptr += STAMP_DWORDS;
			if ((void *)ptr >= end) {
				ptr = ring->buf;
				stamp ^= cpu_to_be32(0x80000000);
			}
		}
	}
}

static int mlx4_en_process_tx_cq(struct mlx4_en_tx_ring *ring)
{
	struct mlx4_en_cq* cq = &ring->tx_cq;
	struct mlx4_cq *mcq = &cq->mcq;
	struct rte_eth_dev* dev = cq->rte_dev;
	struct mlx4_en_priv *priv = rtedev_priv(dev);
	struct mlx4_cqe *cqe;
	u16 index;
	u16 new_index, ring_index, stamp_index;
	u32 txbbs_skipped = 0;
#ifndef CONFIG_INFINIBAND_WQE_FORMAT
	u32 txbbs_stamp = 0;
#endif
	u32 cons_index = mcq->cons_index;
	int size = cq->size;
	u32 size_mask = ring->size_mask;
	struct mlx4_cqe *buf = cq->buf;
	u32 packets = 0;
	u32 bytes = 0;
	int factor = priv->cqe_factor;
	u64 timestamp = 0;
	int done = 0;
	u32 last_nr_txbb;
	u32 ring_cons;

	index = cons_index & size_mask;
	cqe = mlx4_en_get_cqe(buf, index, priv->cqe_size) + factor;
	last_nr_txbb = ACCESS_ONCE(ring->last_nr_txbb);
	ring_cons = ACCESS_ONCE(ring->cons);
	ring_index = ring_cons & size_mask;
	stamp_index = ring_index;

	/* Process all completed CQEs */
	while (XNOR(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK,
			cons_index & size)) {
		/*
		 * make sure we read the CQE after we read the
		 * ownership bit
		 */
		rmb();

		if (unlikely((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) ==
			     MLX4_CQE_OPCODE_ERROR)) {
			struct mlx4_err_cqe *cqe_err = (struct mlx4_err_cqe *)cqe;

			en_err(priv, "CQE error - vendor syndrome: 0x%x syndrome: 0x%x\n",
			       cqe_err->vendor_err_syndrome,
			       cqe_err->syndrome);
		}

		/* Skip over last polled CQE */
		new_index = be16_to_cpu(cqe->wqe_index) & size_mask;

		do {
			txbbs_skipped += last_nr_txbb;
			ring_index = (ring_index + last_nr_txbb) & size_mask;
			if (ring->enable_hwtstamp)
			{
				timestamp = mlx4_en_get_cqe_ts(cqe);
			}

			/* free next descriptor */
			last_nr_txbb = mlx4_en_free_tx_desc(
					ring, ring_index,
					!!((ring_cons + txbbs_skipped) &
					ring->size), timestamp);

			mlx4_en_stamp_wqe(priv, ring, stamp_index,
					  !!((ring_cons + txbbs_stamp) &
						ring->size));
			stamp_index = ring_index;
			txbbs_stamp = txbbs_skipped;
			++done;
		} while ((ring_index != new_index));

		++cons_index;
		index = cons_index & size_mask;
		cqe = mlx4_en_get_cqe(buf, index, priv->cqe_size) + factor;
	}


	/*
	 * To prevent CQ overflow we first update CQ consumer and only then
	 * the ring consumer.
	 */
	mcq->cons_index = cons_index;
	mlx4_cq_set_ci(mcq);
	wmb();

	/* we want to dirty this cache line once */
	ACCESS_ONCE(ring->last_nr_txbb) = last_nr_txbb;
	ACCESS_ONCE(ring->cons) = ring_cons + txbbs_skipped;

	return done;
}
static int mlx4_en_prepare_rx_desc(struct mlx4_en_priv *priv,
				   struct mlx4_en_rx_ring *ring, int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + (index * ring->stride);
	//struct rte_mbuf **frags = ring->rx_info + index;

	{
		dma_addr_t dma;
		int i;
		struct rte_mbuf* mbuf = NULL;

		for (i = 0; i < ring->num_frags; i++) {
			mbuf = rte_pktmbuf_alloc(ring->mb_pool);
			assert(mbuf);
			assert((mbuf->buf_len - mbuf->data_off) >= ring->frag_size);
			dma = mbuf->buf_physaddr + mbuf->data_off;
			rx_desc->data[i].addr = cpu_to_be64(dma);
			ring->rx_info[ring->num_frags*index + i] = mbuf;
		}

		return 0;
	}
}
static void mlx4_en_refill_rx_buffers(struct mlx4_en_priv *priv,
				     struct mlx4_en_rx_ring *ring)
{
	int index = ring->prod & ring->size_mask;

	while ((u32) (ring->prod - ring->cons) < ring->actual_size) {
		if (mlx4_en_prepare_rx_desc(priv, ring, index))
			break;
		ring->prod++;
		index = ring->prod & ring->size_mask;
	}
}

static struct rte_mbuf* mlx4_en_complete_rx_desc(
		struct mlx4_en_rx_ring *ring,
		struct mlx4_en_rx_desc *rx_desc,
		struct rte_mbuf **mbuf_frags,
		int length)
{
	int nr;
	int remaining = length;

	/* Collect used fragments while replacing them in the HW descriptors */
	struct rte_mbuf* head = mbuf_frags[0];
	struct rte_mbuf* prev = 0;
	struct rte_mbuf* mbuf = 0;
	int frags = 0;
	for (nr = 0; nr < ring->num_frags; nr++) {
		mbuf = mbuf_frags[nr];
		if(remaining == 0)
		{
			rte_pktmbuf_free(mbuf);
			continue;
		}
		++frags;
		int frag_len = ring->frag_size;
		if(remaining < frag_len)
			mbuf->data_len = remaining;
		else
			mbuf->data_len = frag_len;
		remaining -= mbuf->data_len;

		if(prev)
			prev->next = mbuf;
		prev = mbuf;
	}
	head->nb_segs = frags;
	head->pkt_len = length;
	return head;
}

static int mlx4_en_process_rx_cq(struct mlx4_en_rx_ring *ring, struct rte_mbuf** ret_array, int budget)
{
	int received = 0;
	struct mlx4_en_cq* cq = &ring->rx_cq;
	struct rte_eth_dev* dev = cq->rte_dev;
	struct mlx4_en_priv *priv = rtedev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_cqe *cqe;
	struct rte_mbuf **mbuf_frag;
	struct rte_mbuf *mbuf = 0;
	struct mlx4_en_rx_desc *rx_desc;
	int index;
	int nr;
	unsigned int length;
	int polled = 0;
	u64 ol_flags = 0;
	int factor = priv->cqe_factor;
	u64 timestamp;
#ifdef HAVE_NETDEV_HW_ENC_FEATURES
	bool l2_tunnel;
#endif


	/* We assume a 1:1 mapping between CQEs and Rx descriptors, so Rx
	 * descriptor offset can be deduced from the CQE index instead of
	 * reading 'cqe->index' */
	index = cq->mcq.cons_index & ring->size_mask;
	cqe = mlx4_en_get_cqe(cq->buf, index, priv->cqe_size) + factor;

	/* Process all completed CQEs */
	while (XNOR(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK,
		    cq->mcq.cons_index & cq->size)) {

		mbuf_frag = ring->rx_info + (index * ring->num_frags);
		rx_desc = ring->buf + (index << ring->log_stride);

		/*
		 * make sure we read the CQE after we read the ownership bit
		 */
		rmb();

		/* Drop packet on bad receive or bad checksum */
		if (unlikely((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) ==
						MLX4_CQE_OPCODE_ERROR)) {
			en_err(priv, "CQE completed in error - vendor syndrom:%d syndrom:%d\n",
			       ((struct mlx4_err_cqe *)cqe)->vendor_err_syndrome,
			       ((struct mlx4_err_cqe *)cqe)->syndrome);
			goto next;
		}
		if (unlikely(cqe->badfcs_enc & MLX4_CQE_BAD_FCS)) {
			en_dbg(RX_ERR, priv, "Accepted frame with bad FCS\n");
			goto next;
		}

		length = be32_to_cpu(cqe->byte_cnt);
		length -= ring->fcs_del;

		//if (cqe->owner_sr_opcode & MLX4_CQE_IS_RECV_MASK)
			//mlx4_en_inline_scatter(ring, frags,
			//		       rx_desc, priv, length);


		/*
		 * Packet is OK - process it.
		 */


		if (cqe->status & cpu_to_be16(MLX4_CQE_STATUS_TCP |
				MLX4_CQE_STATUS_UDP)) {
			if ((cqe->status & cpu_to_be16(MLX4_CQE_STATUS_IPOK)) &&
					cqe->checksum == cpu_to_be16(0xffff)) {
				ol_flags |= PKT_TX_IP_CKSUM;
				if(cqe->status & cpu_to_be16(MLX4_CQE_STATUS_TCP))
					ol_flags |= PKT_TX_IP_CKSUM;
				else if(cqe->status & cpu_to_be16(MLX4_CQE_STATUS_UDP))
					ol_flags |= PKT_TX_UDP_CKSUM;

			}
		}

		/* GRO not possible, complete processing here */
		mbuf = mlx4_en_complete_rx_desc(ring, rx_desc, mbuf_frag, length);
		if (!mbuf) {
			goto next;
		}

		mbuf->ol_flags = ol_flags;

/*
		if ((be32_to_cpu(cqe->vlan_my_qpn) &
		    MLX4_CQE_VLAN_PRESENT_MASK) &&
		    (dev->features & NETIF_F_HW_VLAN_CTAG_RX)) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), be16_to_cpu(cqe->sl_vid));
		}
		*/

		if (ring->enable_hwtstamp) {
			timestamp = mlx4_en_get_cqe_ts(cqe);
			mbuf->udata64 = timestamp;
		}

		ret_array[received++] = mbuf;

next:
		//for (nr = 0; nr < priv->num_frags; nr++)
		//	mlx4_en_free_frag(priv, frags, nr);

		++cq->mcq.cons_index;
		index = (cq->mcq.cons_index) & ring->size_mask;
		cqe = mlx4_en_get_cqe(cq->buf, index, priv->cqe_size) + factor;
		if (++polled == budget)
			goto out;
	}

out:
	mlx4_cq_set_ci(&cq->mcq);
	wmb(); /* ensure HW sees CQ consumer before we post new buffers */
	ring->cons = cq->mcq.cons_index;
	mlx4_en_refill_rx_buffers(priv, ring);
	mlx4_en_update_rx_prod_db(ring);
	return polled;
}

#endif /* DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_HELPER_H_ */
