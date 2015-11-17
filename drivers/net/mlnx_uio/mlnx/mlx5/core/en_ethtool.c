#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "en.h"

static void mlx5e_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *drvinfo)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;

	strlcpy(drvinfo->driver, DRIVER_NAME, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRIVER_VERSION " (" DRIVER_RELDATE ")",
		sizeof(drvinfo->version));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%d.%d.%d",
		 fw_rev_maj(mdev), fw_rev_min(mdev), fw_rev_sub(mdev));
	strlcpy(drvinfo->bus_info, pci_name(mdev->pdev),
		sizeof(drvinfo->bus_info));
}

static const struct {
	u32 supported;
	u32 advertised;
	u32 speed;
} ptys2ethtool_table[MLX5E_LINK_MODES_NUMBER] = {
	[MLX5E_1000BASE_CX_SGMII] = {
		.supported  = SUPPORTED_1000baseKX_Full,
		.advertised = ADVERTISED_1000baseKX_Full,
		.speed      = SPEED_1000,
	},
	[MLX5E_1000BASE_KX] = {
		.supported  = SUPPORTED_1000baseKX_Full,
		.advertised = ADVERTISED_1000baseKX_Full,
		.speed      = SPEED_1000,
	},
	[MLX5E_10GBASE_CX4] = {
		.supported  = SUPPORTED_10000baseKX4_Full,
		.advertised = ADVERTISED_10000baseKX4_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_10GBASE_KX4] = {
		.supported  = SUPPORTED_10000baseKX4_Full,
		.advertised = ADVERTISED_10000baseKX4_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_10GBASE_KR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_20GBASE_KR2] = {
		.supported  = SUPPORTED_20000baseKR2_Full,
		.advertised = ADVERTISED_20000baseKR2_Full,
		.speed      = SPEED_20000,
	},
	[MLX5E_40GBASE_CR4] = {
		.supported  = SUPPORTED_40000baseCR4_Full,
		.advertised = ADVERTISED_40000baseCR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5E_40GBASE_KR4] = {
		.supported  = SUPPORTED_40000baseKR4_Full,
		.advertised = ADVERTISED_40000baseKR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5E_56GBASE_R4] = {
		.supported  = SUPPORTED_56000baseKR4_Full,
		.advertised = ADVERTISED_56000baseKR4_Full,
		.speed      = SPEED_56000,
	},
	[MLX5E_10GBASE_CR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_10GBASE_SR] = {
		.supported  = SUPPORTED_10000baseKR_Full,
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_10GBASE_ER] = {
		.supported  = SUPPORTED_10000baseKR_Full,/* TODO: verify */
		.advertised = ADVERTISED_10000baseKR_Full,
		.speed      = SPEED_10000,
	},
	[MLX5E_40GBASE_SR4] = {
		.supported  = SUPPORTED_40000baseSR4_Full,
		.advertised = ADVERTISED_40000baseSR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5E_40GBASE_LR4] = {
		.supported  = SUPPORTED_40000baseLR4_Full,
		.advertised = ADVERTISED_40000baseLR4_Full,
		.speed      = SPEED_40000,
	},
	[MLX5E_100GBASE_CR4] = {
		.supported  = /*SUPPORTED_100000baseCR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseCR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5E_100GBASE_SR4] = {
		.supported  = /*SUPPORTED_100000baseSR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseSR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5E_100GBASE_KR4] = {
		.supported  = /*SUPPORTED_100000baseKR4_Full*/ 0,
		.advertised = /*ADVERTISED_100000baseKR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5E_100GBASE_LR4] = {
		.supported  = /*SUPPORTED_1000000baseLR4_Full*/ 0,
		.advertised = /*ADVERTISED_1000000baseLR4_Full*/ 0,
		.speed      = SPEED_100000,
	},
	[MLX5E_100BASE_TX]   = {
		.supported  = /*SUPPORTED_100baseTX_Full*/ 0,
		.advertised = /*ADVERTISED_100baseTX_Full*/ 0,
		.speed      = SPEED_100,
	},
	[MLX5E_100BASE_T]    = {
		.supported  = SUPPORTED_100baseT_Full,
		.advertised = ADVERTISED_100baseT_Full,
		.speed      = SPEED_100,
	},
	[MLX5E_10GBASE_T]    = {
		.supported  = SUPPORTED_10000baseT_Full,
		.advertised = ADVERTISED_10000baseT_Full,
		.speed      = SPEED_1000,
	},
	[MLX5E_25GBASE_CR]   = {
		.supported  = /*SUPPORTED_25000baseCR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseCR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5E_25GBASE_KR]   = {
		.supported  = /*SUPPORTED_25000baseKR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseKR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5E_25GBASE_SR]   = {
		.supported  = /*SUPPORTED_25000baseSR_Full*/ 0,
		.advertised = /*ADVERTISED_25000baseSR_Full*/ 0,
		.speed      = SPEED_25000,
	},
	[MLX5E_50GBASE_CR2]  = {
		.supported  = /*SUPPORTED_50000baseCR2_Full*/ 0,
		.advertised = /*ADVERTISED_50000baseCR2_Full*/ 0,
		.speed      = SPEED_50000,
	},
	[MLX5E_50GBASE_KR2]  = {
		.supported  = /*SUPPORTED_50000baseKR2_Full*/ 0,
		.advertised = /*ADVERTISED_50000baseKR2_Full*/ 0,
		.speed      = SPEED_50000,
	},
};

static int mlx5e_get_sset_count(struct net_device *dev, int sset)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return NUM_VPORT_COUNTERS + NUM_PPORT_COUNTERS +
		       priv->params.num_channels * NUM_RQ_STATS +
		       priv->params.num_channels * priv->params.num_tc *
						   NUM_SQ_STATS;
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	case ETH_SS_PRIV_FLAGS:
		return ARRAY_SIZE(mlx5e_priv_flags);
#endif
	/* fallthrough */
	default:
		return -EOPNOTSUPP;
	}
}

static void mlx5e_get_strings(struct net_device *dev,
			      uint32_t stringset, uint8_t *data)
{
	int i, j, tc, idx = 0;
	struct mlx5e_priv *priv = netdev_priv(dev);

	switch (stringset) {
	case ETH_SS_PRIV_FLAGS:
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
		for (i = 0; i < ARRAY_SIZE(mlx5e_priv_flags); i++)
			strcpy(data + i * ETH_GSTRING_LEN,
			       mlx5e_priv_flags[i]);
#endif
		break;

	case ETH_SS_TEST:
		/* TODO: not implemented yet */
		break;

	case ETH_SS_STATS:
		/* VPORT counters */
		for (i = 0; i < NUM_VPORT_COUNTERS; i++)
			strcpy(data + (idx++) * ETH_GSTRING_LEN,
			       vport_strings[i]);

		/* PPORT counters */
		for (i = 0; i < NUM_PPORT_COUNTERS; i++)
			strcpy(data + (idx++) * ETH_GSTRING_LEN,
			       pport_strings[i]);

		/* per channel counters */
		for (i = 0; i < priv->params.num_channels; i++)
			for (j = 0; j < NUM_RQ_STATS; j++)
				sprintf(data + (idx++) * ETH_GSTRING_LEN,
					"rx%d_%s", i, rq_stats_strings[j]);

		for (i = 0; i < priv->params.num_channels; i++)
			for (tc = 0; tc < priv->params.num_tc; tc++)
				for (j = 0; j < NUM_SQ_STATS; j++)
					sprintf(data +
						(idx++) * ETH_GSTRING_LEN,
						"tx%d_%d_%s", i, tc,
						sq_stats_strings[j]);
		break;
	}
}

static void mlx5e_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i, j, tc, idx = 0;

	if (!data)
		return;

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_update_stats(priv);
	mutex_unlock(&priv->state_lock);

	for (i = 0; i < NUM_VPORT_COUNTERS; i++)
		data[idx++] = ((u64 *)&priv->stats.vport)[i];

	for (i = 0; i < NUM_PPORT_COUNTERS; i++)
		data[idx++] = be64_to_cpu(((__be64 *)&priv->stats.pport)[i]);

	/* per channel counters */
	for (i = 0; i < priv->params.num_channels; i++)
		for (j = 0; j < NUM_RQ_STATS; j++)
			data[idx++] = !test_bit(MLX5E_STATE_OPENED,
						&priv->state) ? 0 :
				       ((u64 *)&priv->channel[i]->rq.stats)[j];

	for (i = 0; i < priv->params.num_channels; i++)
		for (tc = 0; tc < priv->params.num_tc; tc++)
			for (j = 0; j < NUM_SQ_STATS; j++)
				data[idx++] = !test_bit(MLX5E_STATE_OPENED,
							&priv->state) ? 0 :
				((u64 *)&priv->channel[i]->sq[tc].stats)[j];
}

static void mlx5e_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	param->rx_max_pending = 1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE;
	param->tx_max_pending = 1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE;
	param->rx_pending     = 1 << priv->params.log_rq_size;
	param->tx_pending     = 1 << priv->params.log_sq_size;
}

static int mlx5e_set_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *param)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_params new_params;
	u16 min_rx_wqes;
	u8 log_rq_size;
	u8 log_sq_size;
	int err = 0;

	if (param->rx_jumbo_pending) {
		netdev_info(dev, "%s: rx_jumbo_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_mini_pending) {
		netdev_info(dev, "%s: rx_mini_pending not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (param->rx_pending < (1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE)) {
		netdev_info(dev, "%s: rx_pending (%d) < min (%d)\n",
			    __func__, param->rx_pending,
			    1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE);
		return -EINVAL;
	}
	if (param->rx_pending > (1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE)) {
		netdev_info(dev, "%s: rx_pending (%d) > max (%d)\n",
			    __func__, param->rx_pending,
			    1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE);
		return -EINVAL;
	}
	if (param->tx_pending < (1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) < min (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}
	if (param->tx_pending > (1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE)) {
		netdev_info(dev, "%s: tx_pending (%d) > max (%d)\n",
			    __func__, param->tx_pending,
			    1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE);
		return -EINVAL;
	}

	log_rq_size = order_base_2(param->rx_pending);
	log_sq_size = order_base_2(param->tx_pending);
	min_rx_wqes = min_t(u16, param->rx_pending - 1,
			    MLX5E_PARAMS_DEFAULT_MIN_RX_WQES);

	if (log_rq_size == priv->params.log_rq_size &&
	    log_sq_size == priv->params.log_sq_size &&
	    min_rx_wqes == priv->params.min_rx_wqes)
		return 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;
	new_params.log_rq_size = log_rq_size;
	new_params.log_sq_size = log_sq_size;
	new_params.min_rx_wqes = min_rx_wqes;
	err = mlx5e_update_priv_params(priv, &new_params);
	mutex_unlock(&priv->state_lock);

	return err;
}

#if defined(HAVE_GET_SET_CHANNELS) || defined(HAVE_GET_SET_CHANNELS_EXT)
static void mlx5e_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int ncv = priv->mdev->priv.eq_table.num_comp_vectors;

	ch->max_combined   = ncv;
	ch->combined_count = priv->params.num_channels;
}

static int mlx5e_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int ncv = priv->mdev->priv.eq_table.num_comp_vectors;
	unsigned int count = ch->combined_count;
	struct mlx5e_params new_params;
	int err = 0;

	if (!count) {
		netdev_info(dev, "%s: combined_count=0 not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (ch->rx_count || ch->tx_count) {
		netdev_info(dev, "%s: separate rx/tx count not supported\n",
			    __func__);
		return -EINVAL;
	}
	if (count > ncv) {
		netdev_info(dev, "%s: count (%d) > max (%d)\n",
			    __func__, count, ncv);
		return -EINVAL;
	}

	if (priv->params.num_channels == count)
		return 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;
	new_params.num_channels = count;
	err = mlx5e_update_priv_params(priv, &new_params);
	mutex_unlock(&priv->state_lock);

	return err;
}
#endif

static int mlx5e_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	coal->rx_coalesce_usecs       = priv->params.rx_cq_moderation_usec;
	coal->rx_max_coalesced_frames = priv->params.rx_cq_moderation_pkts;
	coal->tx_coalesce_usecs       = priv->params.tx_cq_moderation_usec;
	coal->tx_max_coalesced_frames = priv->params.tx_cq_moderation_pkts;

	return 0;
}

static int mlx5e_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *coal)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_channel *c;
	int tc;
	int i;

	priv->params.tx_cq_moderation_usec = coal->tx_coalesce_usecs;
	priv->params.tx_cq_moderation_pkts = coal->tx_max_coalesced_frames;
	priv->params.rx_cq_moderation_usec = coal->rx_coalesce_usecs;
	priv->params.rx_cq_moderation_pkts = coal->rx_max_coalesced_frames;

	for (i = 0; i < priv->params.num_channels; ++i) {
		c = priv->channel[i];

		for (tc = 0; tc < c->num_tc; tc++) {
			mlx5_core_modify_cq_moderation(mdev,
						&c->sq[tc].cq.mcq,
						coal->tx_coalesce_usecs,
						coal->tx_max_coalesced_frames);
		}

		mlx5_core_modify_cq_moderation(mdev, &c->rq.cq.mcq,
					       coal->rx_coalesce_usecs,
					       coal->rx_max_coalesced_frames);
	}

	return 0;
}

static u32 ptys2ethtool_supported_link(u32 eth_proto_cap)
{
	int i;
	u32 supoprted_modes = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_cap & MLX5E_PROT_MASK(i))
			supoprted_modes |= ptys2ethtool_table[i].supported;
	}
	return supoprted_modes;
}

static u32 ptys2ethtool_adver_link(u32 eth_proto_cap)
{
	int i;
	u32 advertising_modes = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_cap & MLX5E_PROT_MASK(i))
			advertising_modes |= ptys2ethtool_table[i].advertised;
	}
	return advertising_modes;
}

static u32 ptys2ethtool_supported_port(u32 eth_proto_cap)
{
	/*
	TODO:
	MLX5E_40GBASE_LR4	 = 16,
	MLX5E_10GBASE_ER	 = 14,
	MLX5E_10GBASE_CX4	 = 2,
	*/

	if (eth_proto_cap & (MLX5E_PROT_MASK(MLX5E_10GBASE_CR)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_SR)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_CR4)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_SR4)
			   | MLX5E_PROT_MASK(MLX5E_100GBASE_SR4)
			   | MLX5E_PROT_MASK(MLX5E_1000BASE_CX_SGMII))) {
		return SUPPORTED_FIBRE;
	}

	if (eth_proto_cap & (MLX5E_PROT_MASK(MLX5E_100GBASE_KR4)
			   | MLX5E_PROT_MASK(MLX5E_40GBASE_KR4)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_KR)
			   | MLX5E_PROT_MASK(MLX5E_10GBASE_KX4)
			   | MLX5E_PROT_MASK(MLX5E_1000BASE_KX))) {
		return SUPPORTED_Backplane;
	}
	return 0;
}

static void get_speed_duplex(struct net_device *netdev,
			     u32 eth_proto_oper,
			     struct ethtool_cmd *cmd)
{
	int i;
	u32 speed = SPEED_UNKNOWN;
	u8 duplex = DUPLEX_UNKNOWN;

	if (!netif_carrier_ok(netdev))
		goto out;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (eth_proto_oper & MLX5E_PROT_MASK(i)) {
			speed = ptys2ethtool_table[i].speed;
			duplex = DUPLEX_FULL;
			break;
		}
	}
out:
	ethtool_cmd_speed_set(cmd, speed);
	cmd->duplex = duplex;
}

static void get_supported(u32 eth_proto_cap, u32 *supported)
{
	*supported |= ptys2ethtool_supported_port(eth_proto_cap);
	*supported |= ptys2ethtool_supported_link(eth_proto_cap);
	*supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
}

static void get_advertising(u32 eth_proto_cap, u8 tx_pause,
			    u8 rx_pause, u32 *advertising)
{
	*advertising |= ptys2ethtool_adver_link(eth_proto_cap);
	*advertising |= tx_pause ? ADVERTISED_Pause : 0;
	*advertising |= (tx_pause ^ rx_pause) ? ADVERTISED_Asym_Pause : 0;
}

static u8 get_connector_port(u32 eth_proto)
{
	/*
	TODO:
	MLX5E_40GBASE_LR4	 = 16,
	MLX5E_10GBASE_ER	 = 14,
	MLX5E_10GBASE_CX4	 = 2,
	*/

	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_10GBASE_SR)
			 | MLX5E_PROT_MASK(MLX5E_40GBASE_SR4)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_SR4)
			 | MLX5E_PROT_MASK(MLX5E_1000BASE_CX_SGMII))) {
			return PORT_FIBRE;
	}

	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_40GBASE_CR4)
			 | MLX5E_PROT_MASK(MLX5E_10GBASE_CR)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_CR4))) {
			return PORT_DA;
	}

	if (eth_proto & (MLX5E_PROT_MASK(MLX5E_10GBASE_KX4)
			 | MLX5E_PROT_MASK(MLX5E_10GBASE_KR)
			 | MLX5E_PROT_MASK(MLX5E_40GBASE_KR4)
			 | MLX5E_PROT_MASK(MLX5E_100GBASE_KR4))) {
			return PORT_NONE;
	}

	return PORT_OTHER;
}

static void get_lp_advertising(u32 eth_proto_lp, u32 *lp_advertising)
{

	*lp_advertising = ptys2ethtool_adver_link(eth_proto_lp);
}

static int mlx5e_get_settings(struct net_device *netdev,
			      struct ethtool_cmd *cmd)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_cap;
	u32 eth_proto_admin;
	u32 eth_proto_lp;
	u32 eth_proto_oper;
	int err;

	err = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN);

	if (err) {
		netdev_err(netdev, "%s: query port ptys failed: %d\n",
			   __func__, err);
		goto err_query_ptys;
	}

	eth_proto_cap   = MLX5_GET(ptys_reg, out, eth_proto_capability);
	eth_proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	eth_proto_oper  = MLX5_GET(ptys_reg, out, eth_proto_oper);
	eth_proto_lp    = MLX5_GET(ptys_reg, out, eth_proto_lp_advertise);

	cmd->supported   = 0;
	cmd->advertising = 0;

	get_supported(eth_proto_cap, &cmd->supported);
	get_advertising(eth_proto_admin, 0, 0, &cmd->advertising);
	get_speed_duplex(netdev, eth_proto_oper, cmd);

	eth_proto_oper = eth_proto_oper ? eth_proto_oper : eth_proto_cap;

	cmd->port = get_connector_port(eth_proto_oper);
	get_lp_advertising(eth_proto_lp, &cmd->lp_advertising);

	cmd->transceiver = XCVR_INTERNAL;

	/* TODO
	set Pause
	cmd->supported ? SUPPORTED_Autoneg
	cmd->advertising ? ADVERTISED_Autoneg
	cmd->autoneg ?
	cmd->phy_address = 0;
	cmd->mdio_support = 0;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 0;
	cmd->eth_tp_mdix = ETH_TP_MDI_INVALID;
	cmd->eth_tp_mdix_ctrl = ETH_TP_MDI_AUTO;

	cmd->lp_advertising |= (priv->port_state.flags & MLX4_EN_PORT_ANC) ?
			ADVERTISED_Autoneg : 0;
	*/

err_query_ptys:
	return err;
}

static u32 mlx5e_ethtool2ptys_adver_link(u32 link_modes)
{
	u32 i, ptys_modes = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (ptys2ethtool_table[i].advertised & link_modes)
			ptys_modes |= MLX5E_PROT_MASK(i);
	}

	return ptys_modes;
}

static u32 mlx5e_ethtool2ptys_speed_link(u32 speed)
{
	u32 i, speed_links = 0;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i) {
		if (ptys2ethtool_table[i].speed == speed)
			speed_links |= MLX5E_PROT_MASK(i);
	}

	return speed_links;
}

static int mlx5e_set_settings(struct net_device *netdev,
			      struct ethtool_cmd *cmd)
{
	struct mlx5e_priv *priv    = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 link_modes;
	u32 speed;
	u32 eth_proto_cap, eth_proto_admin;
	u8 port_status;
	int err;

	speed = ethtool_cmd_speed(cmd);

	link_modes = cmd->autoneg == AUTONEG_ENABLE ?
		mlx5e_ethtool2ptys_adver_link(cmd->advertising) :
		mlx5e_ethtool2ptys_speed_link(speed);

	err = mlx5_query_port_proto_cap(mdev, &eth_proto_cap, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto cap failed: %d\n",
			   __func__, err);
		goto out;
	}

	link_modes = link_modes & eth_proto_cap;
	if (!link_modes) {
		netdev_err(netdev, "%s: Not supported link mode(s) requested",
			   __func__);
		err = -EINVAL;
		goto out;
	}

	err = mlx5_query_port_proto_admin(mdev, &eth_proto_admin, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: query port eth proto admin failed: %d\n",
			   __func__, err);
		goto out;
	}

	if (link_modes == eth_proto_admin)
		goto out;

	err = mlx5_set_port_proto(mdev, link_modes, MLX5_PTYS_EN);
	if (err) {
		netdev_err(netdev, "%s: set port eth proto admin failed: %d\n",
			   __func__, err);
		goto out;
	}

	err = mlx5_query_port_status(mdev, &port_status);
	if (err)
		goto out;

	if (port_status == MLX5_PORT_DOWN)
		return 0;

	err = mlx5_set_port_status(mdev, MLX5_PORT_DOWN);
	if (err)
		goto out;
	err = mlx5_set_port_status(mdev, MLX5_PORT_UP);
out:
	return err;
}

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
static int mlx5e_set_priv_flags(struct net_device *dev, u32 flags)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	u32 changes = flags ^ priv->pflags;
	struct mlx5e_params new_params;
	bool update_params = false;
	int i = 0;

	mutex_lock(&priv->state_lock);
	new_params = priv->params;

	if (changes & MLX5E_PRIV_FLAG_SWLRO) {
		priv->pflags ^= MLX5E_PRIV_FLAG_SWLRO;
		if (!test_bit(MLX5E_STATE_OPENED, &priv->state))
			goto out;
		for (i = 0; i < priv->params.num_channels; i++)
			priv->channel[i]->rq.flags ^= MLX5E_RQ_FLAG_SWLRO;
	}

	if (changes & MLX5E_PRIV_FLAG_HWLRO) {
		new_params.lro_en = !!(flags & MLX5E_PRIV_FLAG_HWLRO);
		priv->pflags ^= MLX5E_PRIV_FLAG_HWLRO;
		update_params = true;
		if (new_params.lro_en)
			priv->netdev->flags |= NETIF_F_LRO;
		else
			priv->netdev->flags &= ~NETIF_F_LRO;
	}

	if (update_params)
		mlx5e_update_priv_params(priv, &new_params);
out:
	mutex_unlock(&priv->state_lock);
	return !(flags == priv->pflags);
}

static u32 mlx5e_get_priv_flags(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	return priv->pflags;
}
#endif

const struct ethtool_ops mlx5e_ethtool_ops = {
	.get_drvinfo       = mlx5e_get_drvinfo,
	.get_link          = ethtool_op_get_link,
	.get_strings       = mlx5e_get_strings,
	.get_sset_count    = mlx5e_get_sset_count,
	.get_ethtool_stats = mlx5e_get_ethtool_stats,
	.get_ringparam     = mlx5e_get_ringparam,
	.set_ringparam     = mlx5e_set_ringparam,
#ifdef HAVE_GET_SET_CHANNELS
	.get_channels      = mlx5e_get_channels,
	.set_channels      = mlx5e_set_channels,
#endif
	.get_coalesce      = mlx5e_get_coalesce,
	.set_coalesce      = mlx5e_set_coalesce,
	.get_settings      = mlx5e_get_settings,
	.set_settings      = mlx5e_set_settings,
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	.set_priv_flags    = mlx5e_set_priv_flags,
	.get_priv_flags    = mlx5e_get_priv_flags,
#endif
};


#ifdef HAVE_ETHTOOL_OPS_EXT
const struct ethtool_ops_ext mlx5e_ethtool_ops_ext = {
	.size = sizeof(struct ethtool_ops_ext),
#ifdef HAVE_GET_SET_CHANNELS_EXT
	.get_channels = mlx5e_get_channels,
	.set_channels = mlx5e_set_channels,
#endif
};
#endif
