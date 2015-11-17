#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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
 *
 */



#include "mlx4_en.h"
#include "mlx4_uio.h"
#include "mlx4_uio_helper.h"

MODULE_AUTHOR("Liran Liss, Yevgeny Petrilin");
MODULE_DESCRIPTION("Mellanox ConnectX HCA Ethernet driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION " ("DRV_RELDATE")");

static const char mlx4_en_version[] =
	DRV_NAME ": Mellanox ConnectX HCA Ethernet driver v"
	DRV_VERSION " (" DRV_RELDATE ")\n";

#define MLX4_EN_PARM_INT(X, def_val, desc) \
	static unsigned int X = def_val;\
	module_param(X , int, 0444); \
	MODULE_PARM_DESC(X, desc);


/*
 * Device scope module parameters
 */

/* Enable RSS UDP traffic */
MLX4_EN_PARM_INT(udp_rss, 1,
		 "Enable RSS for incoming UDP traffic or disabled (0)");

/* Priority pausing */
MLX4_EN_PARM_INT(pfctx, 0, "Priority based Flow Control policy on TX[7:0]."
			   " Per priority bit mask");
MLX4_EN_PARM_INT(pfcrx, 0, "Priority based Flow Control policy on RX[7:0]."
			   " Per priority bit mask");

MLX4_EN_PARM_INT(inline_thold, MAX_INLINE,
		 "Threshold for using inline data (range: 17-104, default: 104)");

#define MAX_PFC_TX     0xff
#define MAX_PFC_RX     0xff

#if defined(HAVE_VA_FORMAT) && !defined(CONFIG_X86_XEN)
void en_print(const char *level, const struct mlx4_en_priv *priv,
	      const char *format, ...)
{
	va_list args;
	struct va_format vaf;

	va_start(args, format);

	vaf.fmt = format;
	vaf.va = &args;
	if (priv->registered)
		printk("%s%s: %s: %pV",
		       level, DRV_NAME, priv->dev->name, &vaf);
	else
		printk("%s%s: %s: Port %d: %pV",
		       level, DRV_NAME, dev_name(&priv->mdev->pdev->dev),
		       priv->port, &vaf);
	va_end(args);
}
#endif

void mlx4_en_update_loopback_state(struct rte_eth_dev *dev,
				   netdev_features_t features)
{
	struct mlx4_en_priv *priv = dev->data->dev_private;

	if (features & NETIF_F_LOOPBACK)
		priv->ctrl_flags |= cpu_to_be32(MLX4_WQE_CTRL_FORCE_LOOPBACK);
	else
		priv->ctrl_flags &= cpu_to_be32(~MLX4_WQE_CTRL_FORCE_LOOPBACK);

	priv->flags &= ~(MLX4_EN_FLAG_RX_FILTER_NEEDED|
			MLX4_EN_FLAG_ENABLE_HW_LOOPBACK);

	/* Drop the packet if SRIOV is not enabled
	 * and not performing the selftest or flb disabled
	 */
	if (mlx4_is_mfunc(priv->mdev->dev) &&
	    !(features & NETIF_F_LOOPBACK) && !priv->validate_loopback)
		priv->flags |= MLX4_EN_FLAG_RX_FILTER_NEEDED;

	/* Set dmac in Tx WQE if we are in SRIOV mode or if loopback selftest
	 * is requested
	 */
	if (mlx4_is_mfunc(priv->mdev->dev) || priv->validate_loopback)
		priv->flags |= MLX4_EN_FLAG_ENABLE_HW_LOOPBACK;

	mutex_lock(&priv->mdev->state_lock);
	if (priv->mdev->dev->caps.flags2 &
	    MLX4_DEV_CAP_FLAG2_UPDATE_QP_SRC_CHECK_LB &&
	    priv->rss_map.indir_qp.qpn) {
		int i;
		int err = 0;

		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			int ret;

			ret = mlx4_en_change_mcast_loopback(priv,
							    &priv->rss_map.qps[i],
							    !!(features &
							       NETIF_F_LOOPBACK));
			if (!err)
				err = ret;
		}
		if (err)
			mlx4_warn(priv->mdev, "failed to change mcast loopback\n");
	}
	mutex_unlock(&priv->mdev->state_lock);
}

static int mlx4_en_get_profile(struct mlx4_en_dev *mdev)
{
	struct mlx4_en_profile *params = &mdev->profile;
	int i;

	params->udp_rss = udp_rss;
#ifdef HAVE_NEW_TX_RING_SCHEME
	params->num_tx_rings_p_up = mlx4_low_memory_profile() ?
		MLX4_EN_MIN_TX_RING_P_UP :
		min_t(int, num_online_cpus(), MLX4_EN_MAX_TX_RING_P_UP);
#endif

	if (params->udp_rss && !(mdev->dev->caps.flags
					& MLX4_DEV_CAP_FLAG_UDP_RSS)) {
		mlx4_warn(mdev, "UDP RSS is not supported on this device\n");
		params->udp_rss = 0;
	}
	for (i = 1; i <= MLX4_MAX_PORTS; i++) {
		params->prof[i].rx_pause = 0; //MOD 1;
		params->prof[i].rx_ppp = pfcrx;
		params->prof[i].tx_pause = 0; //MOD 1;
		params->prof[i].tx_ppp = pfctx;
		params->prof[i].tx_ring_size = MLX4_EN_DEF_TX_RING_SIZE;
		params->prof[i].rx_ring_size = MLX4_EN_DEF_RX_RING_SIZE;
#ifdef HAVE_NEW_TX_RING_SCHEME
		params->prof[i].tx_ring_num = params->num_tx_rings_p_up *
			MLX4_EN_NUM_UP;
#else
		params->prof[i].tx_ring_num = MLX4_EN_NUM_TX_RINGS +
			(!!pfcrx) * MLX4_EN_NUM_PPP_RINGS;
#endif
		params->prof[i].rss_rings = 0;
		params->prof[i].inline_thold = inline_thold;
		params->prof[i].inline_scatter_thold = 0;
	}

	return 0;
}

static void *mlx4_en_get_rte_eth_dev(struct mlx4_dev *dev, void *ctx, u8 port)
{
	struct mlx4_en_dev *endev = ctx;

	return endev->rte_pndev[port];
}

static void mlx4_en_event(struct mlx4_dev *dev, void *endev_ptr,
			  enum mlx4_dev_event event, unsigned long port)
{
	struct mlx4_en_dev *mdev = (struct mlx4_en_dev *) endev_ptr;
	struct mlx4_en_priv *priv;

	switch (event) {
	case MLX4_DEV_EVENT_PORT_UP:
	case MLX4_DEV_EVENT_PORT_DOWN:
		if (!mdev->rte_pndev[port])
			return;
		priv = mdev->rte_pndev[port]->data->dev_private;
		/* To prevent races, we poll the link state in a separate
		  task rather than changing it here */
		priv->link_state = event;
		//queue_work(mdev->workqueue, &priv->linkstate_task);
		break;

	case MLX4_DEV_EVENT_CATASTROPHIC_ERROR:
		mlx4_err(mdev, "Internal error detected, restarting device\n");
		break;

	case MLX4_DEV_EVENT_SLAVE_INIT:
	case MLX4_DEV_EVENT_SLAVE_SHUTDOWN:
		break;
	default:
		if (port < 1 || port > dev->caps.num_ports ||
		    !mdev->rte_pndev[port])
			return;
		mlx4_warn(mdev, "Unhandled event %d for port %d\n", event,
			  (int) port);
	}
}

static void mlx4_en_remove(struct mlx4_dev *dev, void *endev_ptr)
{
	struct mlx4_en_dev *mdev = endev_ptr;
	int i;

	mutex_lock(&mdev->state_lock);
	mdev->device_up = false;
	mutex_unlock(&mdev->state_lock);

	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH)
		if (mdev->rte_pndev[i])
		{
			//mlx4_en_destroy_rte_eth_dev(mdev->rte_pndev[i]);
			assert(0); //XXX
		}

#if defined (HAVE_PTP_CLOCK_INFO) && (defined (CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE))
	if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS)
		mlx4_en_remove_timestamp(mdev);
#endif

	//flush_workqueue(mdev->workqueue);
	//destroy_workqueue(mdev->workqueue);
	(void) mlx4_mr_free(dev, &mdev->mr);
	//iounmap(mdev->uar_map);
	mlx4_uar_free(dev, &mdev->priv_uar);
	mlx4_pd_free(dev, mdev->priv_pdn);
	//if (mdev->nb.notifier_call)
//		unregister_netdevice_notifier(&mdev->nb);
	kfree(mdev);
}

static int mlx4_alloc_rtedev(struct mlx4_dev* dev, struct mlx4_en_dev *mdev, int port, struct mlx4_en_port_profile* prof)
{
	struct rte_eth_dev* rte_dev;
	char ethdev_name[RTE_ETH_NAME_MAX_LEN];
	snprintf(ethdev_name, sizeof(ethdev_name), "%d:%d.%d:port%d",
			dev->persist->rte_pdev->addr.bus, dev->persist->rte_pdev->addr.devid,
			dev->persist->rte_pdev->addr.function, port);
	rte_dev = rte_eth_dev_allocate(ethdev_name, mlx4_is_slave(dev) ? RTE_ETH_DEV_VIRTUAL : RTE_ETH_DEV_PCI);
	if (rte_dev == NULL)
		return -ENOMEM;

	rte_dev->pci_dev = dev->persist->rte_pdev;
	rte_dev->data->rx_mbuf_alloc_failed = 0;

	/*
	 * Initialize driver private data
	 */

	rte_dev->data->dev_private = rte_zmalloc("mlx4_private", sizeof(struct mlx4_en_priv), RTE_CACHE_LINE_SIZE);
	struct mlx4_en_priv* priv = rte_dev->data->dev_private;
	priv->prof = prof;
	priv->port = port;
	priv->mdev = mdev;
	rte_dev->data->mtu = ETHER_MTU;
	TAILQ_INIT(&(rte_dev->link_intr_cbs));

	rte_dev->dev_ops = &mlx4_eth_dev_ops;
	rte_dev->rx_pkt_burst = &mlx4_recv_pkts;
	rte_dev->tx_pkt_burst = &mlx4_xmit_pkts;

	/* Set default MAC */
	rte_dev->data->mac_addrs = rte_zmalloc_socket("mlx4_mac",
			sizeof(struct ether_addr) * (1 << mdev->dev->caps.log_num_macs),
			RTE_CACHE_LINE_SIZE, rte_dev->pci_dev->numa_node);
	mlx4_en_u64_to_mac(rte_dev->data->mac_addrs[0].addr_bytes, mdev->dev->caps.def_mac[priv->port]);
	if (!is_valid_ether_addr(rte_dev->data->mac_addrs[0].addr_bytes)) {
		if (mlx4_is_slave(priv->mdev->dev)) {
			u64 mac_u64 = rte_rand();
			mdev->dev->caps.def_mac[priv->port] = mac_u64;
			mlx4_en_u64_to_mac(rte_dev->data->mac_addrs[0].addr_bytes, mdev->dev->caps.def_mac[priv->port]);

			en_warn(priv, "Assigned random MAC address %pM\n", rte_dev->data->mac_addrs[0].addr_bytes);

		} else {
			en_err(priv, "Port: %d, invalid mac burned: %pM, quiting\n",
					priv->port, rte_dev->data->mac_addrs[0].addr_bytes);
			return -EINVAL;
		}
	}

	memcpy(priv->current_mac, rte_dev->data->mac_addrs[0].addr_bytes, sizeof(priv->current_mac));

	return 0;
}

static void mlx4_en_activate(struct mlx4_dev *dev, void *ctx)
{
	int i;
	struct mlx4_en_dev *mdev = ctx;

	/* Create a netdev for each port */
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH) {
		mlx4_info(mdev, "Activating port:%d\n", i);

		if (mlx4_alloc_rtedev(dev, mdev, i, &mdev->profile.prof[i]))
			mdev->rte_pndev[i] = NULL;
	}

#ifdef HAVE_NETDEV_BONDING_INFO
	/* register notifier */
	mdev->nb.notifier_call = mlx4_en_netdev_event;
	if (register_netdevice_notifier(&mdev->nb)) {
		mdev->nb.notifier_call = NULL;
		mlx4_err(mdev, "Failed to create notifier\n");
	}
#endif
}

static void *mlx4_en_add(struct mlx4_dev *dev)
{
	struct mlx4_en_dev *mdev;
	int i;

	printk_once(KERN_INFO "%s", mlx4_en_version);

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev)
		goto err_free_res;

	if (mlx4_pd_alloc(dev, &mdev->priv_pdn))
		goto err_free_dev;

	if (mlx4_uar_alloc(dev, &mdev->priv_uar))
		goto err_pd;

	//mdev->uar_map = ioremap((phys_addr_t) mdev->priv_uar.pfn << PAGE_SHIFT,
	//			PAGE_SIZE);
	mdev->uar_map = mdev->priv_uar.pfn_addr;

	if (!mdev->uar_map)
		goto err_uar;
	spin_lock_init(&mdev->uar_lock);

	mdev->dev = dev;
	//mdev->dma_device = &dev->persist->pdev->dev;
	mdev->rte_pdev = dev->persist->rte_pdev;
	mdev->device_up = false;

	mdev->LSO_support = !!(dev->caps.flags & (1 << 15));
	if (!mdev->LSO_support)
		mlx4_warn(mdev, "LSO not supported, please upgrade to later FW version to enable LSO\n");

	if (mlx4_mr_alloc(mdev->dev, mdev->priv_pdn, 0, ~0ull,
			 MLX4_PERM_LOCAL_WRITE |  MLX4_PERM_LOCAL_READ,
			 0, 0, &mdev->mr)) {
		mlx4_err(mdev, "Failed allocating memory region\n");
		goto err_map;
	}
	if (mlx4_mr_enable(mdev->dev, &mdev->mr)) {
		mlx4_err(mdev, "Failed enabling memory region\n");
		goto err_mr;
	}

	/* Build device profile according to supplied module parameters */
	if (mlx4_en_get_profile(mdev)) {
		mlx4_err(mdev, "Bad module parameters, aborting\n");
		goto err_mr;
	}

	/* Configure which ports to start according to module parameters */
	mdev->port_cnt = 0;
	mlx4_foreach_port(i, dev, MLX4_PORT_TYPE_ETH)
		mdev->port_cnt++;

	/* Initialize time stamp mechanism */
	//if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_TS)
	//	mlx4_en_init_timestamp(mdev);

	/* Set default number of RX rings*/
	//mlx4_en_set_num_rx_rings(mdev);

	/* Create our own workqueue for reset/multicast tasks
	 * Note: we cannot use the shared workqueue because of deadlocks caused
	 *       by the rtnl lock */
	//mdev->workqueue = create_singlethread_workqueue("mlx4_en");
	//if (!mdev->workqueue)
	//	goto err_mr;

	/* At this stage all non-port specific tasks are complete:
	 * mark the card state as up */
	mutex_init(&mdev->state_lock);
	mdev->device_up = true;

	return mdev;

err_mr:
	(void) mlx4_mr_free(dev, &mdev->mr);
err_map:
	//if (mdev->uar_map)
		//iounmap(mdev->uar_map);
err_uar:
	mlx4_uar_free(dev, &mdev->priv_uar);
err_pd:
	mlx4_pd_free(dev, mdev->priv_pdn);
err_free_dev:
	kfree(mdev);
err_free_res:
	return NULL;
}

static struct mlx4_interface mlx4_en_interface = {
	.add		= mlx4_en_add,
	.remove		= mlx4_en_remove,
	.event		= mlx4_en_event,
	.get_dev	= mlx4_en_get_rte_eth_dev,
	.protocol	= MLX4_PROT_ETH,
	.activate	= mlx4_en_activate,
};

static void mlx4_en_verify_params(void)
{
	if (pfctx > MAX_PFC_TX) {
		pr_warn("mlx4_en: WARNING: illegal module parameter pfctx 0x%x - should be in range 0-0x%x, will be changed to default (0)\n",
			pfctx, MAX_PFC_TX);
		pfctx = 0;
	}

	if (pfcrx > MAX_PFC_RX) {
		pr_warn("mlx4_en: WARNING: illegal module parameter pfcrx 0x%x - should be in range 0-0x%x, will be changed to default (0)\n",
			pfcrx, MAX_PFC_RX);
		pfcrx = 0;
	}

	if (inline_thold < MIN_PKT_LEN || inline_thold > MAX_INLINE) {
		pr_warn("mlx4_en: WARNING: illegal module parameter inline_thold %d - should be in range %d-%d, will be changed to default (%d)\n",
			inline_thold, MIN_PKT_LEN, MAX_INLINE, MAX_INLINE);
		inline_thold = MAX_INLINE;
	}
}


static int mlx4_en_init(const char *name, const char *args)
{

	mlx4_en_verify_params();

	inline_thold = 0;
	return mlx4_register_interface(&mlx4_en_interface);
}


static int mlx4_en_cleanup(const char *name)
{
	mlx4_unregister_interface(&mlx4_en_interface);
	return 0;
}

#ifdef KMOD_DISABLED

module_init(mlx4_en_init);
module_exit(mlx4_en_cleanup);
#endif


static struct rte_driver mlx4_en = {
	.type = PMD_PDEV,
	.init = mlx4_en_init,
	.uninit = mlx4_en_cleanup,
};


PMD_REGISTER_DRIVER(mlx4_en);
