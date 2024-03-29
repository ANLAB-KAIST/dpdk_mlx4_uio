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
#include "log2.h"

void mlx4_en_fill_qp_context(struct mlx4_en_priv *priv, int size, int stride,
			     int is_tx, int rss, int qpn, int cqn,
#ifdef HAVE_NEW_TX_RING_SCHEME
			     int user_prio, struct mlx4_qp_context *context)
#else
			     struct mlx4_qp_context *context)
#endif
{
	struct mlx4_en_dev *mdev = priv->mdev;
	//struct net_device *dev = priv->dev;
	struct rte_eth_dev *rte_dev = priv->rte_dev;

	memset(context, 0, sizeof *context);
	context->flags = cpu_to_be32(7 << 16 | rss << MLX4_RSS_QPC_FLAG_OFFSET);
	context->pd = cpu_to_be32(mdev->priv_pdn);
	context->mtu_msgmax = 0xff;
	if (!is_tx && !rss)
		context->rq_size_stride = ilog2(size) << 3 | (ilog2(stride) - 4);
	if (is_tx) {
		context->sq_size_stride = ilog2(size) << 3 | (ilog2(stride) - 4);
		if (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_PORT_REMAP)
			context->params2 |= MLX4_QP_BIT_FPP;

	} else {
		context->sq_size_stride = ilog2(TXBB_SIZE) - 4;
	}
	context->usr_page = cpu_to_be32(mdev->priv_uar.index);
	context->local_qpn = cpu_to_be32(qpn);
	context->pri_path.ackto = 1 & 0x07;
	context->pri_path.sched_queue = 0x83 | (priv->port - 1) << 6;
#ifdef HAVE_NEW_TX_RING_SCHEME
	if (user_prio >= 0) {
		context->pri_path.sched_queue |= user_prio << 3;
		context->pri_path.feup = MLX4_FEUP_FORCE_ETH_UP;
	}
#endif
	context->pri_path.counter_index = (u8)(priv->counter_index);
	context->cqn_send = cpu_to_be32(cqn);
	context->cqn_recv = cpu_to_be32(cqn);
	if (!rss &&
	    (mdev->dev->caps.flags2 & MLX4_DEV_CAP_FLAG2_LB_SRC_CHK) &&
	    context->pri_path.counter_index != MLX4_SINK_COUNTER_INDEX) {
		/* disable multicast loopback to qp with same counter */
#ifdef KMOD_MODIFIED
		if(!(rte_dev->data->dev_conf.lpbk_mode))
			context->pri_path.fl |= MLX4_FL_ETH_SRC_CHECK_MC_LB;
#else
		if (!(dev->features & NETIF_F_LOOPBACK))
			context->pri_path.fl |= MLX4_FL_ETH_SRC_CHECK_MC_LB;
#endif
		context->pri_path.control |=
			MLX4_CTRL_ETH_SRC_CHECK_IF_COUNTER;
	}
	context->db_rec_addr = cpu_to_be64(priv->res.db.dma << 2);
#ifdef KMOD_MODIFIED
	//XXX VLAN rte_dev->data->dev_conf.rxmode.hw_vlan_strip;
#else
	if (!(dev->features & NETIF_F_HW_VLAN_CTAG_RX))
		context->param3 |= cpu_to_be32(1 << 30);
#endif
#ifdef KMOD_MODIFIED
	//XXX DISABLE inline scatter
#else
	if (!is_tx && !rss &&
	   (priv->prof->inline_scatter_thold >= MIN_INLINE_SCATTER)) {
		context->param3 |= cpu_to_be32(1 << 25);
	}
#endif

#ifdef KMOD_MODIFIED
	//XXX DISABLE vlan offloading
	//we usually use multi rx rings with rss
#else
	if (!is_tx && !rss &&
	    (mdev->dev->caps.tunnel_offload_mode ==  MLX4_TUNNEL_OFFLOAD_MODE_VXLAN)) {
		en_dbg(HW, priv, "Setting RX qp %x tunnel mode to RX tunneled & non-tunneled\n", qpn);
		context->srqn = cpu_to_be32(7 << 28); /* this fills bits 30:28 */
	}
#endif
}

int mlx4_en_change_mcast_loopback(struct mlx4_en_priv *priv, struct mlx4_qp *qp,
				  int loopback)
{
	int ret;
	struct mlx4_update_qp_params qp_params;

	memset(&qp_params, 0, sizeof(qp_params));
	if (!loopback)
		qp_params.flags = MLX4_UPDATE_QP_PARAMS_FLAGS_ETH_CHECK_MC_LB;

	ret = mlx4_update_qp(priv->mdev->dev, qp->qpn,
			     MLX4_UPDATE_QP_ETH_SRC_CHECK_MC_LB,
			     &qp_params);

	return ret;
}

int mlx4_en_map_buffer(struct mlx4_buf *buf)
{
	//struct page **pages;
	//int i;

	if (BITS_PER_LONG == 64 || buf->nbufs == 1)
		return 0;
#ifdef KMOD_MODIFIED
	assert(buf->nbufs == 1); //we do not provide vmap of virtual addresses
	return -1;
#else

	pages = kmalloc(sizeof *pages * buf->nbufs, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < buf->nbufs; ++i)
		pages[i] = virt_to_page(buf->page_list[i].buf);

	buf->direct.buf = vmap(pages, buf->nbufs, VM_MAP, PAGE_KERNEL);
	kfree(pages);
	if (!buf->direct.buf)
		return -ENOMEM;

	return 0;
#endif
}

void mlx4_en_unmap_buffer(struct mlx4_buf *buf)
{
	if (BITS_PER_LONG == 64 || buf->nbufs == 1)
		return;
#ifdef KMOD_MODIFIED
	assert(buf->nbufs == 1); //we do not provide vmap of virtual addresses
	return;
#else
	vunmap(buf->direct.buf);
#endif
}

void mlx4_en_sqp_event(struct mlx4_qp *qp, enum mlx4_event event)
{
    return;
}

