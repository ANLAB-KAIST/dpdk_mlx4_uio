/*
 * en_rx_uio.c
 *
 *  Created on: Jul 1, 2015
 *      Author: leeopop
 */


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

#include "mlx4_uio_helper.h"

static void mlx4_en_init_rx_desc(struct mlx4_en_priv *priv,
				 struct mlx4_en_rx_ring *ring, int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + ring->stride * index;
	int possible_frags;
	int i;

	/* Set size and memtype fields */
	for (i = 0; i < ring->num_frags; i++) {
		rx_desc->data[i].byte_count =
			cpu_to_be32(ring->frag_size);
		rx_desc->data[i].lkey = cpu_to_be32(priv->mdev->mr.key);
	}

	/* If the number of used fragments does not fill up the ring stride,
	 * remaining (unused) fragments must be padded with null address/size
	 * and a special memory key */
	possible_frags = (ring->stride - sizeof(struct mlx4_en_rx_desc)) / DS_SIZE;
	for (i = ring->num_frags; i < possible_frags; i++) {
		rx_desc->data[i].byte_count = 0;
		rx_desc->data[i].lkey = cpu_to_be32(MLX4_EN_MEMTYPE_PAD);
		rx_desc->data[i].addr = 0;
	}
}

static void mlx4_en_free_rx_desc(struct mlx4_en_priv *priv,
		struct mlx4_en_rx_ring *ring,
		int index)
{
	struct rte_mbuf **frags;
	int nr;

	frags = ring->rx_info + (index * ring->num_frags);
	for (nr = 0; nr < ring->num_frags; nr++) {
		en_dbg(DRV, priv, "Freeing fragment:%d\n", nr);
		rte_pktmbuf_free_seg(frags[nr]);
	}
}

static int mlx4_en_fill_rx_buffers(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int ring_ind;
	int buf_ind;
	int new_size;
	for (ring_ind = 0; ring_ind < priv->rte_dev->data->nb_rx_queues; ring_ind++) {
		ring = priv->rte_dev->data->rx_queues[ring_ind];
		for (buf_ind = 0; buf_ind < priv->prof->rx_ring_size; buf_ind++) {
			if (mlx4_en_prepare_rx_desc(priv, ring, ring->actual_size))
			{
				if (ring->actual_size < MLX4_EN_MIN_RX_SIZE)
				{
					en_err(priv, "Failed to allocate enough rx buffers\n");
					return -ENOMEM;
				}
				else
				{
					new_size = rounddown_pow_of_two(ring->actual_size);
					en_warn(priv, "Only %d buffers allocated reducing ring size to %d\n",
							ring->actual_size, new_size);
					while (ring->actual_size > new_size) {
						ring->actual_size--;
						ring->prod--;
						mlx4_en_free_rx_desc(priv, ring, ring->actual_size);
					}
					break;
				}
			}
			ring->actual_size++;
			ring->prod++;
		}
	}
	return 0;
}

int mlx4_en_activate_rx_rings(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int i;
	int ring_ind;
	int err;


	for (ring_ind = 0; ring_ind < priv->rte_dev->data->nb_rx_queues; ring_ind++) {
		ring = priv->rte_dev->data->rx_queues[ring_ind];
		int stride = (priv->prof->inline_scatter_thold >= MIN_INLINE_SCATTER) ?
				priv->stride :
				roundup_pow_of_two(sizeof(struct mlx4_en_rx_desc) +
						DS_SIZE * ring->num_frags);

		ring->prod = 0;
		ring->cons = 0;
		ring->actual_size = 0;
		//ring->cqn = priv->rx_cq[ring_ind]->mcq.cqn;

		ring->stride = stride;
		if (ring->stride <= TXBB_SIZE)
			ring->buf += TXBB_SIZE;

		ring->log_stride = ffs(ring->stride) - 1;
		ring->buf_size = ring->size * ring->stride;

		memset(ring->buf, 0, ring->buf_size);
		mlx4_en_update_rx_prod_db(ring);

		/* Initialize all descriptors */
		for (i = 0; i < ring->size; i++)
			mlx4_en_init_rx_desc(priv, ring, i);

		/* Initialize page allocators */
#ifdef KMOD_DISABLED
		err = mlx4_en_init_allocator(priv, ring);
		if (err) {
			en_err(priv, "Failed initializing ring allocator\n");
			if (ring->stride <= TXBB_SIZE)
				ring->buf -= TXBB_SIZE;
			ring_ind--;
			goto err_allocator;
		}
#endif
#ifdef CONFIG_COMPAT_LRO_ENABLED
		mlx4_en_lro_init(ring, priv);
#endif
	}
	err = mlx4_en_fill_rx_buffers(priv);
	if (err)
		return err;

	for (ring_ind = 0; ring_ind < priv->rte_dev->data->nb_rx_queues; ring_ind++) {
		ring = priv->rte_dev->data->rx_queues[ring_ind];

		ring->size_mask = ring->actual_size - 1;
		mlx4_en_update_rx_prod_db(ring);
	}

	return err;
}
