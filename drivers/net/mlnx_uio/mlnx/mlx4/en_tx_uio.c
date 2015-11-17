/*
 * en_tx_uio.c
 *
 *  Created on: Jul 1, 2015
 *      Author: leeopop
 */

#include "mlx4_en.h"
#include "mlx4_uio_helper.h"

int mlx4_en_activate_tx_ring(struct mlx4_en_priv *priv,
			     struct mlx4_en_tx_ring *ring,
#ifdef HAVE_NEW_TX_RING_SCHEME
			     int cq, int user_prio)
#else
			     int cq)
#endif
{
	struct mlx4_en_dev *mdev = priv->mdev;
	int err;

	ring->cqn = cq;
	ring->prod = 0;
	ring->cons = 0xffffffff;
	ring->last_nr_txbb = 1;
	memset(ring->tx_info, 0, ring->size * sizeof(struct mlx4_en_tx_info));
	memset(ring->buf, 0, ring->buf_size);

	ring->qp_state = MLX4_QP_STATE_RST;
	ring->doorbell_qpn = cpu_to_be32(ring->qp.qpn << 8);
	ring->mr_key = cpu_to_be32(mdev->mr.key);

#ifdef HAVE_NEW_TX_RING_SCHEME
	mlx4_en_fill_qp_context(priv, ring->size, ring->stride, 1, 0, ring->qpn,
				ring->cqn, user_prio, &ring->context);
#else
	mlx4_en_fill_qp_context(priv, ring->size, ring->stride, 1, 0, ring->qpn,
				ring->cqn, &ring->context);
#endif
	if (ring->bf_alloced)
		ring->context.usr_page = cpu_to_be32(ring->bf.uar->index);

	err = mlx4_qp_to_ready(mdev->dev, &ring->wqres.mtt, &ring->context,
			       &ring->qp, &ring->qp_state);

	return err;
}
