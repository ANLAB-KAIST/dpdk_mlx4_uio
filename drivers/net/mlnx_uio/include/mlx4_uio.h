/*
 * mlx4_uio.h
 *
 *  Created on: Jun 30, 2015
 *      Author: leeopop
 */

#ifndef DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_H_
#define DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_H_

#include <rte_common.h>
#include <rte_ethdev.h>

uint16_t
mlx4_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t
mlx4_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);

extern const struct eth_dev_ops mlx4_eth_dev_ops;


#endif /* DRIVERS_NET_MLNX_UIO_INCLUDE_MLX4_UIO_H_ */
