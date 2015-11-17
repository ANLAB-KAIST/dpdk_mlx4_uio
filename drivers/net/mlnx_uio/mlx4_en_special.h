/*
 * mlx4_special.h
 *
 *  Created on: Nov 4, 2014
 *      Author: leeopop
 */

#ifndef MLX4_EN_SPECIAL_H_
#define MLX4_EN_SPECIAL_H_

struct rte_mbuf;
typedef void (*mlx4_tx_completion_callback_t)(uint64_t timestamp, struct rte_mbuf* mbuf, void* arg);

int mlx4_set_tx_timestamp(int port, int queue_id, int use);
int mlx4_set_rx_timestamp(int port, int queue_id, int use);
int mlx4_poll_tx_cq(int port, int txq);
int mlx4_set_tx_completion_callback(int port, int queue_id, mlx4_tx_completion_callback_t callback, void* arg);
uint64_t mlx4_read_dev_clock_hz(int port);
uint64_t mlx4_read_dev_clock(int port);

#endif /* MLX4_EN_SPECIAL_H_ */
