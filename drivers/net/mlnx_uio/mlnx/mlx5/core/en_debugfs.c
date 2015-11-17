#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2015, Mellanox Technologies inc.  All rights reserved.
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

static void mlx5e_create_channel_debugfs(struct mlx5e_priv *priv,
					 int channel_num)
{
	int i;
	char name[MLX5_MAX_NAME_LEN];
	struct dentry *channel_root;
	struct mlx5e_channel *channel;

	snprintf(name, MLX5_MAX_NAME_LEN, "channel-%d", channel_num);
	channel_root = debugfs_create_dir(name, priv->dfs_root);
	if (!channel_root) {
		netdev_err(priv->netdev,
			   "Failed to create channel debugfs for %s\n",
			   priv->netdev->name);
		return;
	}
	priv->channel[channel_num]->dfs_root = channel_root;
	channel = priv->channel[channel_num];

	for (i = 0; i < priv->params.num_tc; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "sqn-%d", i);
		debugfs_create_u32(name, S_IRUSR, channel_root,
				   &channel->sq[i].sqn);

		snprintf(name, MLX5_MAX_NAME_LEN, "sq-cqn-%d", i);
		debugfs_create_u32(name, S_IRUSR, channel_root,
				   &channel->sq[i].cq.mcq.cqn);
	}

	debugfs_create_u32("rqn", S_IRUSR, channel_root,
			   &channel->rq.rqn);

	debugfs_create_u32("rq-cqn", S_IRUSR, channel_root,
			   &channel->rq.cq.mcq.cqn);
}

void mlx5e_create_debugfs(struct mlx5e_priv *priv)
{
	int i;
	char name[MLX5_MAX_NAME_LEN];

	priv->dfs_root = debugfs_create_dir(priv->netdev->name, NULL);
	if (!priv->dfs_root) {
		netdev_err(priv->netdev, "Failed to init debugfs files for %s\n",
			   priv->netdev->name);
		return;
	}

	debugfs_create_u32("uar", S_IRUSR, priv->dfs_root,
			   &priv->cq_uar.index);
	debugfs_create_u32("pdn", S_IRUSR, priv->dfs_root, &priv->pdn);
	debugfs_create_u32("mkey", S_IRUSR, priv->dfs_root,
			   &priv->mr.key);
	debugfs_create_u8("num_tc", S_IRUSR, priv->dfs_root,
			  &priv->params.num_tc);

	for (i = 0; i < priv->params.num_tc; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "tisn-%d", i);
		debugfs_create_u32(name, S_IRUSR, priv->dfs_root,
				   &priv->tisn[i]);
	}

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		snprintf(name, MLX5_MAX_NAME_LEN, "tirn-%d", i);
		debugfs_create_u32(name, S_IRUSR, priv->dfs_root,
				   &priv->tirn[i]);
	}

	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_create_channel_debugfs(priv, i);
}

void mlx5e_destroy_debugfs(struct mlx5e_priv *priv)
{
	debugfs_remove_recursive(priv->dfs_root);
	priv->dfs_root = NULL;
}
