#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#include "linux/mlx5/vport.h"
#include "mlx5_core.h"

u8 mlx5_query_vport_state(struct mlx5_core_dev *mdev, u8 opmod)
{
	u32 in[MLX5_ST_SZ_DW(query_vport_state_in)];
	u32 out[MLX5_ST_SZ_DW(query_vport_state_out)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(query_vport_state_in, in, opcode,
		 MLX5_CMD_OP_QUERY_VPORT_STATE);
	MLX5_SET(query_vport_state_in, in, op_mod, opmod);

	err = mlx5_cmd_exec_check_status(mdev, in, sizeof(in), out,
					 sizeof(out));
	if (err)
		mlx5_core_warn(mdev, "MLX5_CMD_OP_QUERY_VPORT_STATE failed\n");

	return MLX5_GET(query_vport_state_out, out, state);
}
EXPORT_SYMBOL_GPL(mlx5_query_vport_state);

static int mlx5_query_nic_vport_context(struct mlx5_core_dev *mdev, u32 *out,
					 int outlen)
{
	u32 in[MLX5_ST_SZ_DW(query_nic_vport_context_in)];

	memset(in, 0, sizeof(in));

	MLX5_SET(query_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT);

	return mlx5_cmd_exec_check_status(mdev, in, sizeof(in), out, outlen);
}

int mlx5_query_nic_vport_mac_address(struct mlx5_core_dev *mdev, u8 *addr)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	u8 *out_addr;
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	out_addr = MLX5_ADDR_OF(query_nic_vport_context_out, out,
				nic_vport_context.permanent_address);

	err = mlx5_query_nic_vport_context(mdev, out, outlen);
	if (err)
		goto out;

	ether_addr_copy(addr, &out_addr[2]);

out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_mac_address);

int mlx5_query_nic_vport_system_image_guid(struct mlx5_core_dev *mdev,
					   u64 *system_image_guid)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, out, outlen);
	if (err)
		goto out;

	*system_image_guid = MLX5_GET64(query_nic_vport_context_out, out,
					nic_vport_context.system_image_guid);
out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_system_image_guid);

int mlx5_query_nic_vport_node_guid(struct mlx5_core_dev *mdev, u64 *node_guid)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, out, outlen);
	if (err)
		goto out;

	*node_guid = MLX5_GET64(query_nic_vport_context_out, out,
				nic_vport_context.node_guid);

out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_node_guid);

int mlx5_query_nic_vport_qkey_viol_cntr(struct mlx5_core_dev *mdev,
					u16 *qkey_viol_cntr)
{
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_nic_vport_context_out);
	int err;

	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_query_nic_vport_context(mdev, out, outlen);
	if (err)
		goto out;

	*qkey_viol_cntr = MLX5_GET(query_nic_vport_context_out, out,
				nic_vport_context.qkey_violation_counter);

out:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_nic_vport_qkey_viol_cntr);

static int mlx5_modify_nic_vport_context(struct mlx5_core_dev *mdev, void *in,
					 int inlen)
{
	u32 out[MLX5_ST_SZ_DW(modify_nic_vport_context_out)];

	MLX5_SET(modify_nic_vport_context_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT);

	memset(out, 0, sizeof(out));
	return mlx5_cmd_exec_check_status(mdev, in, inlen, out, sizeof(out));
}

static int mlx5_nic_vport_enable_disable_roce(struct mlx5_core_dev *mdev,
					      int enable_disable)
{
	void *in;
	int inlen = MLX5_ST_SZ_BYTES(modify_nic_vport_context_in);
	int err;

	in = mlx5_vzalloc(inlen);
	if (!in) {
		mlx5_core_warn(mdev, "failed to allocate inbox\n");
		return -ENOMEM;
	}

	MLX5_SET(modify_nic_vport_context_in, in, field_select.roce_en, 1);
	MLX5_SET(modify_nic_vport_context_in, in, nic_vport_context.roce_en,
		 enable_disable);

	err = mlx5_modify_nic_vport_context(mdev, in, inlen);

	kvfree(in);

	return err;
}

int mlx5_nic_vport_enable_roce(struct mlx5_core_dev *mdev)
{
	return mlx5_nic_vport_enable_disable_roce(mdev, 1);
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_enable_roce);

int mlx5_nic_vport_disable_roce(struct mlx5_core_dev *mdev)
{
	return mlx5_nic_vport_enable_disable_roce(mdev, 0);
}
EXPORT_SYMBOL_GPL(mlx5_nic_vport_disable_roce);
