#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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

#include "mlx5_core.h"

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,39))
static int mlx5_pci_num_vf(struct pci_dev *pdev)
{
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);

	if (!mlx5_core_is_pf(dev))
		return 0;

	return dev->priv.sriov.num_vfs;
}
#endif

static int is_valid_vf(struct mlx5_core_dev *dev, int vf)
{
	struct pci_dev *pdev = dev->pdev;

	if (vf == 1)
		return 1;

	if (mlx5_core_is_pf(dev))
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,39))
		return (vf <= mlx5_pci_num_vf(pdev)) && (vf >= 1);
#else
		return (vf <= pci_num_vf(pdev)) && (vf >= 1);
#endif

	return 0;
}

int mlx5_core_access_reg(struct mlx5_core_dev *dev, void *data_in,
			 int size_in, void *data_out, int size_out,
			 u16 reg_num, int arg, int write)
{
	struct mlx5_access_reg_mbox_in *in = NULL;
	struct mlx5_access_reg_mbox_out *out = NULL;
	int err = -ENOMEM;

	in = mlx5_vzalloc(sizeof(*in) + size_in);
	if (!in)
		goto ex;

	out = mlx5_vzalloc(sizeof(*out) + size_out);
	if (!out)
		goto ex;

	memcpy(in->data, data_in, size_in);
	in->hdr.opcode = cpu_to_be16(MLX5_CMD_OP_ACCESS_REG);
	in->hdr.opmod = cpu_to_be16(!write);
	in->arg = cpu_to_be32(arg);
	in->register_id = cpu_to_be16(reg_num);
	err = mlx5_cmd_exec(dev, in, sizeof(*in) + size_in, out,
			    sizeof(*out) + size_out);
	if (err)
		goto ex;

	err = mlx5_cmd_status_to_err(&out->hdr);
	if (!err)
		memcpy(data_out, out->data, size_out);

ex:
	kvfree(out);
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_reg);


struct mlx5_reg_pcap {
	u8			rsvd0;
	u8			port_num;
	u8			rsvd1[2];
	__be32			caps_127_96;
	__be32			caps_95_64;
	__be32			caps_63_32;
	__be32			caps_31_0;
};

static int set_port_caps_pf(struct mlx5_core_dev *dev, u8 port_num,
			    u32 set, u32 clear, u32 cur)
{
	struct mlx5_reg_pcap in;
	struct mlx5_reg_pcap out;
	u32 tmp;
	int err;

	tmp = (cur | set) & ~clear;

	memset(&in, 0, sizeof(in));
	in.caps_127_96 = cpu_to_be32(tmp);
	in.port_num = port_num;

	err = mlx5_core_access_reg(dev, &in, sizeof(in), &out,
				   sizeof(out), MLX5_REG_PCAP, 0, 1);

	return err;
}

static int set_port_caps_vf(struct mlx5_core_dev *dev, u8 port_num,
			    u32 set, u32 clear)
{
	struct mlx5_hca_vport_context *req;
	int err;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->cap_mask1 = set | ~clear;
	req->cap_mask1_perm = set | clear;
	err = mlx5_core_modify_hca_vport_context(dev, 0, port_num,
						 0, req);

	kfree(req);
	return err;
}

int mlx5_set_port_caps(struct mlx5_core_dev *dev, u8 port_num,
		       u32 set, u32 clear, u32 cur)
{
	if (mlx5_core_is_pf(dev))
		return set_port_caps_pf(dev, port_num, set, clear, cur);

	return set_port_caps_vf(dev, port_num, set, clear);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_caps);

int mlx5_query_port_ptys(struct mlx5_core_dev *dev, u32 *ptys,
			 int ptys_size, int proto_mask)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);

	err = mlx5_core_access_reg(dev, in, sizeof(in), ptys,
				   ptys_size, MLX5_REG_PTYS, 0, 0);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_ptys);

int mlx5_query_port_proto_cap(struct mlx5_core_dev *dev,
			      u32 *proto_cap, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_cap = MLX5_GET(ptys_reg, out, eth_proto_capability);
	else
		*proto_cap = MLX5_GET(ptys_reg, out, ib_proto_capability);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_cap);

int mlx5_core_access_ptys(struct mlx5_core_dev *dev, struct mlx5_ptys_reg *ptys, int write)
{
	int sz = MLX5_ST_SZ_BYTES(ptys_reg);
	void *out = NULL;
	void *in = NULL;
	int err;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out)
		return -ENOMEM;

	MLX5_SET(ptys_reg, in, local_port, ptys->local_port);
	MLX5_SET(ptys_reg, in, proto_mask, ptys->proto_mask);
	if (write) {
		MLX5_SET(ptys_reg, in, eth_proto_capability, ptys->eth_proto_cap);
		MLX5_SET(ptys_reg, in, ib_link_width_capability, ptys->ib_link_width_cap);
		MLX5_SET(ptys_reg, in, ib_proto_capability, ptys->ib_proto_cap);
		MLX5_SET(ptys_reg, in, eth_proto_admin, ptys->eth_proto_admin);
		MLX5_SET(ptys_reg, in, ib_link_width_admin, ptys->ib_link_width_admin);
		MLX5_SET(ptys_reg, in, ib_proto_admin, ptys->ib_proto_admin);
		MLX5_SET(ptys_reg, in, eth_proto_oper, ptys->eth_proto_oper);
		MLX5_SET(ptys_reg, in, ib_link_width_oper, ptys->ib_link_width_oper);
		MLX5_SET(ptys_reg, in, ib_proto_oper, ptys->ib_proto_oper);
		MLX5_SET(ptys_reg, in, eth_proto_lp_advertise, ptys->eth_proto_lp_advertise);
	}

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PTYS, 0, !!write);
	if (err)
		goto out;

	if (!write) {
		ptys->local_port = MLX5_GET(ptys_reg, out, local_port);
		ptys->proto_mask = MLX5_GET(ptys_reg, out, proto_mask);
		ptys->eth_proto_cap = MLX5_GET(ptys_reg, out, eth_proto_capability);
		ptys->ib_link_width_cap = MLX5_GET(ptys_reg, out, ib_link_width_capability);
		ptys->ib_proto_cap = MLX5_GET(ptys_reg, out, ib_proto_capability);
		ptys->eth_proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
		ptys->ib_link_width_admin = MLX5_GET(ptys_reg, out, ib_link_width_admin);
		ptys->ib_proto_admin = MLX5_GET(ptys_reg, out, ib_proto_admin);
		ptys->eth_proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);
		ptys->ib_link_width_oper = MLX5_GET(ptys_reg, out, ib_link_width_oper);
		ptys->ib_proto_oper = MLX5_GET(ptys_reg, out, ib_proto_oper);
		ptys->eth_proto_lp_advertise = MLX5_GET(ptys_reg, out, eth_proto_lp_advertise);
	}

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_ptys);

int mlx5_core_access_pvlc(struct mlx5_core_dev *dev, struct mlx5_pvlc_reg *pvlc, int write)
{
	int sz = MLX5_ST_SZ_BYTES(pvlc_reg);
	u8 in[MLX5_ST_SZ_BYTES(pvlc_reg)];
	u8 out[MLX5_ST_SZ_BYTES(pvlc_reg)];
	int err;

	memset(out, 0, sizeof(out));
	memset(in, 0, sizeof(in));

	MLX5_SET(pvlc_reg, in, local_port, pvlc->local_port);
	if (write)
		MLX5_SET(pvlc_reg, in, vl_admin, pvlc->vl_admin);

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PVLC, 0, !!write);
	if (err)
		return err;

	if (!write) {
		pvlc->local_port = MLX5_GET(pvlc_reg, out, local_port);
		pvlc->vl_hw_cap = MLX5_GET(pvlc_reg, out, vl_hw_cap);
		pvlc->vl_admin = MLX5_GET(pvlc_reg, out, vl_admin);
		pvlc->vl_operational = MLX5_GET(pvlc_reg, out, vl_operational);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_pvlc);

static int mtu_to_ib_mtu(int mtu)
{
	switch (mtu) {
	case 256: return 1;
	case 512: return 2;
	case 1024: return 3;
	case 2048: return 4;
	case 4096: return 5;
	default:
		pr_warn("invalid mtu\n");
		return -1;
	}
}

int mlx5_core_access_pmtu(struct mlx5_core_dev *dev, struct mlx5_pmtu_reg *pmtu, int write)
{
	int sz = MLX5_ST_SZ_BYTES(pmtu_reg);
	void *out = NULL;
	void *in = NULL;
	int err;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out)
		return -ENOMEM;

	MLX5_SET(pmtu_reg, in, local_port, pmtu->local_port);
	if (write)
		MLX5_SET(pmtu_reg, in, admin_mtu, pmtu->admin_mtu);

	err = mlx5_core_access_reg(dev, in, sz, out, sz, MLX5_REG_PMTU, 0, !!write);
	if (err)
		goto out;

	if (!write) {
		pmtu->local_port = MLX5_GET(pmtu_reg, out, local_port);
		pmtu->max_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, max_mtu));
		pmtu->admin_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, admin_mtu));
		pmtu->oper_mtu = mtu_to_ib_mtu(MLX5_GET(pmtu_reg, out, oper_mtu));
	}

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_pmtu);

int mlx5_query_port_proto_admin(struct mlx5_core_dev *dev,
				u32 *proto_admin, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	else
		*proto_admin = MLX5_GET(ptys_reg, out, ib_proto_admin);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_admin);

int mlx5_set_port_proto(struct mlx5_core_dev *dev, u32 proto_admin,
			int proto_mask)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);
	if (proto_mask == MLX5_PTYS_EN)
		MLX5_SET(ptys_reg, in, eth_proto_admin, proto_admin);
	else
		MLX5_SET(ptys_reg, in, ib_proto_admin, proto_admin);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PTYS, 0, 1);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_proto);

int mlx5_set_port_status(struct mlx5_core_dev *dev,
			 enum mlx5_port_status status)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)];
	u32 out[MLX5_ST_SZ_DW(paos_reg)];
	int err;

	memset(in, 0, sizeof(in));

	MLX5_SET(paos_reg, in, admin_status, status);
	MLX5_SET(paos_reg, in, ase, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PAOS, 0, 1);
	return err;
}

int mlx5_query_port_status(struct mlx5_core_dev *dev, u8 *status)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)];
	u32 out[MLX5_ST_SZ_DW(paos_reg)];
	int err;

	memset(in, 0, sizeof(in));

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PAOS, 0, 0);
	if (err)
		return err;

	*status = MLX5_GET(paos_reg, out, oper_status);
	return err;
}

static void mlx5_query_port_mtu(struct mlx5_core_dev *dev,
				int *admin_mtu, int *max_mtu, int *oper_mtu)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)];
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	memset(in, 0, sizeof(in));

	MLX5_SET(pmtu_reg, in, local_port, 1);

	mlx5_core_access_reg(dev, in, sizeof(in), out,
			     sizeof(out), MLX5_REG_PMTU, 0, 0);

	if (max_mtu)
		*max_mtu  = MLX5_GET(pmtu_reg, out, max_mtu);
	if (oper_mtu)
		*oper_mtu = MLX5_GET(pmtu_reg, out, oper_mtu);
	if (admin_mtu)
		*admin_mtu = MLX5_GET(pmtu_reg, out, admin_mtu);
}

int mlx5_set_port_mtu(struct mlx5_core_dev *dev, int mtu)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)];
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	memset(in, 0, sizeof(in));

	MLX5_SET(pmtu_reg, in, admin_mtu, mtu);
	MLX5_SET(pmtu_reg, in, local_port, 1);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PMTU, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_mtu);

void mlx5_query_port_max_mtu(struct mlx5_core_dev *dev, int *max_mtu)
{
	mlx5_query_port_mtu(dev, NULL, max_mtu, NULL);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_max_mtu);

void mlx5_query_port_oper_mtu(struct mlx5_core_dev *dev, int *oper_mtu)
{
	mlx5_query_port_mtu(dev, NULL, NULL, oper_mtu);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_oper_mtu);

int mlx5_core_query_gids(struct mlx5_core_dev *dev, u8 other_vport,
			 u8 port_num, u16  vf_num, u16 gid_index,
			 union ib_gid *gid)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	union ib_gid *tmp;
	int tbsz;
	int nout;
	int err;

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	tbsz = mlx5_get_gid_table_len(MLX5_CAP_GEN(dev, gid_table_size));
	mlx5_core_dbg(dev, "vf_num %d, index %d, gid_table_size %d\n",
		      vf_num, gid_index, tbsz);

	if (gid_index > tbsz && gid_index != 0xffff)
		return -EINVAL;

	if (gid_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*gid);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_gid_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_GID);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_gid_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_gid_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_gid_in, in, gid_index, gid_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_gid_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto out;

	tmp = out + MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	gid->global.subnet_prefix = tmp->global.subnet_prefix;
	gid->global.interface_id = tmp->global.interface_id;

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_gids);

int mlx5_core_query_pkeys(struct mlx5_core_dev *dev, u8 other_vport,
			  u8 port_num, u16 vf_num, u16 pkey_index,
			  u16 *pkey)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	void *pkarr;
	int nout;
	int tbsz;
	int err;
	int i;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	tbsz = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(dev, pkey_table_size));
	if (pkey_index > tbsz && pkey_index != 0xffff)
		return -EINVAL;

	if (pkey_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * MLX5_ST_SZ_BYTES(pkey);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_pkey_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_pkey_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_pkey_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_pkey_in, in, pkey_index, pkey_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_pkey_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto out;

	pkarr = out + MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	for (i = 0; i < nout; i++, pkey++, pkarr += MLX5_ST_SZ_BYTES(pkey))
		*pkey = MLX5_GET_PR(pkey, pkarr, pkey);

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_pkeys);

#define MLX5_ENABLE_HCA_MASK (MLX5_HCA_VPORT_SEL_NODE_GUID | MLX5_HCA_VPORT_SEL_PORT_GUID)
int mlx5_core_check_enable_vf_hca(struct mlx5_core_dev *dev, u32 field_select, u8 vport_num)
{
	struct mlx5_core_sriov *sriov = &dev->priv.sriov;
	struct mlx5_vf_context *ctx;
	int err;

	if (!mlx5_core_is_pf(dev))
		return 0;

	if (!sriov)
		return -ENOMEM;

	if (!sriov->vfs_ctx)
		return -ENOMEM;

	vport_num += 1;
	if (!is_valid_vf(dev, vport_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vport_num);
		return -EINVAL;
	}

	ctx = &sriov->vfs_ctx[vport_num - 1];
	ctx->state_mask |= (MLX5_ENABLE_HCA_MASK & field_select);
	if (ctx->state_mask != MLX5_ENABLE_HCA_MASK || ctx->enabled)
		return 0;

	err = mlx5_core_enable_hca(dev, vport_num);
	if (!err)
		ctx->enabled = 1;

	return err;
}

int mlx5_core_modify_hca_vport_context(struct mlx5_core_dev *dev,
				       u8 other_vport, u8 port_num,
				       u16 vf_num,
				       struct mlx5_hca_vport_context *req)
{
	int in_sz = MLX5_ST_SZ_BYTES(modify_hca_vport_context_in);
	u8 out[MLX5_ST_SZ_BYTES(modify_hca_vport_context_out)];
	int is_group_manager;
	void *in;
	int err;
	void *ctx;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	memset(out, 0, sizeof(out));
	MLX5_SET(modify_hca_vport_context_in, in, opcode, MLX5_CMD_OP_MODIFY_HCA_VPORT_CONTEXT);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(modify_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(modify_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(modify_hca_vport_context_in, in, port_num, port_num);

	ctx = MLX5_ADDR_OF(modify_hca_vport_context_in, in, hca_vport_context);
	MLX5_SET(hca_vport_context, ctx, field_select, req->field_select);
	MLX5_SET(hca_vport_context, ctx, sm_virt_aware, req->sm_virt_aware);
	MLX5_SET(hca_vport_context, ctx, has_smi, req->has_smi);
	MLX5_SET(hca_vport_context, ctx, has_raw, req->has_raw);
	MLX5_SET(hca_vport_context, ctx, vport_state_policy, req->policy);
	MLX5_SET(hca_vport_context, ctx, port_physical_state, req->phys_state);
	MLX5_SET(hca_vport_context, ctx, vport_state, req->vport_state);
	MLX5_SET64(hca_vport_context, ctx, port_guid, req->port_guid);
	MLX5_SET64(hca_vport_context, ctx, node_guid, req->node_guid);
	MLX5_SET(hca_vport_context, ctx, cap_mask1, req->cap_mask1);
	MLX5_SET(hca_vport_context, ctx, cap_mask1_field_select, req->cap_mask1_perm);
	MLX5_SET(hca_vport_context, ctx, cap_mask2, req->cap_mask2);
	MLX5_SET(hca_vport_context, ctx, cap_mask2_field_select, req->cap_mask2_perm);
	MLX5_SET(hca_vport_context, ctx, lid, req->lid);
	MLX5_SET(hca_vport_context, ctx, init_type_reply, req->init_type_reply);
	MLX5_SET(hca_vport_context, ctx, lmc, req->lmc);
	MLX5_SET(hca_vport_context, ctx, subnet_timeout, req->subnet_timeout);
	MLX5_SET(hca_vport_context, ctx, sm_lid, req->sm_lid);
	MLX5_SET(hca_vport_context, ctx, sm_sl, req->sm_sl);
	MLX5_SET(hca_vport_context, ctx, qkey_violation_counter, req->qkey_violation_counter);
	MLX5_SET(hca_vport_context, ctx, pkey_violation_counter, req->pkey_violation_counter);
	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));
	if (err)
		goto ex;

	err = mlx5_cmd_status_to_err_v2(out);

ex:
	kfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_modify_hca_vport_context);

int mlx5_core_query_hca_vport_context(struct mlx5_core_dev *dev,
				      u8 other_vport, u8 port_num,
				      u16 vf_num,
				      struct mlx5_hca_vport_context *rep)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_context_out);
	int in[MLX5_ST_SZ_BYTES(query_hca_vport_context_in)];
	int is_group_manager;
	void *out;
	void *ctx;
	int err;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	memset(in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);

	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(query_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_context_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out,  out_sz);
	if (err)
		goto ex;
	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto ex;

	ctx = MLX5_ADDR_OF(query_hca_vport_context_out, out, hca_vport_context);
	rep->field_select = MLX5_GET_PR(hca_vport_context, ctx, field_select);
	rep->sm_virt_aware = MLX5_GET_PR(hca_vport_context, ctx, sm_virt_aware);
	rep->has_smi = MLX5_GET_PR(hca_vport_context, ctx, has_smi);
	rep->has_raw = MLX5_GET_PR(hca_vport_context, ctx, has_raw);
	rep->policy = MLX5_GET_PR(hca_vport_context, ctx, vport_state_policy);
	rep->phys_state = MLX5_GET_PR(hca_vport_context, ctx,
				      port_physical_state);
	rep->vport_state = MLX5_GET_PR(hca_vport_context, ctx, vport_state);
	rep->port_physical_state = MLX5_GET_PR(hca_vport_context, ctx,
					       port_physical_state);
	rep->port_guid = MLX5_GET64_PR(hca_vport_context, ctx, port_guid);
	rep->node_guid = MLX5_GET64_PR(hca_vport_context, ctx, node_guid);
	rep->cap_mask1 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask1);
	rep->cap_mask1_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask1_field_select);
	rep->cap_mask2 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask2);
	rep->cap_mask2_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask2_field_select);
	rep->lid = MLX5_GET_PR(hca_vport_context, ctx, lid);
	rep->init_type_reply = MLX5_GET_PR(hca_vport_context, ctx,
					   init_type_reply);
	rep->lmc = MLX5_GET_PR(hca_vport_context, ctx, lmc);
	rep->subnet_timeout = MLX5_GET_PR(hca_vport_context, ctx,
					  subnet_timeout);
	rep->sm_lid = MLX5_GET_PR(hca_vport_context, ctx, sm_lid);
	rep->sm_sl = MLX5_GET_PR(hca_vport_context, ctx, sm_sl);
	rep->qkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  qkey_violation_counter);
	rep->pkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  pkey_violation_counter);
	rep->grh_required = MLX5_GET_PR(hca_vport_context, ctx, grh_required);
	rep->sys_image_guid = MLX5_GET64_PR(hca_vport_context, ctx,
					    system_image_guid);

ex:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_hca_vport_context);

int mlx5_core_query_vport_counter(struct mlx5_core_dev *dev, u8 other_vport,
				  u8 port_num, u16 vf_num,
				  struct mlx5_vport_counters *vc)
{
	int	out_sz = MLX5_ST_SZ_BYTES(query_vport_counter_out);
	int	in_sz = MLX5_ST_SZ_BYTES(query_vport_counter_in);
	int	is_group_manager;
	void   *out;
	void   *in;
	int	err;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto ex;
	}

	MLX5_SET(query_vport_counter_in, in, opcode, MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_vport_counter_in, in, other_vport, 1);
			MLX5_SET(query_vport_counter_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}
	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_vport_counter_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out,  out_sz);
	if (err)
		goto ex;
	err = mlx5_cmd_status_to_err_v2(out);
	if (err)
		goto ex;

	vc->received_errors.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_errors.packets);
	vc->received_errors.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_errors.octets);
	vc->transmit_errors.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmit_errors.packets);
	vc->transmit_errors.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmit_errors.octets);
	vc->received_ib_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.packets);
	vc->received_ib_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_unicast.octets);
	vc->transmitted_ib_unicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.packets);
	vc->transmitted_ib_unicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_unicast.octets);
	vc->received_ib_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_multicast.packets);
	vc->received_ib_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_ib_multicast.octets);
	vc->transmitted_ib_multicast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_multicast.packets);
	vc->transmitted_ib_multicast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_ib_multicast.octets);
	vc->received_eth_broadcast.packets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_broadcast.packets);
	vc->received_eth_broadcast.octets = MLX5_GET64_PR(query_vport_counter_out, out, received_eth_broadcast.octets);
	vc->transmitted_eth_broadcast.packets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_broadcast.packets);
	vc->transmitted_eth_broadcast.octets = MLX5_GET64_PR(query_vport_counter_out, out, transmitted_eth_broadcast.octets);

ex:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_vport_counter);
