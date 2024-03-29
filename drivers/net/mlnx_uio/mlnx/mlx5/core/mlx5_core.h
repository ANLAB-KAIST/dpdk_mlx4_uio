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

#ifndef __MLX5_CORE_H__
#define __MLX5_CORE_H__


#define DRIVER_NAME "mlx5_core"
#define DRIVER_VERSION	"3.0-1.0.1"
#define DRIVER_RELDATE "03 Mar 2015"

extern int mlx5_core_debug_mask;

#define mlx5_core_dbg(dev, format, ...)					\
	pr_debug("%s:%s:%d:(pid %d): " format,				\
		 (dev)->priv.name, __func__, __LINE__, current->pid,	\
		 ##__VA_ARGS__)

#define mlx5_core_dbg_mask(dev, mask, format, ...)			\
do {									\
	if ((mask) & mlx5_core_debug_mask)				\
		mlx5_core_dbg(dev, format, ##__VA_ARGS__);		\
} while (0)

#define mlx5_core_err(dev, format, ...)					\
	pr_err("%s:%s:%d:(pid %d): " format,				\
	       (dev)->priv.name, __func__, __LINE__, current->pid,	\
	       ##__VA_ARGS__)

#define mlx5_core_warn(dev, format, ...)				\
	pr_warn("%s:%s:%d:(pid %d): " format,				\
		(dev)->priv.name, __func__, __LINE__, current->pid,	\
		##__VA_ARGS__)

enum {
	MLX5_CMD_DATA, /* print command payload only */
	MLX5_CMD_TIME, /* print command execution time */
};

static inline int mlx5_cmd_exec_check_status(struct mlx5_core_dev *dev, u32 *in,
					     int in_size, u32 *out,
					     int out_size)
{
	int err;

	err = mlx5_cmd_exec(dev, in, in_size, out, out_size);
	if (err)
		return err;

	return mlx5_cmd_status_to_err((struct mlx5_outbox_hdr *)out);
}

int mlx5_query_hca_caps(struct mlx5_core_dev *dev);
int mlx5_query_board_id(struct mlx5_core_dev *dev);

int mlx5_cmd_init_hca(struct mlx5_core_dev *dev);
int mlx5_cmd_teardown_hca(struct mlx5_core_dev *dev);
void mlx5_core_event(struct mlx5_core_dev *dev, enum mlx5_dev_event event,
			    unsigned long param);
void mlx5_enter_error_state(struct mlx5_core_dev *dev);
void mlx5_cmd_comp_handler(struct mlx5_core_dev *dev, unsigned long vector);
int mlx5_rename_eq(struct mlx5_core_dev *dev, int eq_ix, char *name);
int mlx5_core_sriov_configure(struct pci_dev *dev, int num_vfs);
int mlx5_core_enable_hca(struct mlx5_core_dev *dev, u16 func_id);
int mlx5_core_disable_hca(struct mlx5_core_dev *dev, u16 func_id);

void mlx5e_init(void);
void mlx5e_cleanup(void);

#endif /* __MLX5_CORE_H__ */

#include "post_kmod.h"
