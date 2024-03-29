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

#ifndef MLX5_DRIVER_H
#define MLX5_DRIVER_H



enum mlx5_res_type {
	MLX5_RES_QP,
	MLX5_RES_SRQ,
	MLX5_RES_XSRQ,
	MLX5_RES_DCT,
};

enum {
	MLX5_BOARD_ID_LEN = 64,
	MLX5_MAX_NAME_LEN = 16,
};

enum {
	/* one minute for the sake of bringup. Generally, commands must always
	 * complete and we may need to increase this timeout value
	 */
	MLX5_CMD_TIMEOUT_MSEC	= 2 * 60 * 1000,
	MLX5_CMD_WQ_MAX_NAME	= 32,
};

enum {
	CMD_OWNER_SW		= 0x0,
	CMD_OWNER_HW		= 0x1,
	CMD_STATUS_SUCCESS	= 0,
};

enum mlx5_sqp_t {
	MLX5_SQP_SMI		= 0,
	MLX5_SQP_GSI		= 1,
	MLX5_SQP_IEEE_1588	= 2,
	MLX5_SQP_SNIFFER	= 3,
	MLX5_SQP_SYNC_UMR	= 4,
};

enum {
	MLX5_MAX_PORTS	= 2,
};

enum {
	MLX5_EQ_VEC_PAGES	 = 0,
	MLX5_EQ_VEC_CMD		 = 1,
	MLX5_EQ_VEC_ASYNC	 = 2,
	MLX5_EQ_VEC_COMP_BASE,
};

enum {
	MLX5_MAX_IRQ_NAME	= 32
};

enum {
	MLX5_ATOMIC_MODE_OFF		= 16,
	MLX5_ATOMIC_MODE_NONE		= 0 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_IB_COMP	= 1 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_CX		= 2 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_8B		= 3 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_16B		= 4 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_32B		= 5 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_64B		= 6 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_128B		= 7 << MLX5_ATOMIC_MODE_OFF,
	MLX5_ATOMIC_MODE_256B		= 8 << MLX5_ATOMIC_MODE_OFF,
};

enum {
	MLX5_ATOMIC_MODE_DCT_OFF	= 20,
	MLX5_ATOMIC_MODE_DCT_NONE	= 0 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_IB_COMP	= 1 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_CX		= 2 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_8B		= 3 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_16B	= 4 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_32B	= 5 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_64B	= 6 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_128B	= 7 << MLX5_ATOMIC_MODE_DCT_OFF,
	MLX5_ATOMIC_MODE_DCT_256B	= 8 << MLX5_ATOMIC_MODE_DCT_OFF,
};

enum {
	MLX5_ATOMIC_OPS_CMP_SWAP		= 1 << 0,
	MLX5_ATOMIC_OPS_FETCH_ADD		= 1 << 1,
	MLX5_ATOMIC_OPS_MASKED_CMP_SWAP		= 1 << 2,
	MLX5_ATOMIC_OPS_MASKED_FETCH_ADD	= 1 << 3,
};

enum {
	MLX5_REG_PCAP		 = 0x5001,
	MLX5_REG_PMTU		 = 0x5003,
	MLX5_REG_PTYS		 = 0x5004,
	MLX5_REG_PAOS		 = 0x5006,
	MLX5_REG_PPCNT		 = 0x5008,
	MLX5_REG_PMAOS		 = 0x5012,
	MLX5_REG_PUDE		 = 0x5009,
	MLX5_REG_PMPE		 = 0x5010,
	MLX5_REG_PELC		 = 0x500e,
	MLX5_REG_PVLC		 = 0x500f,
	MLX5_REG_PMLP		 = 0, /* TBD */
	MLX5_REG_NODE_DESC	 = 0x6001,
	MLX5_REG_HOST_ENDIANNESS = 0x7004,
};

enum mlx5_page_fault_resume_flags {
	MLX5_PAGE_FAULT_RESUME_REQUESTOR = 1 << 0,
	MLX5_PAGE_FAULT_RESUME_WRITE	 = 1 << 1,
	MLX5_PAGE_FAULT_RESUME_RDMA	 = 1 << 2,
	MLX5_PAGE_FAULT_RESUME_ERROR	 = 1 << 7,
};

enum dbg_rsc_type {
	MLX5_DBG_RSC_QP,
	MLX5_DBG_RSC_EQ,
	MLX5_DBG_RSC_CQ,
	MLX5_DBG_RSC_DCT,
};

struct mlx5_field_desc {
	struct dentry	       *dent;
	int			i;
};

struct mlx5_rsc_debug {
	struct mlx5_core_dev   *dev;
	void		       *object;
	enum dbg_rsc_type	type;
	struct dentry	       *root;
	struct mlx5_field_desc	fields[0];
};

enum mlx5_dev_event {
	MLX5_DEV_EVENT_SYS_ERROR,
	MLX5_DEV_EVENT_PORT_UP,
	MLX5_DEV_EVENT_PORT_DOWN,
	MLX5_DEV_EVENT_PORT_INITIALIZED,
	MLX5_DEV_EVENT_LID_CHANGE,
	MLX5_DEV_EVENT_PKEY_CHANGE,
	MLX5_DEV_EVENT_GUID_CHANGE,
	MLX5_DEV_EVENT_CLIENT_REREG,
};

enum mlx5_port_status {
	MLX5_PORT_UP        = 1 << 1,
	MLX5_PORT_DOWN      = 1 << 2,
};

struct mlx5_uuar_info {
	struct mlx5_uar	       *uars;
	int			num_uars;
	int			num_low_latency_uuars;
	unsigned long	       *bitmap;
	unsigned int	       *count;
	struct mlx5_bf	       *bfs;

	/*
	 * protect uuar allocation data structs
	 */
	struct mutex		lock;
	u32			ver;
};

struct mlx5_bf {
	void __iomem	       *reg;
	void __iomem	       *regreg;
	int			buf_size;
	struct mlx5_uar	       *uar;
	unsigned long		offset;
	int			need_lock;
	/* protect blue flame buffer selection when needed
	 */
	spinlock_t		lock;

	/* serialize 64 bit writes when done as two 32 bit accesses
	 */
	spinlock_t		lock32;
	int			uuarn;
};

struct mlx5_cmd_first {
	__be32		data[4];
};

struct mlx5_cmd_msg {
	struct list_head		list;
	struct mlx5_cmd_cache_head     *ch;
	u32				len;
	struct mlx5_cmd_first		first;
	struct mlx5_cmd_mailbox	       *next;
};

struct mlx5_cmd_debug {
	struct dentry	       *dbg_root;
	struct dentry	       *dbg_in;
	struct dentry	       *dbg_out;
	struct dentry	       *dbg_outlen;
	struct dentry	       *dbg_status;
	struct dentry	       *dbg_run;
	void		       *in_msg;
	void		       *out_msg;
	u8			status;
	u16			inlen;
	u16			outlen;
};

struct mlx5_cmd_cache_head {
	/* protect block chain allocations
	 */
	spinlock_t		lock;
	struct list_head	head;
	struct kobject		kobj;
	unsigned		max_inbox_size;
	unsigned		num_ent;
	unsigned		miss;
	unsigned		total_commands;
	unsigned		free;
	struct mlx5_core_dev   *dev;
};

enum {
	MLX5_NUM_COMMAND_CACHES = 5,
};

struct cmd_msg_cache {
	struct kobject		       *ko;
	struct mlx5_cmd_cache_head	ch[MLX5_NUM_COMMAND_CACHES];
	atomic_t			real_miss;
};

struct mlx5_cmd_stats {
	u64		sum;
	u64		n;
	struct dentry  *root;
	struct dentry  *avg;
	struct dentry  *count;
	/* protect command average calculations */
	spinlock_t	lock;
};

struct mlx5_cmd {
	void	       *cmd_alloc_buf;
	dma_addr_t	alloc_dma;
	int		alloc_size;
	void	       *cmd_buf;
	dma_addr_t	dma;
	u16		cmdif_rev;
	u8		log_sz;
	u8		log_stride;
	int		max_reg_cmds;
	int		events;
	u32 __iomem    *vector;

	/* protect command queue allocations
	 */
	spinlock_t	alloc_lock;

	/* protect token allocations
	 */
	spinlock_t	token_lock;
	u8		token;
	unsigned long	bitmask;
	char		wq_name[MLX5_CMD_WQ_MAX_NAME];
	struct workqueue_struct *wq;
	struct semaphore sem;
	struct semaphore pages_sem;
	int	mode;
	struct mlx5_cmd_work_ent *ent_arr[MLX5_MAX_COMMANDS];
	struct pci_pool *pool;
	struct mlx5_cmd_debug dbg;
	struct cmd_msg_cache cache;
	int checksum_disabled;
	struct mlx5_cmd_stats stats[MLX5_CMD_OP_MAX];
};

struct mlx5_port_caps {
	int	gid_table_len;
	int	pkey_table_len;
	u8	ext_port_cap;
};

struct mlx5_cmd_mailbox {
	void	       *buf;
	dma_addr_t	dma;
	struct mlx5_cmd_mailbox *next;
};

struct mlx5_buf_list {
	void		       *buf;
	dma_addr_t		map;
};

struct mlx5_buf {
	struct mlx5_buf_list	direct;
	struct mlx5_buf_list   *page_list;
	int			nbufs;
	int			npages;
	int			size;
	u8			page_shift;
};

struct mlx5_eq {
	struct mlx5_core_dev   *dev;
	__be32 __iomem	       *doorbell;
	u32			cons_index;
	struct mlx5_buf		buf;
	int			size;
	u8			irqn;
	u8			eqn;
	int			nent;
	struct list_head	list;
	int			index;
	struct mlx5_rsc_debug	*dbg;
	cpumask_var_t		affinity_mask;
};

struct mlx5_core_psv {
	u32	psv_idx;
	struct psv_layout {
		u32	pd;
		u16	syndrome;
		u16	reserved;
		u16	bg;
		u16	app_tag;
		u32	ref_tag;
	} psv;
};

struct mlx5_core_sig_ctx {
	struct mlx5_core_psv	psv_memory;
	struct mlx5_core_psv	psv_wire;
	struct ib_sig_err       err_item;
	bool			sig_status_checked;
	bool			sig_err_exists;
	u32			sigerr_count;
};

struct mlx5_core_mr {
	u64			iova;
	u64			size;
	u32			key;
	u32			pd;
};

struct mlx5_core_rsc_common {
	enum mlx5_res_type	res;
	atomic_t		refcount;
	struct completion	free;
};

struct mlx5_core_srq {
	struct mlx5_core_rsc_common	common; /* must be first */
	u32				srqn;
	int				max;
	int				max_gs;
	int				max_avail_gather;
	int				wqe_shift;
	void				(*event)(struct mlx5_core_srq *, enum mlx5_event);

	atomic_t			refcount;
	struct completion		free;
};

struct mlx5_eq_table {
	void __iomem	       *update_ci;
	void __iomem	       *update_arm_ci;
	struct list_head	comp_eqs_list;
	struct mlx5_eq		pages_eq;
	struct mlx5_eq		async_eq;
	struct mlx5_eq		cmd_eq;
	cpumask_var_t		*irq_masks;
	int			num_comp_vectors;
	/* protect EQs list
	 */
	spinlock_t		lock;
};

struct mlx5_uar {
	u32			index;
	struct list_head	bf_list;
	unsigned		free_bf_bmap;
	void __iomem	       *bf_map;
	void __iomem	       *map;
};


struct mlx5_core_health {
	struct health_buffer __iomem   *health;
	__be32 __iomem		       *health_counter;
	struct timer_list		timer;
	struct list_head		list;
	u32				prev;
	int				miss_counter;
};

struct mlx5_cq_table {
	/* protect radix tree
	 */
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct mlx5_qp_table {
	/* protect radix tree
	 */
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct mlx5_srq_table {
	/* protect radix tree
	 */
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct mlx5_mr_table {
	/* protect radix tree
	 */
	spinlock_t              lock;
	struct radix_tree_root	tree;
};

struct mlx5_vf_context {
	u32	state_mask;
	int	enabled;
};

struct mlx5_sriov_vf {
	struct mlx5_core_dev   *dev;
	struct kobject		kobj;
	int			vf;
};

struct mlx5_core_sriov {
	struct mlx5_vf_context	*vfs_ctx;
	struct kobject		*config;
	struct kobject		node_guid_kobj;
	struct mlx5_sriov_vf	*vfs;
	int			num_vfs;
	int			vf_partial_init;
};

struct mlx5_irq_info {
	cpumask_var_t mask;
	char name[MLX5_MAX_IRQ_NAME];
};

struct mlx5_priv {
	char			name[MLX5_MAX_NAME_LEN];
	struct mlx5_eq_table	eq_table;
	struct msix_entry	*msix_arr;
	struct mlx5_irq_info	*irq_info;
	struct mlx5_uuar_info	uuari;
	MLX5_DECLARE_DOORBELL_LOCK(cq_uar_lock);

	struct io_mapping	*bf_mapping;

	/* pages stuff */
	struct workqueue_struct *pg_wq;
	struct rb_root		page_root;
	int			fw_pages;
	atomic_t		reg_pages;
	struct list_head	free_list;

	struct mlx5_core_health health;

	struct mlx5_srq_table	srq_table;

	/* start: qp staff */
	struct mlx5_qp_table	qp_table;
	struct dentry	       *qp_debugfs;
	struct dentry	       *eq_debugfs;
	struct dentry	       *cq_debugfs;
	struct dentry	       *cmdif_debugfs;
	/* end: qp staff */

	/* start: dct stuff */
	struct dentry	       *dct_debugfs;
	/* end: dct stuff */

	/* start: cq staff */
	struct mlx5_cq_table	cq_table;
	/* end: cq staff */

	/* start: mr staff */
	struct mlx5_mr_table	mr_table;
	/* end: mr staff */

	/* start: alloc staff */
	/* protect buffer alocation according to numa node */
	struct mutex            alloc_mutex;
	int                     numa_node;

	struct mutex            pgdir_mutex;
	struct list_head        pgdir_list;
	/* end: alloc staff */
	struct dentry	       *dbg_root;

	/* protect mkey key part */
	spinlock_t		mkey_lock;
	u8			mkey_key;

	struct list_head        dev_list;
	struct list_head        ctx_list;
	spinlock_t              ctx_lock;

	struct mlx5_core_sriov	sriov;
	unsigned long		pci_dev_data;
};

enum mlx5_device_state {
	MLX5_DEVICE_STATE_UP,
	MLX5_DEVICE_STATE_INTERNAL_ERROR,
};

enum mlx5_interface_state {
	MLX5_INTERFACE_STATE_DOWN,
	MLX5_INTERFACE_STATE_UP,
};

enum mlx5_pci_status {
	MLX5_PCI_STATUS_DISABLED,
	MLX5_PCI_STATUS_ENABLED,
};

struct mlx5_special_contexts {
	int resd_lkey;
};

struct mlx5_core_dev {
	struct pci_dev	       *pdev;
	struct mutex		pci_status_mutex;
	enum mlx5_pci_status	pci_status;
	u8			rev_id;
	char			board_id[MLX5_BOARD_ID_LEN];
	struct mlx5_cmd		cmd;
	struct mlx5_port_caps	port_caps[MLX5_MAX_PORTS];
	u32 hca_caps_cur[MLX5_CAP_NUM][MLX5_UN_SZ_DW(hca_cap_union)];
	u32 hca_caps_max[MLX5_CAP_NUM][MLX5_UN_SZ_DW(hca_cap_union)];
	phys_addr_t		iseg_base;
	struct mlx5_init_seg __iomem *iseg;
	enum mlx5_device_state	state;
	struct mutex		intf_state_mutex;
	enum mlx5_interface_state interface_state;
	void			(*event) (struct mlx5_core_dev *dev,
					  enum mlx5_dev_event event,
					  unsigned long param);
	struct mlx5_priv	priv;
	struct mlx5_profile	*profile;
	atomic_t		num_qps;
	u64			aysnc_events_mask;
	u32			supported_issi_mask;
	u32			issi;
	struct mlx5_special_contexts special_contexts;
};

struct mlx5_db {
	__be32			*db;
	union {
		struct mlx5_db_pgdir		*pgdir;
		struct mlx5_ib_user_db_page	*user_page;
	}			u;
	dma_addr_t		dma;
	int			index;
};

enum {
	MLX5_DB_PER_PAGE = PAGE_SIZE / L1_CACHE_BYTES,
};

struct mlx5_core_dct {
	struct mlx5_core_rsc_common	common; /* must be first */
	void (*event)(struct mlx5_core_dct *, enum mlx5_event);
	int			dctn;
	struct completion	drained;
	struct mlx5_rsc_debug	*dbg;
	int			pid;
};

enum {
	MLX5_COMP_EQ_SIZE = 1024,
};

enum {
	MLX5_PTYS_IB = 1 << 0,
	MLX5_PTYS_EN = 1 << 2,
};

struct mlx5_db_pgdir {
	struct list_head	list;
	DECLARE_BITMAP(bitmap, MLX5_DB_PER_PAGE);
	__be32		       *db_page;
	dma_addr_t		db_dma;
};

typedef void (*mlx5_cmd_cbk_t)(int status, void *context);

struct mlx5_cmd_work_ent {
	struct mlx5_cmd_msg    *in;
	struct mlx5_cmd_msg    *out;
	void		       *uout;
	int			uout_size;
	mlx5_cmd_cbk_t		callback;
	void		       *context;
	int			idx;
	struct completion	done;
	struct mlx5_cmd        *cmd;
	struct work_struct	work;
	struct mlx5_cmd_layout *lay;
	int			ret;
	int			page_queue;
	u8			status;
	u8			token;
#ifdef HAVE_KTIME_GET_NS
	u64			ts1;
	u64			ts2;
#else
	struct timespec ts1;
	struct timespec ts2;
#endif
	u16			op;
};

struct mlx5_pas {
	u64	pa;
	u8	log_sz;
};

enum port_state_policy {
	MLX5_AAA_000
};

enum phy_port_state {
	MLX5_AAA_111
};

struct mlx5_hca_vport_context {
	u32			field_select;
	bool			sm_virt_aware;
	bool			has_smi;
	bool			has_raw;
	enum port_state_policy	policy;
	enum phy_port_state	phys_state;
	enum ib_port_state	vport_state;
	u8			port_physical_state;
	u64			sys_image_guid;
	u64			port_guid;
	u64			node_guid;
	u32			cap_mask1;
	u32			cap_mask1_perm;
	u32			cap_mask2;
	u32			cap_mask2_perm;
	u16			lid;
	u8			init_type_reply; /* bitmask: see ib spec 14.2.5.6 InitTypeReply */
	u8			lmc;
	u8			subnet_timeout;
	u16			sm_lid;
	u8			sm_sl;
	u16			qkey_violation_counter;
	u16			pkey_violation_counter;
	bool			grh_required;
};

struct mlx5_net_counters {
	u64	packets;
	u64	octets;
};

struct mlx5_ptys_reg {
	u8	local_port;
	u8	proto_mask;
	u32	eth_proto_cap;
	u16	ib_link_width_cap;
	u16	ib_proto_cap;
	u32	eth_proto_admin;
	u16	ib_link_width_admin;
	u16	ib_proto_admin;
	u32	eth_proto_oper;
	u16	ib_link_width_oper;
	u16	ib_proto_oper;
	u32	eth_proto_lp_advertise;
};

struct mlx5_pvlc_reg {
	u8	local_port;
	u8	vl_hw_cap;
	u8	vl_admin;
	u8	vl_operational;
};

struct mlx5_pmtu_reg {
	u8	local_port;
	u16	max_mtu;
	u16	admin_mtu;
	u16	oper_mtu;
};

struct mlx5_vport_counters {
	struct mlx5_net_counters	received_errors;
	struct mlx5_net_counters	transmit_errors;
	struct mlx5_net_counters	received_ib_unicast;
	struct mlx5_net_counters	transmitted_ib_unicast;
	struct mlx5_net_counters	received_ib_multicast;
	struct mlx5_net_counters	transmitted_ib_multicast;
	struct mlx5_net_counters	received_eth_broadcast;
	struct mlx5_net_counters	transmitted_eth_broadcast;
};

static inline void *mlx5_buf_offset(struct mlx5_buf *buf, int offset)
{
	if (likely(BITS_PER_LONG == 64 || buf->nbufs == 1))
		return buf->direct.buf + offset;
	else
		return buf->page_list[offset >> PAGE_SHIFT].buf +
			(offset & (PAGE_SIZE - 1));
}

extern struct workqueue_struct *mlx5_core_wq;

#define STRUCT_FIELD(header, field) \
	.struct_offset_bytes = offsetof(struct ib_unpacked_ ## header, field),      \
	.struct_size_bytes   = sizeof((struct ib_unpacked_ ## header *)0)->field

static inline struct mlx5_core_dev *pci2mlx5_core_dev(struct pci_dev *pdev)
{
	return pci_get_drvdata(pdev);
}

extern struct dentry *mlx5_debugfs_root;

static inline u16 fw_rev_maj(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->fw_rev) & 0xffff;
}

static inline u16 fw_rev_min(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->fw_rev) >> 16;
}

static inline u16 fw_rev_sub(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->cmdif_rev_fw_sub) & 0xffff;
}

static inline u16 cmdif_rev(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->cmdif_rev_fw_sub) >> 16;
}

static inline void *mlx5_vzalloc(unsigned long size)
{
	void *rtn;

	rtn = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vzalloc(size);
	return rtn;
}

static inline void *mlx5_vmalloc(unsigned long size)
{
	void *rtn;

	rtn = kmalloc(size, GFP_KERNEL | __GFP_NOWARN);
	if (!rtn)
		rtn = vmalloc(size);
	return rtn;
}

int mlx5_cmd_init(struct mlx5_core_dev *dev);
void mlx5_cmd_cleanup(struct mlx5_core_dev *dev);
void mlx5_cmd_use_events(struct mlx5_core_dev *dev);
void mlx5_cmd_use_polling(struct mlx5_core_dev *dev);
int mlx5_cmd_status_to_err(struct mlx5_outbox_hdr *hdr);
int mlx5_cmd_status_to_err_v2(void *ptr);
int mlx5_core_query_special_contexts(struct mlx5_core_dev *dev);
int mlx5_core_get_caps(struct mlx5_core_dev *dev, enum mlx5_cap_type cap_type,
		       enum mlx5_cap_mode cap_mode);
int mlx5_cmd_exec(struct mlx5_core_dev *dev, void *in, int in_size, void *out,
		  int out_size);
int mlx5_cmd_exec_cb(struct mlx5_core_dev *dev, void *in, int in_size,
		     void *out, int out_size, mlx5_cmd_cbk_t callback,
		     void *context);
int mlx5_cmd_alloc_uar(struct mlx5_core_dev *dev, u32 *uarn);
int mlx5_cmd_free_uar(struct mlx5_core_dev *dev, u32 uarn);
int mlx5_alloc_uuars(struct mlx5_core_dev *dev, struct mlx5_uuar_info *uuari);
int mlx5_free_uuars(struct mlx5_core_dev *dev, struct mlx5_uuar_info *uuari);
int mlx5_alloc_map_uar(struct mlx5_core_dev *mdev, struct mlx5_uar *uar);
void mlx5_unmap_free_uar(struct mlx5_core_dev *mdev, struct mlx5_uar *uar);
void mlx5_health_cleanup(void);
void  __init mlx5_health_init(void);
void mlx5_start_health_poll(struct mlx5_core_dev *dev);
void mlx5_stop_health_poll(struct mlx5_core_dev *dev);
int mlx5_buf_alloc_node(struct mlx5_core_dev *dev, int size, int max_direct,
			struct mlx5_buf *buf, int node);
int mlx5_buf_alloc(struct mlx5_core_dev *dev, int size, int max_direct,
		   struct mlx5_buf *buf);
void mlx5_buf_free(struct mlx5_core_dev *dev, struct mlx5_buf *buf);
struct mlx5_cmd_mailbox *mlx5_alloc_cmd_mailbox_chain(struct mlx5_core_dev *dev,
						      gfp_t flags, int npages);
void mlx5_free_cmd_mailbox_chain(struct mlx5_core_dev *dev,
				 struct mlx5_cmd_mailbox *head);
int mlx5_core_create_srq(struct mlx5_core_dev *dev, struct mlx5_core_srq *srq,
			 struct mlx5_create_srq_mbox_in *in, int inlen,
			 int is_xrc);
int mlx5_core_destroy_srq(struct mlx5_core_dev *dev, struct mlx5_core_srq *srq);
int mlx5_core_query_srq(struct mlx5_core_dev *dev, struct mlx5_core_srq *srq,
			struct mlx5_query_srq_mbox_out *out);
int mlx5_core_arm_srq(struct mlx5_core_dev *dev, struct mlx5_core_srq *srq,
		      u16 lwm, int is_srq);
void mlx5_init_mr_table(struct mlx5_core_dev *dev);
void mlx5_cleanup_mr_table(struct mlx5_core_dev *dev);
int mlx5_core_create_mkey(struct mlx5_core_dev *dev, struct mlx5_core_mr *mr,
			  struct mlx5_create_mkey_mbox_in *in, int inlen,
			  mlx5_cmd_cbk_t callback, void *context,
			  struct mlx5_create_mkey_mbox_out *out);
int mlx5_core_destroy_mkey(struct mlx5_core_dev *dev, struct mlx5_core_mr *mr);
int mlx5_core_query_mkey(struct mlx5_core_dev *dev, struct mlx5_core_mr *mr,
			 struct mlx5_query_mkey_mbox_out *out, int outlen);
int mlx5_core_dump_fill_mkey(struct mlx5_core_dev *dev, struct mlx5_core_mr *mr,
			     u32 *mkey);
int mlx5_core_alloc_pd(struct mlx5_core_dev *dev, u32 *pdn);
int mlx5_core_dealloc_pd(struct mlx5_core_dev *dev, u32 pdn);
int mlx5_core_mad_ifc(struct mlx5_core_dev *dev, void *inb, void *outb,
		      u16 opmod, u8 port);
void mlx5_pagealloc_init(struct mlx5_core_dev *dev);
void mlx5_pagealloc_cleanup(struct mlx5_core_dev *dev);
int mlx5_pagealloc_start(struct mlx5_core_dev *dev);
void mlx5_pagealloc_stop(struct mlx5_core_dev *dev);
void mlx5_core_req_pages_handler(struct mlx5_core_dev *dev, u16 func_id,
				 s32 npages);
int mlx5_update_guids(struct mlx5_core_dev *dev);
int mlx5_satisfy_startup_pages(struct mlx5_core_dev *dev, int boot);
int mlx5_reclaim_startup_pages(struct mlx5_core_dev *dev);
void mlx5_register_debugfs(void);
void mlx5_unregister_debugfs(void);
int mlx5_eq_init(struct mlx5_core_dev *dev);
void mlx5_eq_cleanup(struct mlx5_core_dev *dev);
void mlx5_fill_page_array(struct mlx5_buf *buf, __be64 *pas);
void mlx5_cq_completion(struct mlx5_core_dev *dev, u32 cqn);
int mlx5_rsc_event(struct mlx5_core_dev *dev, u32 rsn, int event_type);
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
void mlx5_eq_pagefault(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe);
#endif
void mlx5_srq_event(struct mlx5_core_dev *dev, u32 srqn, int event_type);
struct mlx5_core_srq *mlx5_core_get_srq(struct mlx5_core_dev *dev, u32 srqn);
void mlx5_cmd_comp_handler(struct mlx5_core_dev *dev, unsigned long vector);
void mlx5_cq_event(struct mlx5_core_dev *dev, u32 cqn, int event_type);
int mlx5_create_map_eq(struct mlx5_core_dev *dev, struct mlx5_eq *eq, u8 vecidx,
		       int nent, u64 mask, const char *name, struct mlx5_uar *uar);
int mlx5_destroy_unmap_eq(struct mlx5_core_dev *dev, struct mlx5_eq *eq);
int mlx5_start_eqs(struct mlx5_core_dev *dev);
int mlx5_stop_eqs(struct mlx5_core_dev *dev);
int mlx5_vector2eqn(struct mlx5_core_dev *dev, int vector, int *eqn, int *irqn);
int mlx5_core_attach_mcg(struct mlx5_core_dev *dev, union ib_gid *mgid, u32 qpn);
int mlx5_core_detach_mcg(struct mlx5_core_dev *dev, union ib_gid *mgid, u32 qpn);

int mlx5_qp_debugfs_init(struct mlx5_core_dev *dev);
void mlx5_qp_debugfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_dct_debugfs_init(struct mlx5_core_dev *dev);
void mlx5_dct_debugfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_core_access_reg(struct mlx5_core_dev *dev, void *data_in,
			 int size_in, void *data_out, int size_out,
			 u16 reg_num, int arg, int write);
int mlx5_set_port_caps(struct mlx5_core_dev *dev, u8 port_num,
		       u32 set, u32 clear, u32 cur);
int mlx5_query_port_ptys(struct mlx5_core_dev *dev, u32 *ptys,
			 int ptys_size, int proto_mask);
int mlx5_query_port_proto_cap(struct mlx5_core_dev *dev,
			      u32 *proto_cap, int proto_mask);
int mlx5_core_access_ptys(struct mlx5_core_dev *dev, struct mlx5_ptys_reg *ptys, int write);
int mlx5_core_access_pvlc(struct mlx5_core_dev *dev, struct mlx5_pvlc_reg *pvlc, int write);
int mlx5_core_access_pmtu(struct mlx5_core_dev *dev, struct mlx5_pmtu_reg *pmtu, int write);
int mlx5_query_port_proto_admin(struct mlx5_core_dev *dev,
				u32 *proto_admin, int proto_mask);
int mlx5_set_port_proto(struct mlx5_core_dev *dev, u32 proto_admin,
			int proto_mask);
int mlx5_set_port_status(struct mlx5_core_dev *dev,
			 enum mlx5_port_status status);
int mlx5_query_port_status(struct mlx5_core_dev *dev, u8 *status);
int mlx5_set_port_mtu(struct mlx5_core_dev *dev, int mtu);
void mlx5_query_port_max_mtu(struct mlx5_core_dev *dev, int *max_mtu);
void mlx5_query_port_oper_mtu(struct mlx5_core_dev *dev, int *oper_mtu);

int mlx5_debug_eq_add(struct mlx5_core_dev *dev, struct mlx5_eq *eq);
void mlx5_debug_eq_remove(struct mlx5_core_dev *dev, struct mlx5_eq *eq);
int mlx5_core_eq_query(struct mlx5_core_dev *dev, struct mlx5_eq *eq,
		       struct mlx5_query_eq_mbox_out *out, int outlen);
int mlx5_eq_debugfs_init(struct mlx5_core_dev *dev);
void mlx5_eq_debugfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_cq_debugfs_init(struct mlx5_core_dev *dev);
void mlx5_cq_debugfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_db_alloc(struct mlx5_core_dev *dev, struct mlx5_db *db);
int mlx5_db_alloc_node(struct mlx5_core_dev *dev, struct mlx5_db *db,
		       int node);
void mlx5_db_free(struct mlx5_core_dev *dev, struct mlx5_db *db);

const char *mlx5_command_str(int command);
int mlx5_cmdif_debugfs_init(struct mlx5_core_dev *dev);
void mlx5_cmdif_debugfs_cleanup(struct mlx5_core_dev *dev);
int mlx5_core_create_psv(struct mlx5_core_dev *dev, u32 pdn,
			 int npsvs, u32 *sig_index);
int mlx5_core_destroy_psv(struct mlx5_core_dev *dev, int psv_num);
void mlx5_core_put_rsc(struct mlx5_core_rsc_common *common);
int mlx5_query_odp_caps(struct mlx5_core_dev *dev,
			struct mlx5_odp_caps *odp_caps);
int mlx5_core_modify_hca_vport_context(struct mlx5_core_dev *dev,
				       u8 other_vport, u8 port_num,
				       u16 vf_num,
				       struct mlx5_hca_vport_context *req);
int mlx5_core_check_enable_vf_hca(struct mlx5_core_dev *dev, u32 field_select, u8 vport_num);
int mlx5_core_query_hca_vport_context(struct mlx5_core_dev *dev,
				      u8 other_vport, u8 port_num,
				      u16 vf_num,
				      struct mlx5_hca_vport_context *rep);
int mlx5_core_query_gids(struct mlx5_core_dev *dev, u8 other_vport,
			 u8 port_num, u16  vf_num, u16 gid_index,
			 union ib_gid *gid);
int mlx5_core_query_pkeys(struct mlx5_core_dev *dev, u8 other_vport,
			  u8 port_num, u16 vf_num, u16 pkey_index,
			  u16 *pkey);
int mlx5_core_query_vport_counter(struct mlx5_core_dev *dev, u8 other_vport,
				  u8 port_num, u16 vf_num,
				  struct mlx5_vport_counters *vc);
int mlx5_sriov_init(struct mlx5_core_dev *dev);
int mlx5_sriov_cleanup(struct mlx5_core_dev *dev);

static inline u32 mlx5_mkey_to_idx(u32 mkey)
{
	return mkey >> 8;
}

static inline int fw_initializing(struct mlx5_core_dev *dev)
{
	return ioread32be(&dev->iseg->initializing) >> 31;
}

static inline u32 mlx5_idx_to_mkey(u32 mkey_idx)
{
	return mkey_idx << 8;
}

static inline u8 mlx5_mkey_variant(u32 mkey)
{
	return mkey & 0xff;
}

enum {
	MLX5_PROF_MASK_QP_SIZE		= (u64)1 << 0,
	MLX5_PROF_MASK_MR_CACHE		= (u64)1 << 1,
	MLX5_PROF_MASK_DCT		= (u64)1 << 2,
};

enum {
	MAX_MR_CACHE_ENTRIES    = 15,
};

enum {
	MLX5_INTERFACE_PROTOCOL_IB  = 0,
	MLX5_INTERFACE_PROTOCOL_ETH = 1,
};

struct mlx5_interface {
	void *			(*add)(struct mlx5_core_dev *dev);
	void			(*remove)(struct mlx5_core_dev *dev, void *context);
	void			(*event)(struct mlx5_core_dev *dev, void *context,
					 enum mlx5_dev_event event, unsigned long param);
	void *                  (*get_dev)(void *context);
	int			protocol;
	struct list_head	list;
};

void *mlx5_get_protocol_dev(struct mlx5_core_dev *mdev, int protocol);
int mlx5_register_interface(struct mlx5_interface *intf);
void mlx5_unregister_interface(struct mlx5_interface *intf);
int mlx5_vport_enable_roce(struct mlx5_core_dev *mdev);
int mlx5_core_query_vendor_id(struct mlx5_core_dev *mdev, u32 *vendor_id);

struct mlx5_profile {
	u64	mask;
	u8	log_max_qp;
	int	dct_enable;
	struct {
		int	size;
		int	limit;
	} mr_cache[MAX_MR_CACHE_ENTRIES];
};

static inline int mlx5_get_out_cmd_status(void *ptr)
{
	return *(u8 *)ptr;
}

enum {
	MLX5_PCI_DEV_IS_VF		= 1 << 0,
};

static inline int mlx5_core_is_pf(struct mlx5_core_dev *dev)
{
	return !(dev->priv.pci_dev_data & MLX5_PCI_DEV_IS_VF);
}

static inline int mlx5_get_gid_table_len(u16 param)
{
	if (param > 4) {
		pr_warn("gid table length is zero\n");
		return 0;
	}

	return 8 * (1 << param);
}

static inline u16 mlx5_to_sw_pkey_sz(int pkey_sz)
{
	if (pkey_sz > MLX5_MAX_LOG_PKEY_TABLE)
		return 0;

	return MLX5_MIN_PKEY_TABLE_SIZE << pkey_sz;
}

enum {
	MLX5_SRIOV_UNLOAD_MAGIC = 0x2cf58291
};

#endif /* MLX5_DRIVER_H */

#include "post_kmod.h"
