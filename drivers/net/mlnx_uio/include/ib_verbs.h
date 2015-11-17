/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems.  All rights reserved.
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

#if !defined(IB_VERBS_H)
#define IB_VERBS_H

extern struct workqueue_struct *ib_wq;

union ib_gid {
	u8	raw[16];
	struct {
		__be64	subnet_prefix;
		__be64	interface_id;
	} global;
};

enum rdma_node_type {
	/* IB values map to NodeInfo:NodeType. */
	RDMA_NODE_IB_CA 	= 1,
	RDMA_NODE_IB_SWITCH,
	RDMA_NODE_IB_ROUTER,
	RDMA_NODE_RNIC,
	RDMA_NODE_USNIC,
	RDMA_NODE_USNIC_UDP,
};

enum rdma_transport_type {
	RDMA_TRANSPORT_IB,
	RDMA_TRANSPORT_IWARP,
	RDMA_TRANSPORT_USNIC,
	RDMA_TRANSPORT_USNIC_UDP
};

enum rdma_transport_type
rdma_node_get_transport(enum rdma_node_type node_type) __attribute_const__;

enum rdma_link_layer {
	IB_LINK_LAYER_UNSPECIFIED,
	IB_LINK_LAYER_INFINIBAND,
	IB_LINK_LAYER_ETHERNET,
};

enum ib_device_cap_flags {
	IB_DEVICE_RESIZE_MAX_WR		= 1,
	IB_DEVICE_BAD_PKEY_CNTR		= (1<<1),
	IB_DEVICE_BAD_QKEY_CNTR		= (1<<2),
	IB_DEVICE_RAW_MULTI		= (1<<3),
	IB_DEVICE_AUTO_PATH_MIG		= (1<<4),
	IB_DEVICE_CHANGE_PHY_PORT	= (1<<5),
	IB_DEVICE_UD_AV_PORT_ENFORCE	= (1<<6),
	IB_DEVICE_CURR_QP_STATE_MOD	= (1<<7),
	IB_DEVICE_SHUTDOWN_PORT		= (1<<8),
	IB_DEVICE_INIT_TYPE		= (1<<9),
	IB_DEVICE_PORT_ACTIVE_EVENT	= (1<<10),
	IB_DEVICE_SYS_IMAGE_GUID	= (1<<11),
	IB_DEVICE_RC_RNR_NAK_GEN	= (1<<12),
	IB_DEVICE_SRQ_RESIZE		= (1<<13),
	IB_DEVICE_N_NOTIFY_CQ		= (1<<14),
	IB_DEVICE_LOCAL_DMA_LKEY	= (1<<15),
	IB_DEVICE_RESERVED		= (1<<16), /* old SEND_W_INV */
	IB_DEVICE_MEM_WINDOW		= (1<<17),
	/*
	 * Devices should set IB_DEVICE_UD_IP_SUM if they support
	 * insertion of UDP and TCP checksum on outgoing UD IPoIB
	 * messages and can verify the validity of checksum for
	 * incoming messages.  Setting this flag implies that the
	 * IPoIB driver may set NETIF_F_IP_CSUM for datagram mode.
	 */
	IB_DEVICE_UD_IP_CSUM		= (1<<18),
	IB_DEVICE_UD_TSO		= (1<<19),
	IB_DEVICE_XRC			= (1<<20),
	IB_DEVICE_MEM_MGT_EXTENSIONS	= (1<<21),
	IB_DEVICE_BLOCK_MULTICAST_LOOPBACK = (1<<22),
	IB_DEVICE_MEM_WINDOW_TYPE_2A	= (1<<23),
	IB_DEVICE_MEM_WINDOW_TYPE_2B	= (1<<24),
	IB_DEVICE_MANAGED_FLOW_STEERING = (1<<29)
};

enum ib_atomic_cap {
	IB_ATOMIC_NONE,
	IB_ATOMIC_HCA,
	IB_ATOMIC_GLOB
};

struct ib_device_attr {
	u64			fw_ver;
	__be64			sys_image_guid;
	u64			max_mr_size;
	u64			page_size_cap;
	u32			vendor_id;
	u32			vendor_part_id;
	u32			hw_ver;
	int			max_qp;
	int			max_qp_wr;
	int			device_cap_flags;
	int			max_sge;
	int			max_sge_rd;
	int			max_cq;
	int			max_cqe;
	int			max_mr;
	int			max_pd;
	int			max_qp_rd_atom;
	int			max_ee_rd_atom;
	int			max_res_rd_atom;
	int			max_qp_init_rd_atom;
	int			max_ee_init_rd_atom;
	enum ib_atomic_cap	atomic_cap;
	enum ib_atomic_cap	masked_atomic_cap;
	int			max_ee;
	int			max_rdd;
	int			max_mw;
	int			max_raw_ipv6_qp;
	int			max_raw_ethy_qp;
	int			max_mcast_grp;
	int			max_mcast_qp_attach;
	int			max_total_mcast_qp_attach;
	int			max_ah;
	int			max_fmr;
	int			max_map_per_fmr;
	int			max_srq;
	int			max_srq_wr;
	int			max_srq_sge;
	unsigned int		max_fast_reg_page_list_len;
	u16			max_pkeys;
	u8			local_ca_ack_delay;
};

enum ib_port_state {
	IB_PORT_NOP		= 0,
	IB_PORT_DOWN		= 1,
	IB_PORT_INIT		= 2,
	IB_PORT_ARMED		= 3,
	IB_PORT_ACTIVE		= 4,
	IB_PORT_ACTIVE_DEFER	= 5
};

enum ib_port_cap_flags {
	IB_PORT_SM				= 1 <<  1,
	IB_PORT_NOTICE_SUP			= 1 <<  2,
	IB_PORT_TRAP_SUP			= 1 <<  3,
	IB_PORT_OPT_IPD_SUP                     = 1 <<  4,
	IB_PORT_AUTO_MIGR_SUP			= 1 <<  5,
	IB_PORT_SL_MAP_SUP			= 1 <<  6,
	IB_PORT_MKEY_NVRAM			= 1 <<  7,
	IB_PORT_PKEY_NVRAM			= 1 <<  8,
	IB_PORT_LED_INFO_SUP			= 1 <<  9,
	IB_PORT_SM_DISABLED			= 1 << 10,
	IB_PORT_SYS_IMAGE_GUID_SUP		= 1 << 11,
	IB_PORT_PKEY_SW_EXT_PORT_TRAP_SUP	= 1 << 12,
	IB_PORT_EXTENDED_SPEEDS_SUP             = 1 << 14,
	IB_PORT_CM_SUP				= 1 << 16,
	IB_PORT_SNMP_TUNNEL_SUP			= 1 << 17,
	IB_PORT_REINIT_SUP			= 1 << 18,
	IB_PORT_DEVICE_MGMT_SUP			= 1 << 19,
	IB_PORT_VENDOR_CLASS_SUP		= 1 << 20,
	IB_PORT_DR_NOTICE_SUP			= 1 << 21,
	IB_PORT_CAP_MASK_NOTICE_SUP		= 1 << 22,
	IB_PORT_BOOT_MGMT_SUP			= 1 << 23,
	IB_PORT_LINK_LATENCY_SUP		= 1 << 24,
	IB_PORT_CLIENT_REG_SUP			= 1 << 25,
	IB_PORT_IP_BASED_GIDS			= 1 << 26
};

enum ib_port_width {
	IB_WIDTH_1X	= 1,
	IB_WIDTH_4X	= 2,
	IB_WIDTH_8X	= 4,
	IB_WIDTH_12X	= 8
};

static inline int ib_width_enum_to_int(enum ib_port_width width)
{
	switch (width) {
	case IB_WIDTH_1X:  return  1;
	case IB_WIDTH_4X:  return  4;
	case IB_WIDTH_8X:  return  8;
	case IB_WIDTH_12X: return 12;
	default: 	  return -1;
	}
}

enum ib_port_speed {
	IB_SPEED_SDR	= 1,
	IB_SPEED_DDR	= 2,
	IB_SPEED_QDR	= 4,
	IB_SPEED_FDR10	= 8,
	IB_SPEED_FDR	= 16,
	IB_SPEED_EDR	= 32
};

struct ib_protocol_stats {
	/* TBD... */
};

struct iw_protocol_stats {
	u64	ipInReceives;
	u64	ipInHdrErrors;
	u64	ipInTooBigErrors;
	u64	ipInNoRoutes;
	u64	ipInAddrErrors;
	u64	ipInUnknownProtos;
	u64	ipInTruncatedPkts;
	u64	ipInDiscards;
	u64	ipInDelivers;
	u64	ipOutForwDatagrams;
	u64	ipOutRequests;
	u64	ipOutDiscards;
	u64	ipOutNoRoutes;
	u64	ipReasmTimeout;
	u64	ipReasmReqds;
	u64	ipReasmOKs;
	u64	ipReasmFails;
	u64	ipFragOKs;
	u64	ipFragFails;
	u64	ipFragCreates;
	u64	ipInMcastPkts;
	u64	ipOutMcastPkts;
	u64	ipInBcastPkts;
	u64	ipOutBcastPkts;

	u64	tcpRtoAlgorithm;
	u64	tcpRtoMin;
	u64	tcpRtoMax;
	u64	tcpMaxConn;
	u64	tcpActiveOpens;
	u64	tcpPassiveOpens;
	u64	tcpAttemptFails;
	u64	tcpEstabResets;
	u64	tcpCurrEstab;
	u64	tcpInSegs;
	u64	tcpOutSegs;
	u64	tcpRetransSegs;
	u64	tcpInErrs;
	u64	tcpOutRsts;
};

union rdma_protocol_stats {
	struct ib_protocol_stats	ib;
	struct iw_protocol_stats	iw;
};

struct ib_port_attr {
	enum ib_port_state	state;
	int		max_mtu;
	int		active_mtu;
	int			gid_tbl_len;
	u32			port_cap_flags;
	u32			max_msg_sz;
	u32			bad_pkey_cntr;
	u32			qkey_viol_cntr;
	u16			pkey_tbl_len;
	u16			lid;
	u16			sm_lid;
	u8			lmc;
	u8			max_vl_num;
	u8			sm_sl;
	u8			subnet_timeout;
	u8			init_type_reply;
	u8			active_width;
	u8			active_speed;
	u8                      phys_state;
};

enum ib_device_modify_flags {
	IB_DEVICE_MODIFY_SYS_IMAGE_GUID	= 1 << 0,
	IB_DEVICE_MODIFY_NODE_DESC	= 1 << 1
};

struct ib_device_modify {
	u64	sys_image_guid;
	char	node_desc[64];
};

enum ib_port_modify_flags {
	IB_PORT_SHUTDOWN		= 1,
	IB_PORT_INIT_TYPE		= (1<<2),
	IB_PORT_RESET_QKEY_CNTR		= (1<<3)
};

struct ib_port_modify {
	u32	set_port_cap_mask;
	u32	clr_port_cap_mask;
	u8	init_type;
};

enum ib_event_type {
	IB_EVENT_CQ_ERR,
	IB_EVENT_QP_FATAL,
	IB_EVENT_QP_REQ_ERR,
	IB_EVENT_QP_ACCESS_ERR,
	IB_EVENT_COMM_EST,
	IB_EVENT_SQ_DRAINED,
	IB_EVENT_PATH_MIG,
	IB_EVENT_PATH_MIG_ERR,
	IB_EVENT_DEVICE_FATAL,
	IB_EVENT_PORT_ACTIVE,
	IB_EVENT_PORT_ERR,
	IB_EVENT_LID_CHANGE,
	IB_EVENT_PKEY_CHANGE,
	IB_EVENT_SM_CHANGE,
	IB_EVENT_SRQ_ERR,
	IB_EVENT_SRQ_LIMIT_REACHED,
	IB_EVENT_QP_LAST_WQE_REACHED,
	IB_EVENT_CLIENT_REREGISTER,
	IB_EVENT_GID_CHANGE,
};

struct ib_event {
	struct ib_device	*device;
	union {
		struct ib_cq	*cq;
		struct ib_qp	*qp;
		struct ib_srq	*srq;
		u8		port_num;
	} element;
	enum ib_event_type	event;
};

struct ib_event_handler {
	struct ib_device *device;
	void            (*handler)(struct ib_event_handler *, struct ib_event *);
	struct list_head  list;
};

#define INIT_IB_EVENT_HANDLER(_ptr, _device, _handler)		\
	do {							\
		(_ptr)->device  = _device;			\
		(_ptr)->handler = _handler;			\
		INIT_LIST_HEAD(&(_ptr)->list);			\
	} while (0)

struct ib_global_route {
	union ib_gid	dgid;
	u32		flow_label;
	u8		sgid_index;
	u8		hop_limit;
	u8		traffic_class;
};

struct ib_grh {
	__be32		version_tclass_flow;
	__be16		paylen;
	u8		next_hdr;
	u8		hop_limit;
	union ib_gid	sgid;
	union ib_gid	dgid;
};

enum {
	IB_MULTICAST_QPN = 0xffffff
};

#define IB_LID_PERMISSIVE	cpu_to_be16(0xFFFF)

enum ib_ah_flags {
	IB_AH_GRH	= 1
};

enum ib_rate {
	IB_RATE_PORT_CURRENT = 0,
	IB_RATE_2_5_GBPS = 2,
	IB_RATE_5_GBPS   = 5,
	IB_RATE_10_GBPS  = 3,
	IB_RATE_20_GBPS  = 6,
	IB_RATE_30_GBPS  = 4,
	IB_RATE_40_GBPS  = 7,
	IB_RATE_60_GBPS  = 8,
	IB_RATE_80_GBPS  = 9,
	IB_RATE_120_GBPS = 10,
	IB_RATE_14_GBPS  = 11,
	IB_RATE_56_GBPS  = 12,
	IB_RATE_112_GBPS = 13,
	IB_RATE_168_GBPS = 14,
	IB_RATE_25_GBPS  = 15,
	IB_RATE_100_GBPS = 16,
	IB_RATE_200_GBPS = 17,
	IB_RATE_300_GBPS = 18
};

/**
 * ib_rate_to_mult - Convert the IB rate enum to a multiple of the
 * base rate of 2.5 Gbit/sec.  For example, IB_RATE_5_GBPS will be
 * converted to 2, since 5 Gbit/sec is 2 * 2.5 Gbit/sec.
 * @rate: rate to convert.
 */
int ib_rate_to_mult(enum ib_rate rate) __attribute_const__;

/**
 * ib_rate_to_mbps - Convert the IB rate enum to Mbps.
 * For example, IB_RATE_2_5_GBPS will be converted to 2500.
 * @rate: rate to convert.
 */
int ib_rate_to_mbps(enum ib_rate rate) __attribute_const__;

/**
 * mult_to_ib_rate - Convert a multiple of 2.5 Gbit/sec to an IB rate
 * enum.
 * @mult: multiple to convert.
 */
enum ib_rate mult_to_ib_rate(int mult) __attribute_const__;

struct ib_ah_attr {
	struct ib_global_route	grh;
	u16			dlid;
	u8			sl;
	u8			src_path_bits;
	u8			static_rate;
	u8			ah_flags;
	u8			port_num;
	u8			dmac[ETH_ALEN];
	u16			vlan_id;
};

enum ib_wc_status {
	IB_WC_SUCCESS,
	IB_WC_LOC_LEN_ERR,
	IB_WC_LOC_QP_OP_ERR,
	IB_WC_LOC_EEC_OP_ERR,
	IB_WC_LOC_PROT_ERR,
	IB_WC_WR_FLUSH_ERR,
	IB_WC_MW_BIND_ERR,
	IB_WC_BAD_RESP_ERR,
	IB_WC_LOC_ACCESS_ERR,
	IB_WC_REM_INV_REQ_ERR,
	IB_WC_REM_ACCESS_ERR,
	IB_WC_REM_OP_ERR,
	IB_WC_RETRY_EXC_ERR,
	IB_WC_RNR_RETRY_EXC_ERR,
	IB_WC_LOC_RDD_VIOL_ERR,
	IB_WC_REM_INV_RD_REQ_ERR,
	IB_WC_REM_ABORT_ERR,
	IB_WC_INV_EECN_ERR,
	IB_WC_INV_EEC_STATE_ERR,
	IB_WC_FATAL_ERR,
	IB_WC_RESP_TIMEOUT_ERR,
	IB_WC_GENERAL_ERR
};

enum ib_wc_opcode {
	IB_WC_SEND,
	IB_WC_RDMA_WRITE,
	IB_WC_RDMA_READ,
	IB_WC_COMP_SWAP,
	IB_WC_FETCH_ADD,
	IB_WC_BIND_MW,
	IB_WC_LSO,
	IB_WC_LOCAL_INV,
	IB_WC_FAST_REG_MR,
	IB_WC_MASKED_COMP_SWAP,
	IB_WC_MASKED_FETCH_ADD,
/*
 * Set value of IB_WC_RECV so consumers can test if a completion is a
 * receive by testing (opcode & IB_WC_RECV).
 */
	IB_WC_RECV			= 1 << 7,
	IB_WC_RECV_RDMA_WITH_IMM
};

enum ib_wc_flags {
	IB_WC_GRH		= 1,
	IB_WC_WITH_IMM		= (1<<1),
	IB_WC_WITH_INVALIDATE	= (1<<2),
	IB_WC_IP_CSUM_OK	= (1<<3),
	IB_WC_WITH_SMAC		= (1<<4),
	IB_WC_WITH_VLAN		= (1<<5),
};

struct ib_wc {
	u64			wr_id;
	enum ib_wc_status	status;
	enum ib_wc_opcode	opcode;
	u32			vendor_err;
	u32			byte_len;
	struct ib_qp	       *qp;
	union {
		__be32		imm_data;
		u32		invalidate_rkey;
	} ex;
	u32			src_qp;
	int			wc_flags;
	u16			pkey_index;
	u16			slid;
	u8			sl;
	u8			dlid_path_bits;
	u8			port_num;	/* valid only for DR SMPs on switches */
	u8			smac[ETH_ALEN];
	u16			vlan_id;
};

enum ib_cq_notify_flags {
	IB_CQ_SOLICITED			= 1 << 0,
	IB_CQ_NEXT_COMP			= 1 << 1,
	IB_CQ_SOLICITED_MASK		= IB_CQ_SOLICITED | IB_CQ_NEXT_COMP,
	IB_CQ_REPORT_MISSED_EVENTS	= 1 << 2,
};

enum ib_srq_type {
	IB_SRQT_BASIC,
	IB_SRQT_XRC
};

enum ib_srq_attr_mask {
	IB_SRQ_MAX_WR	= 1 << 0,
	IB_SRQ_LIMIT	= 1 << 1,
};

struct ib_srq_attr {
	u32	max_wr;
	u32	max_sge;
	u32	srq_limit;
};

struct ib_srq_init_attr {
	void		      (*event_handler)(struct ib_event *, void *);
	void		       *srq_context;
	struct ib_srq_attr	attr;
	enum ib_srq_type	srq_type;

	union {
		struct {
			struct ib_xrcd *xrcd;
			struct ib_cq   *cq;
		} xrc;
	} ext;
};

struct ib_qp_cap {
	u32	max_send_wr;
	u32	max_recv_wr;
	u32	max_send_sge;
	u32	max_recv_sge;
	u32	max_inline_data;
};

enum ib_sig_type {
	IB_SIGNAL_ALL_WR,
	IB_SIGNAL_REQ_WR
};

enum ib_qp_type {
	/*
	 * IB_QPT_SMI and IB_QPT_GSI have to be the first two entries
	 * here (and in that order) since the MAD layer uses them as
	 * indices into a 2-entry table.
	 */
	IB_QPT_SMI,
	IB_QPT_GSI,

	IB_QPT_RC,
	IB_QPT_UC,
	IB_QPT_UD,
	IB_QPT_RAW_IPV6,
	IB_QPT_RAW_ETHERTYPE,
	IB_QPT_RAW_PACKET = 8,
	IB_QPT_XRC_INI = 9,
	IB_QPT_XRC_TGT,
	IB_QPT_MAX,
	/* Reserve a range for qp types internal to the low level driver.
	 * These qp types will not be visible at the IB core layer, so the
	 * IB_QPT_MAX usages should not be affected in the core layer
	 */
	IB_QPT_RESERVED1 = 0x1000,
	IB_QPT_RESERVED2,
	IB_QPT_RESERVED3,
	IB_QPT_RESERVED4,
	IB_QPT_RESERVED5,
	IB_QPT_RESERVED6,
	IB_QPT_RESERVED7,
	IB_QPT_RESERVED8,
	IB_QPT_RESERVED9,
	IB_QPT_RESERVED10,
};

enum ib_qp_create_flags {
	IB_QP_CREATE_IPOIB_UD_LSO		= 1 << 0,
	IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK	= 1 << 1,
	IB_QP_CREATE_NETIF_QP			= 1 << 5,
	/* reserve bits 26-31 for low level drivers' internal use */
	IB_QP_CREATE_RESERVED_START		= 1 << 26,
	IB_QP_CREATE_RESERVED_END		= 1 << 31,
};


/*
 * Note: users may not call ib_close_qp or ib_destroy_qp from the event_handler
 * callback to destroy the passed in QP.
 */

struct ib_qp_init_attr {
	void                  (*event_handler)(struct ib_event *, void *);
	void		       *qp_context;
	struct ib_cq	       *send_cq;
	struct ib_cq	       *recv_cq;
	struct ib_srq	       *srq;
	struct ib_xrcd	       *xrcd;     /* XRC TGT QPs only */
	struct ib_qp_cap	cap;
	enum ib_sig_type	sq_sig_type;
	enum ib_qp_type		qp_type;
	enum ib_qp_create_flags	create_flags;
	u8			port_num; /* special QP types only */
};

struct ib_qp_open_attr {
	void                  (*event_handler)(struct ib_event *, void *);
	void		       *qp_context;
	u32			qp_num;
	enum ib_qp_type		qp_type;
};

enum ib_rnr_timeout {
	IB_RNR_TIMER_655_36 =  0,
	IB_RNR_TIMER_000_01 =  1,
	IB_RNR_TIMER_000_02 =  2,
	IB_RNR_TIMER_000_03 =  3,
	IB_RNR_TIMER_000_04 =  4,
	IB_RNR_TIMER_000_06 =  5,
	IB_RNR_TIMER_000_08 =  6,
	IB_RNR_TIMER_000_12 =  7,
	IB_RNR_TIMER_000_16 =  8,
	IB_RNR_TIMER_000_24 =  9,
	IB_RNR_TIMER_000_32 = 10,
	IB_RNR_TIMER_000_48 = 11,
	IB_RNR_TIMER_000_64 = 12,
	IB_RNR_TIMER_000_96 = 13,
	IB_RNR_TIMER_001_28 = 14,
	IB_RNR_TIMER_001_92 = 15,
	IB_RNR_TIMER_002_56 = 16,
	IB_RNR_TIMER_003_84 = 17,
	IB_RNR_TIMER_005_12 = 18,
	IB_RNR_TIMER_007_68 = 19,
	IB_RNR_TIMER_010_24 = 20,
	IB_RNR_TIMER_015_36 = 21,
	IB_RNR_TIMER_020_48 = 22,
	IB_RNR_TIMER_030_72 = 23,
	IB_RNR_TIMER_040_96 = 24,
	IB_RNR_TIMER_061_44 = 25,
	IB_RNR_TIMER_081_92 = 26,
	IB_RNR_TIMER_122_88 = 27,
	IB_RNR_TIMER_163_84 = 28,
	IB_RNR_TIMER_245_76 = 29,
	IB_RNR_TIMER_327_68 = 30,
	IB_RNR_TIMER_491_52 = 31
};

enum ib_qp_attr_mask {
	IB_QP_STATE			= 1,
	IB_QP_CUR_STATE			= (1<<1),
	IB_QP_EN_SQD_ASYNC_NOTIFY	= (1<<2),
	IB_QP_ACCESS_FLAGS		= (1<<3),
	IB_QP_PKEY_INDEX		= (1<<4),
	IB_QP_PORT			= (1<<5),
	IB_QP_QKEY			= (1<<6),
	IB_QP_AV			= (1<<7),
	IB_QP_PATH_MTU			= (1<<8),
	IB_QP_TIMEOUT			= (1<<9),
	IB_QP_RETRY_CNT			= (1<<10),
	IB_QP_RNR_RETRY			= (1<<11),
	IB_QP_RQ_PSN			= (1<<12),
	IB_QP_MAX_QP_RD_ATOMIC		= (1<<13),
	IB_QP_ALT_PATH			= (1<<14),
	IB_QP_MIN_RNR_TIMER		= (1<<15),
	IB_QP_SQ_PSN			= (1<<16),
	IB_QP_MAX_DEST_RD_ATOMIC	= (1<<17),
	IB_QP_PATH_MIG_STATE		= (1<<18),
	IB_QP_CAP			= (1<<19),
	IB_QP_DEST_QPN			= (1<<20),
	IB_QP_SMAC			= (1<<21),
	IB_QP_ALT_SMAC			= (1<<22),
	IB_QP_VID			= (1<<23),
	IB_QP_ALT_VID			= (1<<24),
};

enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};

enum ib_mig_state {
	IB_MIG_MIGRATED,
	IB_MIG_REARM,
	IB_MIG_ARMED
};

enum ib_mw_type {
	IB_MW_TYPE_1 = 1,
	IB_MW_TYPE_2 = 2
};

struct ib_qp_attr {
	enum ib_qp_state	qp_state;
	enum ib_qp_state	cur_qp_state;
	int		path_mtu;
	enum ib_mig_state	path_mig_state;
	u32			qkey;
	u32			rq_psn;
	u32			sq_psn;
	u32			dest_qp_num;
	int			qp_access_flags;
	struct ib_qp_cap	cap;
	struct ib_ah_attr	ah_attr;
	struct ib_ah_attr	alt_ah_attr;
	u16			pkey_index;
	u16			alt_pkey_index;
	u8			en_sqd_async_notify;
	u8			sq_draining;
	u8			max_rd_atomic;
	u8			max_dest_rd_atomic;
	u8			min_rnr_timer;
	u8			port_num;
	u8			timeout;
	u8			retry_cnt;
	u8			rnr_retry;
	u8			alt_port_num;
	u8			alt_timeout;
	u8			smac[ETH_ALEN];
	u8			alt_smac[ETH_ALEN];
	u16			vlan_id;
	u16			alt_vlan_id;
};

enum ib_wr_opcode {
	IB_WR_RDMA_WRITE,
	IB_WR_RDMA_WRITE_WITH_IMM,
	IB_WR_SEND,
	IB_WR_SEND_WITH_IMM,
	IB_WR_RDMA_READ,
	IB_WR_ATOMIC_CMP_AND_SWP,
	IB_WR_ATOMIC_FETCH_AND_ADD,
	IB_WR_LSO,
	IB_WR_SEND_WITH_INV,
	IB_WR_RDMA_READ_WITH_INV,
	IB_WR_LOCAL_INV,
	IB_WR_FAST_REG_MR,
	IB_WR_MASKED_ATOMIC_CMP_AND_SWP,
	IB_WR_MASKED_ATOMIC_FETCH_AND_ADD,
	IB_WR_BIND_MW,
	/* reserve values for low level drivers' internal use.
	 * These values will not be used at all in the ib core layer.
	 */
	IB_WR_RESERVED1 = 0xf0,
	IB_WR_RESERVED2,
	IB_WR_RESERVED3,
	IB_WR_RESERVED4,
	IB_WR_RESERVED5,
	IB_WR_RESERVED6,
	IB_WR_RESERVED7,
	IB_WR_RESERVED8,
	IB_WR_RESERVED9,
	IB_WR_RESERVED10,
};

enum ib_send_flags {
	IB_SEND_FENCE		= 1,
	IB_SEND_SIGNALED	= (1<<1),
	IB_SEND_SOLICITED	= (1<<2),
	IB_SEND_INLINE		= (1<<3),
	IB_SEND_IP_CSUM		= (1<<4),

	/* reserve bits 26-31 for low level drivers' internal use */
	IB_SEND_RESERVED_START	= (1 << 26),
	IB_SEND_RESERVED_END	= (1 << 31),
};



#endif /* IB_VERBS_H */
