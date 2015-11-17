#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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

static inline int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq,
				     struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct sk_buff *skb;
	dma_addr_t dma_addr;

	skb = netdev_alloc_skb(rq->netdev, rq->wqe_sz);
	if (unlikely(!skb))
		return -ENOMEM;

	dma_addr = dma_map_single(rq->pdev,
				  /* hw start padding */
				  skb->data,
				  /* hw end padding */
				  rq->wqe_sz,
				  DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(rq->pdev, dma_addr)))
		goto err_free_skb;

	skb_reserve(skb, MLX5E_NET_IP_ALIGN);

	*((dma_addr_t *)skb->cb) = dma_addr;
	wqe->data.addr = cpu_to_be64(dma_addr + MLX5E_NET_IP_ALIGN);

	rq->skb[ix] = skb;

	return 0;

err_free_skb:
	dev_kfree_skb(skb);

	return -ENOMEM;
}

bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5_wq_ll *wq = &rq->wq;

	if (unlikely(!test_bit(MLX5E_RQ_STATE_POST_WQES_ENABLE, &rq->state)))
		return false;

	while (!mlx5_wq_ll_is_full(wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(wq, wq->head);

		if (unlikely(mlx5e_alloc_rx_wqe(rq, wqe, wq->head)))
			break;

		mlx5_wq_ll_push(wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
	wmb();

	mlx5_wq_ll_update_db_record(wq);

	return !mlx5_wq_ll_is_full(wq);
}

static void mlx5e_lro_update_hdr(struct sk_buff *skb, struct mlx5_cqe64 *cqe)
{
	/* TODO: consider vlans, ip options, ... */
	struct ethhdr	*eth	= (struct ethhdr *)(skb->data);
	struct iphdr	*ipv4	= (struct iphdr *)(skb->data + ETH_HLEN);
	struct ipv6hdr	*ipv6	= (struct ipv6hdr *)(skb->data + ETH_HLEN);
	struct tcphdr	*tcp;

	u8 l4_hdr_type = get_cqe_l4_hdr_type(cqe);
	int tcp_ack = ((CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA  == l4_hdr_type) ||
		       (CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA == l4_hdr_type));

	/* TODO: consider vlan */
	u16 tot_len = be32_to_cpu(cqe->byte_cnt) - ETH_HLEN;

	if (eth->h_proto == htons(ETH_P_IP)) {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct iphdr));
		ipv6 = NULL;
	} else {
		tcp = (struct tcphdr *)(skb->data + ETH_HLEN +
					sizeof(struct ipv6hdr));
		ipv4 = NULL;
	}

	/* TODO: handle timestamp */

	if (get_cqe_lro_tcppsh(cqe))
		tcp->psh                = 1;

	if (tcp_ack) {
		tcp->ack                = 1;
		tcp->ack_seq            = cqe->lro_ack_seq_num;
		tcp->window             = cqe->lro_tcp_win;
	}

	if (ipv4) {
		ipv4->ttl               = cqe->lro_min_ttl;
		ipv4->tot_len           = cpu_to_be16(tot_len);
		ipv4->check             = 0;
		ipv4->check             = ip_fast_csum((unsigned char *)ipv4,
						       ipv4->ihl);
	} else {
		ipv6->hop_limit         = cqe->lro_min_ttl;
		ipv6->payload_len       = cpu_to_be16(tot_len -
						      sizeof(struct ipv6hdr));
	}
	/* TODO: handle tcp checksum */
}

#ifdef HAVE_NETIF_F_RXHASH
static inline void mlx5e_skb_set_hash(struct mlx5_cqe64 *cqe,
				      struct sk_buff *skb)
{
#ifdef HAVE_SKB_SET_HASH
	u8 cht = cqe->rss_hash_type;
	int ht = (cht & CQE_RSS_HTYPE_L4) ? PKT_HASH_TYPE_L4 :
		 (cht & CQE_RSS_HTYPE_IP) ? PKT_HASH_TYPE_L3 :
					    PKT_HASH_TYPE_NONE;
	skb_set_hash(skb, be32_to_cpu(cqe->rss_hash_result), ht);
#else
	skb->rxhash = be32_to_cpu(cqe->rss_hash_result);
#endif
}
#endif

static inline void mlx5e_build_rx_skb(struct mlx5_cqe64 *cqe,
				      struct mlx5e_rq *rq,
				      struct sk_buff *skb)
{
	struct net_device *netdev = rq->netdev;
	u32 cqe_bcnt = be32_to_cpu(cqe->byte_cnt);
	int lro_num_seg;

	skb_put(skb, cqe_bcnt);

	lro_num_seg = be32_to_cpu(cqe->srqn) >> 24;
	if (lro_num_seg > 1) {
		mlx5e_lro_update_hdr(skb, cqe);
		skb_shinfo(skb)->gso_size = MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ;
		rq->stats.lro_packets++;
		rq->stats.lro_bytes += cqe_bcnt;
	}

	if (likely(netdev->features & NETIF_F_RXCSUM) &&
	    (cqe->hds_ip_ext & CQE_L2_OK) &&
	    (cqe->hds_ip_ext & CQE_L3_OK) &&
	    (cqe->hds_ip_ext & CQE_L4_OK)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		skb->ip_summed = CHECKSUM_NONE;
		rq->stats.csum_none++;
	}

	skb->protocol = eth_type_trans(skb, netdev);

	skb_record_rx_queue(skb, rq->ix);

#ifdef HAVE_NETIF_F_RXHASH
	if (likely(netdev->features & NETIF_F_RXHASH))
		mlx5e_skb_set_hash(cqe, skb);
#endif

	if (cqe_has_vlan(cqe))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
		__vlan_hwaccel_put_tag(skb, be16_to_cpu(cqe->vlan_info));
#else
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       be16_to_cpu(cqe->vlan_info));
#endif
}

bool mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);
	struct mlx5_cqe64 *cqe;
#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
	struct net_device *netdev = rq->netdev;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_cqe64 *prev_cqe;
#endif
	int i;

	/* avoid accessing cq (dma coherent memory) if not needed */
	if (!test_and_clear_bit(MLX5E_CQ_HAS_CQES, &cq->flags))
		return false;

	cqe = mlx5e_get_cqe(cq);

	for (i = 0; i < budget; i++) {
		struct mlx5e_rx_wqe *wqe;
		struct sk_buff *skb;
		__be16 wqe_counter_be;
		u16 wqe_counter;

		if (!cqe)
			break;

		mlx5_cqwq_pop(&cq->wq);
		mlx5e_prefetch_cqe(cq);

		wqe_counter_be = cqe->wqe_counter;
		wqe_counter    = be16_to_cpu(wqe_counter_be);
		wqe            = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
		skb            = rq->skb[wqe_counter];
		prefetch(skb->data);
		rq->skb[wqe_counter] = NULL;

		dma_unmap_single(rq->pdev,
				 *((dma_addr_t *)skb->cb),
				 rq->wqe_sz,
				 DMA_FROM_DEVICE);

		if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
			rq->stats.wqe_err++;
			dev_kfree_skb(skb);
			cqe = mlx5e_get_cqe(cq);
			goto wq_ll_pop;
		}

		mlx5e_build_rx_skb(cqe, rq, skb);
		rq->stats.packets++;

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
		prev_cqe = cqe;
#endif
		cqe = mlx5e_get_cqe(cq);

#ifdef HAVE_SK_BUFF_XMIT_MORE
		if (cqe)
			skb->xmit_more = 1;
#endif

#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
		if (rq->flags & MLX5E_RQ_FLAG_SWLRO)
			lro_receive_skb(&rq->sw_lro.lro_mgr, skb, NULL);
		else
#endif

#if defined HAVE_VLAN_GRO_RECEIVE || defined HAVE_VLAN_HWACCEL_RX
		if (priv->vlan_grp && cqe_has_vlan(prev_cqe))
#ifdef HAVE_VLAN_GRO_RECEIVE
			vlan_gro_receive(cq->napi, priv->vlan_grp,
					 be16_to_cpu(prev_cqe->vlan_info),
					 skb);
#else
			vlan_hwaccel_rx(skb, priv->vlan_grp,
					be16_to_cpu(prev_cqe->vlan_info));
#endif
		else
#endif
		napi_gro_receive(cq->napi, skb);

wq_ll_pop:
		mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
			       &wqe->next.next_wqe_index);
	}

	mlx5_cqwq_update_db_record(&cq->wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	if (i == budget) {
		set_bit(MLX5E_CQ_HAS_CQES, &cq->flags);
		return true;
	}
#ifdef CONFIG_COMPAT_LRO_ENABLED_IPOIB
	if (rq->flags & MLX5E_RQ_FLAG_SWLRO)
		lro_flush_all(&rq->sw_lro.lro_mgr);
#endif
	return false;
}
