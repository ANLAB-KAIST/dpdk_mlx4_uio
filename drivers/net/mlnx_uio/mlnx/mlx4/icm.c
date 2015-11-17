#ifndef K_CONVERTED
#define K_CONVERTED
#endif
#include "kmod.h"
/*
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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



#include "mlx4.h"
#include "icm.h"
#include "fw.h"
#include "log2.h"

#include <rte_persistent.h>

/*
 * We allocate in as big chunks as we can, up to a maximum of 256 KB
 * per chunk.
 */
enum {
	MLX4_ICM_ALLOC_SIZE	= 1 << 18,
	MLX4_TABLE_CHUNK_SIZE	= 1 << 18
};

#ifdef KMOD_REMOVED
static void mlx4_free_icm_pages(struct mlx4_dev *dev, struct mlx4_icm_chunk *chunk)
{
#ifdef KMOD_MODIFIED
	int i;

	//if (chunk->nsg > 0)
	//	pci_unmap_sg(dev->persist->pdev, chunk->mem, chunk->npages,
	//		     PCI_DMA_BIDIRECTIONAL);

	//for (i = 0; i < chunk->npages; ++i)
	//	__free_pages(sg_page(&chunk->mem[i]),
	//		     get_order(chunk->mem[i].length));
	for(i=0; i<chunk->npages; i++)
	{
		rte_persistent_free(chunk->persistent_mem[i]);
		chunk->persistent_mem[i] = NULL;
	}
#endif
}
#endif

#ifdef KMOD_MODIFIED
static void mlx4_free_icm_coherent(struct mlx4_dev *dev, struct mlx4_icm_chunk *chunk)
{
	int i;
	/*
	for (i = 0; i < chunk->npages; ++i)
		dma_free_coherent(&dev->persist->pdev->dev,
				  chunk->mem[i].length,
				  lowmem_page_address(sg_page(&chunk->mem[i])),
				  sg_dma_address(&chunk->mem[i]));
	 */
	for(i=0; i<chunk->npages; i++)
	{
		rte_persistent_free(chunk->persistent_mem[i]);
		chunk->persistent_mem[i] = NULL;
	}
}
#endif

#ifdef KMOD_MODIFIED
void mlx4_free_icm(struct mlx4_dev *dev, struct mlx4_icm *icm/*, int coherent = 1*/)
{
	struct mlx4_icm_chunk *chunk, *tmp;

	if (!icm)
		return;

	list_for_each_entry_safe(chunk, tmp, &icm->chunk_list, list) {
		//if (coherent)
			mlx4_free_icm_coherent(dev, chunk);
		//else
		//	mlx4_free_icm_pages(dev, chunk);

		kfree(chunk);
	}

	kfree(icm);
}
#endif

#ifdef KMOD_REMOVED
static int mlx4_alloc_icm_pages(struct scatterlist *mem, int order,
				gfp_t gfp_mask, int node)
{
	struct page *page;

	page = alloc_pages_node(node, gfp_mask, order);
	if (!page) {
		page = alloc_pages(gfp_mask, order);
		if (!page)
			return -ENOMEM;
	}

	sg_set_page(mem, page, PAGE_SIZE << order, 0);
	return 0;
}
#endif

#ifdef KMOD_MODIFIED
static int mlx4_alloc_icm_coherent(struct rte_pci_device *dev, void **persistent_mem,
				    int order, gfp_t gfp_mask)
{
	void *buf = rte_persistent_alloc(PAGE_SIZE << order, dev->numa_node);
	if (!buf)
		return -ENOMEM;

	*persistent_mem = buf;
	return 0;
}
#endif

#ifdef KMOD_MODIFIED
struct mlx4_icm *mlx4_alloc_icm(struct mlx4_dev *dev, int npages,
				gfp_t gfp_mask/*, int coherent*/)
{
	struct mlx4_icm *icm;
	struct mlx4_icm_chunk *chunk = NULL;
	int cur_order;
	int ret;
	int coherent = 1; //only persistent memory

	/* We use sg_set_buf for coherent allocs, which assumes low memory */
	//BUG_ON(coherent && (gfp_mask & __GFP_HIGHMEM));

	icm = kmalloc_node(sizeof(*icm),
			   gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN),
			   dev->numa_node);
	if (!icm) {
		icm = kmalloc(sizeof(*icm),
			      gfp_mask & ~(__GFP_HIGHMEM | __GFP_NOWARN));
		if (!icm)
			return NULL;
	}

	icm->refcount = 0;
	INIT_LIST_HEAD(&icm->chunk_list);

	cur_order = get_order(MLX4_ICM_ALLOC_SIZE);

	while (npages > 0) {
		if (!chunk) {
			chunk = kmalloc_node(sizeof(*chunk),
					     gfp_mask & ~(__GFP_HIGHMEM |
							  __GFP_NOWARN),
					     dev->numa_node);
			if (!chunk) {
				chunk = kmalloc(sizeof(*chunk),
						gfp_mask & ~(__GFP_HIGHMEM |
							     __GFP_NOWARN));
				if (!chunk)
					goto fail;
			}

			//sg_init_table(chunk->mem, MLX4_ICM_CHUNK_LEN);
			memset(chunk->persistent_mem, 0, sizeof(chunk->persistent_mem));
			chunk->npages = 0;
			chunk->nsg    = 0;
			list_add_tail(&chunk->list, &icm->chunk_list);
		}

		while (1 << cur_order > npages)
			--cur_order;

		if (coherent)
		{
			ret = mlx4_alloc_icm_coherent(dev->persist->rte_pdev,
						      &chunk->persistent_mem[chunk->npages],
						      cur_order, gfp_mask);
		}
		else
		{
			assert(0);
			//ret = mlx4_alloc_icm_pages(&chunk->mem[chunk->npages],
			//			   cur_order, gfp_mask,
			//			   dev->numa_node);
		}

		if (ret) {
			if (--cur_order < 0)
				goto fail;
			else
				continue;
		}

		++chunk->npages;

		if (coherent)
			++chunk->nsg;
		else if (chunk->npages == MLX4_ICM_CHUNK_LEN) {
			assert(0);
			/*
			chunk->nsg = pci_map_sg(dev->persist->pdev, chunk->mem,
						chunk->npages,
						PCI_DMA_BIDIRECTIONAL);

			if (chunk->nsg <= 0)
				goto fail;
				*/
		}

		if (chunk->npages == MLX4_ICM_CHUNK_LEN)
			chunk = NULL;

		npages -= 1 << cur_order;
	}
/*
	if (!coherent && chunk) {
		chunk->nsg = pci_map_sg(dev->persist->pdev, chunk->mem,
					chunk->npages,
					PCI_DMA_BIDIRECTIONAL);

		if (chunk->nsg <= 0)
			goto fail;
	}
*/
	return icm;

fail:
	mlx4_free_icm(dev, icm/*, coherent*/);
	return NULL;
}
#endif

static int mlx4_MAP_ICM(struct mlx4_dev *dev, struct mlx4_icm *icm, u64 virt)
{
	return mlx4_map_cmd(dev, MLX4_CMD_MAP_ICM, icm, virt);
}

static int mlx4_UNMAP_ICM(struct mlx4_dev *dev, u64 virt, u32 page_count)
{
	return mlx4_cmd(dev, virt, page_count, 0, MLX4_CMD_UNMAP_ICM,
			MLX4_CMD_TIME_CLASS_B, MLX4_CMD_NATIVE);
}

int mlx4_MAP_ICM_AUX(struct mlx4_dev *dev, struct mlx4_icm *icm)
{
	return mlx4_map_cmd(dev, MLX4_CMD_MAP_ICM_AUX, icm, -1);
}

int mlx4_UNMAP_ICM_AUX(struct mlx4_dev *dev)
{
	return mlx4_cmd(dev, 0, 0, 0, MLX4_CMD_UNMAP_ICM_AUX,
			MLX4_CMD_TIME_CLASS_B, MLX4_CMD_NATIVE);
}

#ifdef KMOD_MODIFIED
int mlx4_table_get(struct mlx4_dev *dev, struct mlx4_icm_table *table, u32 obj,
		   gfp_t gfp)
{
	u32 i = (obj & (table->num_obj - 1)) /
			(MLX4_TABLE_CHUNK_SIZE / table->obj_size);
	int ret = 0;

	mutex_lock(&table->mutex);

	if (table->icm[i]) {
		++table->icm[i]->refcount;
		goto out;
	}

	table->icm[i] = mlx4_alloc_icm(dev, MLX4_TABLE_CHUNK_SIZE >> PAGE_SHIFT,
				       (table->lowmem ? gfp : GFP_HIGHUSER) |
				       __GFP_NOWARN/*, table->coherent*/);
	if (!table->icm[i]) {
		ret = -ENOMEM;
		goto out;
	}

	if (mlx4_MAP_ICM(dev, table->icm[i], table->virt +
			 (u64) i * MLX4_TABLE_CHUNK_SIZE)) {
		mlx4_free_icm(dev, table->icm[i]/*, table->coherent*/);
		table->icm[i] = NULL;
		ret = -ENOMEM;
		goto out;
	}

	++table->icm[i]->refcount;

out:
	mutex_unlock(&table->mutex);
	return ret;
}
#endif

#ifdef KMOD_MODIFIED
void mlx4_table_put(struct mlx4_dev *dev, struct mlx4_icm_table *table, u32 obj)
{
	u32 i;
	u64 offset;

	i = (obj & (table->num_obj - 1)) / (MLX4_TABLE_CHUNK_SIZE / table->obj_size);

	mutex_lock(&table->mutex);

	if (--table->icm[i]->refcount == 0) {
		offset = (u64) i * MLX4_TABLE_CHUNK_SIZE;
		mlx4_UNMAP_ICM(dev, table->virt + offset,
			       MLX4_TABLE_CHUNK_SIZE / MLX4_ICM_PAGE_SIZE);
		mlx4_free_icm(dev, table->icm[i]/*, table->coherent*/);
		table->icm[i] = NULL;
	}

	mutex_unlock(&table->mutex);
}
#endif

#ifdef KMOD_MODIFIED
void *mlx4_table_find(struct mlx4_icm_table *table, u32 obj,
			dma_addr_t *dma_handle)
{
	int offset, dma_offset, i;
	u64 idx;
	struct mlx4_icm_chunk *chunk;
	struct mlx4_icm *icm;
	void *persistent_addr = NULL;

	if (!table->lowmem)
		return NULL;

	mutex_lock(&table->mutex);

	idx = (u64) (obj & (table->num_obj - 1)) * table->obj_size;
	icm = table->icm[idx / MLX4_TABLE_CHUNK_SIZE];
	dma_offset = offset = idx % MLX4_TABLE_CHUNK_SIZE;

	if (!icm)
		goto out;

	list_for_each_entry(chunk, &icm->chunk_list, list) {
		for (i = 0; i < chunk->npages; ++i) {
			/*
			if (dma_handle && dma_offset >= 0) {
				if (sg_dma_len(&chunk->mem[i]) > dma_offset)
					*dma_handle = sg_dma_address(&chunk->mem[i]) +
						dma_offset;
				dma_offset -= sg_dma_len(&chunk->mem[i]);
			}
			*/
			if (dma_handle && dma_offset >= 0) {
				if (rte_persistent_mem_length(chunk->persistent_mem[i]) > dma_offset)
					*dma_handle = rte_persistent_hw_addr(chunk->persistent_mem[i]) +
					dma_offset;
				dma_offset -= rte_persistent_mem_length(chunk->persistent_mem[i]);
			}
			/*
			 * DMA mapping can merge pages but not split them,
			 * so if we found the page, dma_handle has already
			 * been assigned to.
			 */
			if (rte_persistent_mem_length(chunk->persistent_mem[i]) > offset) {
				persistent_addr = chunk->persistent_mem[i];
				goto out;
			}
			offset -= rte_persistent_mem_length(persistent_addr);
		}
	}

out:
	mutex_unlock(&table->mutex);
	return persistent_addr ? RTE_PTR_ADD(persistent_addr, offset) : NULL;
}
#endif

#ifdef KMOD_MODIFIED
int mlx4_table_get_range(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			 u32 start, u32 end)
{
	int inc = MLX4_TABLE_CHUNK_SIZE / table->obj_size;
	int err;
	u32 i;

	for (i = start; i <= end; i += inc) {
		err = mlx4_table_get(dev, table, i, GFP_KERNEL);
		if (err)
			goto fail;
	}

	return 0;

fail:
	while (i > start) {
		i -= inc;
		mlx4_table_put(dev, table, i);
	}

	return err;
}
#endif

void mlx4_table_put_range(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			  u32 start, u32 end)
{
	u32 i;

	for (i = start; i <= end; i += MLX4_TABLE_CHUNK_SIZE / table->obj_size)
		mlx4_table_put(dev, table, i);
}

#ifdef KMOD_MODIFIED

int mlx4_init_icm_table(struct mlx4_dev *dev, struct mlx4_icm_table *table,
			u64 virt, int obj_size,	u32 nobj, int reserved,
			int use_lowmem, int use_coherent)
{
	int obj_per_chunk;
	int num_icm;
	unsigned chunk_size;
	int i;
	u64 size;

	if(!use_coherent)
	{
		dev_warn(dev, "%s tried not to use_coherent, but enabled by default.\n", __FUNCTION__);
	}

	obj_per_chunk = MLX4_TABLE_CHUNK_SIZE / obj_size;
	num_icm = (nobj + obj_per_chunk - 1) / obj_per_chunk;

	table->icm      = kcalloc(num_icm, sizeof *table->icm, GFP_KERNEL);
	if (!table->icm)
		return -ENOMEM;
	table->virt     = virt;
	table->num_icm  = num_icm;
	table->num_obj  = nobj;
	table->obj_size = obj_size;
	table->lowmem   = use_lowmem;
	table->coherent = use_coherent;
	mutex_init(&table->mutex);

	size = (u64) nobj * obj_size;
	for (i = 0; i * MLX4_TABLE_CHUNK_SIZE < reserved * obj_size; ++i) {
		chunk_size = MLX4_TABLE_CHUNK_SIZE;
		if ((i + 1) * MLX4_TABLE_CHUNK_SIZE > size)
			chunk_size = PAGE_ALIGN(size -
					i * MLX4_TABLE_CHUNK_SIZE);

		table->icm[i] = mlx4_alloc_icm(dev, chunk_size >> PAGE_SHIFT,
					       (use_lowmem ? GFP_KERNEL : GFP_HIGHUSER) |
					       __GFP_NOWARN/*, use_coherent*/);
		if (!table->icm[i])
			goto err;
		if (mlx4_MAP_ICM(dev, table->icm[i], virt + i * MLX4_TABLE_CHUNK_SIZE)) {
			mlx4_free_icm(dev, table->icm[i]/*, use_coherent*/);
			table->icm[i] = NULL;
			goto err;
		}

		/*
		 * Add a reference to this ICM chunk so that it never
		 * gets freed (since it contains reserved firmware objects).
		 */
		++table->icm[i]->refcount;
	}

	return 0;

err:
	for (i = 0; i < num_icm; ++i)
		if (table->icm[i]) {
			mlx4_UNMAP_ICM(dev, virt + i * MLX4_TABLE_CHUNK_SIZE,
				       MLX4_TABLE_CHUNK_SIZE / MLX4_ICM_PAGE_SIZE);
			mlx4_free_icm(dev, table->icm[i]/*, use_coherent*/);
		}

	kfree(table->icm);

	return -ENOMEM;
}
#endif

#ifdef KMOD_MODIFIED
void mlx4_cleanup_icm_table(struct mlx4_dev *dev, struct mlx4_icm_table *table)
{
	int i;

	for (i = 0; i < table->num_icm; ++i)
		if (table->icm[i]) {
			mlx4_UNMAP_ICM(dev, table->virt + i * MLX4_TABLE_CHUNK_SIZE,
				       MLX4_TABLE_CHUNK_SIZE / MLX4_ICM_PAGE_SIZE);
			mlx4_free_icm(dev, table->icm[i]/*, table->coherent*/);
		}

	kfree(table->icm);
}
#endif
