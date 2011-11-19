/* Copyright (c) 2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <internal/process.h>
#include <internal/conf.h>

/* NB: these definitions need to exactly match those in the kernel "fsl_usdpaa"
 * driver. It is all temporary until being replaced by HugeTLB. */
#include <sys/ioctl.h>
#define USDPAA_IOCTL_MAGIC 'u'
struct usdpaa_ioctl_get_region {
	uint64_t phys_start;
	uint64_t phys_len;
};
struct usdpaa_ioctl_id_alloc {
	uint32_t base; /* Return value, the start of the allocated range */
	enum usdpaa_id_type id_type; /* what kind of resource(s) to allocate */
	uint32_t num; /* how many IDs to allocate (and return value) */
	uint32_t align; /* must be a power of 2, 0 is treated like 1 */
	int partial; /* whether to allow less than 'num' */
};
struct usdpaa_ioctl_id_release {
	/* Input; */
	enum usdpaa_id_type id_type;
	uint32_t base;
	uint32_t num;
};
#define USDPAA_IOCTL_GET_PHYS_BASE \
	_IOR(USDPAA_IOCTL_MAGIC, 0x01, struct usdpaa_ioctl_get_region)
#define USDPAA_IOCTL_ID_ALLOC \
	_IOWR(USDPAA_IOCTL_MAGIC, 0x02, struct usdpaa_ioctl_id_alloc)
#define USDPAA_IOCTL_ID_RELEASE \
	_IOW(USDPAA_IOCTL_MAGIC, 0x03, struct usdpaa_ioctl_id_release)

/* As higher-level drivers will be built on top of this (dma_mem, qbman, ...),
 * it's preferable that the process driver itself not provide any exported API.
 * As such, combined with the fact that none of these operations are performance
 * critical, it is justified to use lazy initialisation, so that's what the lock
 * is for. */
static int fd = -1;
static pthread_mutex_t fd_init_lock = PTHREAD_MUTEX_INITIALIZER;

static struct usdpaa_ioctl_get_region region;
static void *mmapped_virt;
static int is_mmapped;

static int check_fd(void)
{
	if (fd >= 0)
		return 0;
	pthread_mutex_lock(&fd_init_lock);
	/* check again with the lock held */
	if (fd < 0)
		fd = open(PROCESS_PATH, O_RDWR);
	pthread_mutex_unlock(&fd_init_lock);
	return (fd >= 0) ? 0 : -ENODEV;
}

int process_dma_map(void **virt, uint64_t *phys, uint64_t *len)
{
	int ret = check_fd();
	if (ret)
		return ret;
	BUG_ON(is_mmapped);
	ret = ioctl(fd, USDPAA_IOCTL_GET_PHYS_BASE, &region);
	if (ret) {
		perror("ioctl(USDPAA_IOCTL_GET_PHYS_BASE)");
		return ret;
	}
	*phys = region.phys_start;
	*len = region.phys_len;
	/* If we start the virtual address search from 0, we sometimes *will*
	 * get a map starting at zero, which breaks things because it's
	 * indistinguishable from NULL. So we start the search at least one page
	 * higher. (Using 0x10000 rather than 0x1000, just in case bigger pages
	 * come along!) */
	mmapped_virt = mmap((void *)0x10000, *len, PROT_READ | PROT_WRITE, MAP_SHARED,
			    fd, 0);
	if (mmapped_virt == MAP_FAILED) {
		perror("mmap(USDPAA)");
		return -EFAULT;
	}
	*virt = mmapped_virt;
	is_mmapped = 1;
	return 0;
}

void process_dma_unmap(void)
{
	int ret;
	BUG_ON(!is_mmapped);
	ret = munmap(mmapped_virt, region.phys_len);
	if (ret)
		perror("munmap(USDPAA)");
	is_mmapped = 0;
}

int process_alloc(enum usdpaa_id_type id_type, uint32_t *base, uint32_t num,
		  uint32_t align, int partial)
{
	struct usdpaa_ioctl_id_alloc id = {
		.id_type = id_type,
		.num = num,
		.align = align,
		.partial = partial
	};
	int ret = check_fd();
	if (ret)
		return ret;
	ret = ioctl(fd, USDPAA_IOCTL_ID_ALLOC, &id);
	if (ret)
		return ret;
	for (ret = 0; ret < id.num; ret++)
		base[ret] = id.base + ret;
	return id.num;
}

void process_release(enum usdpaa_id_type id_type, uint32_t base, uint32_t num)
{
	struct usdpaa_ioctl_id_release id = {
		.id_type = id_type,
		.base = base,
		.num = num
	};
	int ret = check_fd();
	if (ret)
		return ret;
	return ioctl(fd, USDPAA_IOCTL_ID_RELEASE, &id);
}
