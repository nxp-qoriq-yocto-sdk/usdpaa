/* Copyright (c) 2010 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include "private.h"

/* For an efficient conversion between user-space virtual address map(s) and bus
 * addresses required by hardware for DMA, we use a single contiguous mmap() on
 * the /dev/fsl-shmem device, a pre-arranged physical base address (and
 * similarly reserved from regular linux use by a "mem=<...>" kernel boot
 * parameter). See conf.h for the hard-coded constants that are used. */

static int fd;

/* Present "carve up" is to use the first 0x5b80000 bytes of shmem for buffer
 * pools and the rest of shmem (which is 256MB total) for ad-hoc allocations. */
#define SHMEM_ALLOC_BAR	((void *)FSL_SHMEM_VIRT + 0x5b80000)
#define SHMEM_ALLOC_SZ	(0x10000000 - 0x05b80000)

int fsl_shmem_setup(void)
{
	void *p;
	int ret = -ENODEV;
	fd = open(FSL_SHMEM_PATH, O_RDWR);
	if (fd < 0) {
		perror("can't open shmem device");
		return ret;
	}
	p = mmap((void *)FSL_SHMEM_VIRT, FSL_SHMEM_SIZE, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_FIXED, fd, FSL_SHMEM_PHYS);
	if (p == MAP_FAILED) {
		perror("can't mmap() shmem device");
		goto err;
	}
	if (p != (void *)FSL_SHMEM_VIRT)
		goto err;
	ret = shmem_alloc_init(SHMEM_ALLOC_BAR, SHMEM_ALLOC_SZ);
	if (ret)
		goto err;
	printf("FSL shmem device mapped (phys=0x%x,virt=%p,sz=0x%x)\n",
		FSL_SHMEM_PHYS, p, FSL_SHMEM_SIZE);
	return 0;
err:
	fprintf(stderr, "ERROR; FSL shmem setup failed, ret = %d\n", ret);
	close(fd);
	return ret;
}

