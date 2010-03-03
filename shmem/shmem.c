#include "private.h"

/* For an efficient conversion between user-space virtual address map(s) and bus
 * addresses required by hardware for DMA, we use a single contiguous mmap() on
 * the /dev/fsl-shmem device, a pre-arranged physical base address (and
 * similarly reserved from regular linux use by a "mem=<...>" kernel boot
 * parameter). See conf.h for the hard-coded constants that are used. */

/* drain buffer pools of any stale entries (assumes Fman is quiesced),
 * mmap() the device,
 * carve out bman buffers and seed them into buffer pools,
 * initialise ad-hoc DMA allocation memory.
 *    -> returns non-zero on failure.
 */

static int fd;

/* these vars are shared with the other shmem C files, they define the "carve up"
 * of the shmem region */

static struct shmem_bpool shmem_bpools[] = {
	{
		.bpid = 7,
		.sz = 704,
		.num = 0x6000,
		.offset = 0
	},
	{
		.bpid = 8,
		.sz = 1088,
		.num = 0x6000,
		.offset = 0x01080000
	},
	{
		.bpid = 9,
		.sz = 2112,
		.num = 0x6000,
		.offset = 0x02a00000
	}
};
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
	ret = shmem_bman_init(shmem_bpools, 3);
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

