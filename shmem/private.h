#include <compat.h>
#include <fsl_shmem.h>

struct shmem_bpool {
	u8 bpid;
	size_t sz;
	unsigned int num;
	size_t offset;
	struct bman_pool_params params;
	struct bman_pool *pool;
};

/* Hook to shmem_alloc.c */
int shmem_alloc_init(void *bar, size_t sz);

/* Hook to shmem_bman.c */
int shmem_bman_init(struct shmem_bpool *bpools, int num);

