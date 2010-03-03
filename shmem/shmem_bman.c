#include "private.h"

static int __pool_drain(struct shmem_bpool *p)
{
	int cnt = 0;
	int breathed = 0;
	while (1) {
		struct bm_buffer buf[8];
		int toacquire = breathed ? 1 : 8;
		int ret = bman_acquire(p->pool, buf, toacquire, 0);
		if (ret < 0) {
			if (!breathed) {
				/* pause in case we're racing against releases then
				 * retry to make sure we get everything, and the
				 * retry will acquire in units of 1 (to pick up
				 * the modulo-8 remains). */
				breathed = 1;
				usleep(50000);
				continue;
			}
			goto done;
		}
		BUG_ON(ret != toacquire);
		cnt += toacquire;
	}
done:
	return cnt;
}

static void pool_cleanup(struct shmem_bpool *p)
{
	__pool_drain(p);
	bman_free_pool(p->pool);
}

static int pool_init(struct shmem_bpool *p)
{
	u64 bar = FSL_SHMEM_PHYS + p->offset;
	int ret, drained;
	unsigned int loop;
	p->params.bpid = p->bpid;
	p->params.flags = 0;
	p->pool = bman_new_pool(&p->params);
	if (!p->pool)
		return -ENOMEM;
	drained = __pool_drain(p);
	for (loop = 0; loop < p->num; ) {
		struct bm_buffer buf[8];
		int cnt;
		for (cnt = 0; cnt < 8; cnt++, loop++, bar += p->sz) {
			buf[cnt].hi = upper_32_bits(bar);
			buf[cnt].lo = lower_32_bits(bar);
		}
		ret = bman_release(p->pool, buf, 8, BMAN_RELEASE_FLAG_WAIT);
		if (ret) {
			fprintf(stderr, "Failed to seed bpid %d\n", p->bpid);
			pool_cleanup(p);
			return -ENOMEM;
		}
	}
	printf("Seeded bpid %d with %d buffers\n", p->bpid, p->num);
	if (drained)
		printf("... (after draining %d stale buffers)\n", drained);
	return 0;
}

int shmem_bman_init(struct shmem_bpool *bpools, int num)
{
	int ret, loop;
	for (loop = 0; loop < num; loop++) {
		ret = pool_init(&bpools[loop]);
		if (ret) {
			fprintf(stderr, "Failed to init pool %d (bpid %d)\n",
				loop, bpools[loop].bpid);
			while ((--loop) >= 0)
				pool_cleanup(&bpools[loop]);
			return ret;
		}
	}
	return 0;
}

