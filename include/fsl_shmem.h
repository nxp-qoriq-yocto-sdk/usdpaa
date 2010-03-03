#ifndef FSL_SHMEM_H
#define FSL_SHMEM_H

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
int fsl_shmem_setup(void);

/* Ad-hoc DMA allocation (not optimised for speed...). NB, the size must be
 * provided to 'free'. */
void *fsl_shmem_memalign(size_t boundary, size_t size);
void fsl_shmem_free(void *ptr, size_t size);

#endif /* !FSL_SHMEM_H */

