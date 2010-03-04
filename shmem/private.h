#include <compat.h>
#include <fsl_shmem.h>

/* Hook to shmem_alloc.c */
int shmem_alloc_init(void *bar, size_t sz);

