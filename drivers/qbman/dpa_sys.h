/* Copyright (c) 2008 - 2010 Freescale Semiconductor, Inc.
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
 */

#include "compat.h"

#ifdef CONFIG_FSL_DPA_CHECKING
#define DPA_ASSERT(x) \
	do { \
		if (!(x)) { \
			pr_crit("ASSERT: (%s:%d) %s\n", __FILE__, __LINE__, \
				__stringify_1(x)); \
			exit(1); \
		} \
	} while(0)
#else
#define DPA_ASSERT(x)		do { ; } while(0)
#endif

/* Commonly used combo */
static inline void dcbit_ro(void *p)
{
	dcbi(p);
	dcbt_ro(p);
}

/* For trees that contain such support, these stubs are re-mapped to
 * hypervisor+failover features. */
struct device_node {
	int offset;
	const char *full_name;
};
#define for_each_child_of_node(n1,n2) while (0)
static inline int fsl_dpa_should_recover(void)
{
	return 0;
}
static inline int pamu_enable_liodn(struct device_node *n __always_unused,
					int i __always_unused)
{
	return 0;
}
