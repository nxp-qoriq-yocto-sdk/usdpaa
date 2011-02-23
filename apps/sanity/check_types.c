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

#include <compat.h>
#include <fsl_bman.h>
#include <fsl_qman.h>

/* This code exists just to sanity-check certain API headers for regressions */

#define CHECK_STRUCT(type,expected) \
	do { \
		struct foo_type_##type { \
			struct type the_obj; \
			char suffix; \
		} __packed myvar; \
		size_t foo_expected = (expected); \
		size_t foo_got = (unsigned long)&myvar.suffix - \
				(unsigned long)&myvar; \
		if (foo_expected != foo_got) { \
			fprintf(stderr, "FAIL: sizeof(%s) == %d, not %d\n", \
				__stringify(type), foo_got, foo_expected); \
			ret = -1; \
		} else \
			printf("OK: sizeof(%s) == %d\n", \
				__stringify(type), foo_got); \
	} while (0)

int main(int argc, char *argv[])
{
	int ret = 0;
	CHECK_STRUCT(qm_eqcr_entry, 64);
	CHECK_STRUCT(qm_dqrr_entry, 64);
	CHECK_STRUCT(qm_mr_entry, 64);
	CHECK_STRUCT(qm_mc_command, 64);
	CHECK_STRUCT(qm_mc_result, 64);
	CHECK_STRUCT(qm_fd, 16);
	CHECK_STRUCT(qm_sg_entry, 16);
	CHECK_STRUCT(qm_fqd_taildrop, 2);
	CHECK_STRUCT(qm_fqd_oac, 2);
	/* FAILs in the above tests will show up on stderr, which should
	 * otherwise be silent if all tests pass, so automation could possibly
	 * capture that. Otherwise if only stdout is captured, print a unique
	 * pass/fail summary line there that could be caught by a script. */
	if (ret)
		printf("Some checks failed\n");
	else
		printf("All checks passed\n");
	return ret;
}

