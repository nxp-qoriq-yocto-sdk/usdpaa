/* Copyright (c) 2009 Freescale Semiconductor, Inc.
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

#include "qman_test.h"

void qman_test_fqrange(void)
{
	int num;
	u32 result1, result2, result3;

	pr_info("Testing \"FQRANGE\" allocator ...\n");
	/* Seed the allocator*/
	qman_release_fqid_range(0, 1000);

	num = qman_alloc_fqid_range(&result1, 100, 4, 0);
	BUG_ON(result1 % 4);

	num = qman_alloc_fqid_range(&result2, 500, 500, 0);
	BUG_ON((num != 500) || (result2 != 500));

	num = qman_alloc_fqid_range(&result3, 1000, 0, 0);
	BUG_ON(num >= 0);

	num = qman_alloc_fqid_range(&result3, 1000, 0, 1);
	BUG_ON(num < 400);

	qman_release_fqid_range(result2, 500);
	qman_release_fqid_range(result1, 100);
	qman_release_fqid_range(result3, num);

	/* It should now be possible to drain the allocator empty */
	num = qman_alloc_fqid_range(&result1, 1000, 0, 0);
	BUG_ON(num != 1000);
	pr_info("                              ... SUCCESS!\n");
}

