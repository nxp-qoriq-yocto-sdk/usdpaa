/* Copyright 2009-2011 Freescale Semiconductor, Inc.
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

#include "dpa_sys.h"
#include <internal/process.h>

int bman_alloc_bpid_range(u32 *result, u32 count, u32 align, int partial)
{
	return process_alloc(usdpaa_id_bpid, result, count, align, partial);
}
EXPORT_SYMBOL(bman_alloc_bpid_range);

void bman_release_bpid_range(u32 bpid, u32 count)
{
	process_release(usdpaa_id_bpid, bpid, count);
}
EXPORT_SYMBOL(bman_release_bpid_range);

int qman_alloc_fqid_range(u32 *result, u32 count, u32 align, int partial)
{
	return process_alloc(usdpaa_id_fqid, result, count, align, partial);
}
EXPORT_SYMBOL(qman_alloc_fqid_range);

void qman_release_fqid_range(u32 fqid, u32 count)
{
	process_release(usdpaa_id_fqid, fqid, count);
}
EXPORT_SYMBOL(qman_release_fqid_range);
