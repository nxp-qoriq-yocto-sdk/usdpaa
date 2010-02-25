/* Copyright (c) 2008, 2009 Freescale Semiconductor, Inc.
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

#include "compat.h"

void qman_test_high(int cpu);
void bman_test_high(int cpu);
void speed(int cpu);

/* These aren't really part of the "compat" header because we don't assume their
 * presence in linux or LWE. */

/* Alternate Time Base */
#define SPR_ATBL	526
#define SPR_ATBU	527

#define my_mfspr(reg) \
({ \
	register_t ret; \
	asm volatile("mfspr %0, %1" : "=r" (ret) : "i" (reg) : "memory"); \
	ret; \
})
static inline uint64_t
my_get_timebase(void)
{
	uint32_t hi, lo, chk;

	/*
	 * To make sure that there is no carry over
	 * between checking of TBU and TBL
	 */
	do {
		hi = my_mfspr(SPR_ATBU);
		lo = my_mfspr(SPR_ATBL);
		chk = my_mfspr(SPR_ATBU);
	} while (unlikely(hi != chk));

	return (uint64_t) hi << 32 | (uint64_t) lo;
}

