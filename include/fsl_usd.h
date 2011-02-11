/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
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

#ifndef FSL_USD_H
#define FSL_USD_H

#ifdef __cplusplus
extern "C" {
#endif

/***********************************/
/* USDPAA-specific initialisation: */

/* Thread-entry/exit hooks; */
int qman_thread_init(int cpu, int recovery_mode);
int bman_thread_init(int cpu, int recovery_mode);
int qman_thread_finish(void);
int bman_thread_finish(void);

/* Obtain thread-local UIO file-descriptors */
int qman_thread_fd(void);
int bman_thread_fd(void);

/* Post-process interrupts. NB, the kernel IRQ handler disables the interrupt
 * line before notifying us, and this post-processing re-enables it once
 * processing is complete. As such, it is essential to call this before going
 * into another blocking read/select/poll. */
void qman_thread_irq(void);
void bman_thread_irq(void);

/* Global setup, must be called on an initialised thread if recovery_mode!=0 */
int qman_global_init(int recovery_mode);
int bman_global_init(int recovery_mode);

#ifdef CONFIG_FSL_QMAN_ADAPTIVE_EQCR_THROTTLE
/* Rev1-specific instrumentation to throttle (per-cpu) EQCR_CI updates */
extern __thread u32 eqcr_ci_histogram[8];
extern __thread u32 throt_histogram[41];
#endif

#ifdef __cplusplus
}
#endif

#endif /* FSL_USD_H */

