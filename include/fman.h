/* Copyright (c) 2010 Freescale Semiconductor, Inc.
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

#ifndef __FMAN_H
#define __FMAN_H

/* This struct exports parameters about an Fman network interface */
struct fman_if {
	enum {
		fman_mac_1g,
		fman_mac_10g
	} mac_type;
	struct list_head node;
};

/* And this is the base list node that the interfaces are added to. (See
 * fman_if_enable_all_rx() below for an example of its use.) */
const struct list_head *fman_if_list;

/* "init" discovers all Fman interfaces. "finish" tears down the driver. */
int fman_if_init(void);
void fman_if_finish(void);

/* Enable/disable Rx on specific interfaces */
void fman_if_enable_rx(const struct fman_if *);
void fman_if_disable_rx(const struct fman_if *);

/* Enable/disable Rx on all interfaces */
static inline void fman_if_enable_all_rx(void)
{
	const struct fman_if *__if;
	list_for_each_entry(__if, fman_if_list, node)
		fman_if_enable_rx(__if);
}
static inline void fman_if_disable_all_rx(void)
{
	const struct fman_if *__if;
	list_for_each_entry(__if, fman_if_list, node)
		fman_if_disable_rx(__if);
}

#endif	/* __FMAN_H */
