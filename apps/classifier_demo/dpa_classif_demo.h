/* Copyright (c) 2011-2013 Freescale Semiconductor, Inc.
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

#ifndef __DPA_CLASSIF_DEMO_H
#define __DPA_CLASSIF_DEMO_H


#define APP_TABLE_KEY_SIZE			9 /*bytes*/
#define APP_NUM_OF_ENTRIES			20
#define APP_NUM_OF_STATIC_ENTRIES		4
#define APP_NUM_ENTRIES_TO_REMOVE		10
#define APP_NUM_STATIC_ENTRIES_TO_REMOVE	1
#define APP_NUM_ENTRIES_TO_UPDATE		5
#define APP_NUM_STATIC_ENTRIES_TO_UPDATE	2


struct dpa_classif_connection {
	uint8_t		key[APP_TABLE_KEY_SIZE];
	uint32_t	fqid;
	int		entry_id;
};

struct ppam_arguments {
	int	fm;
	int	port;
};


int		ppam_init(void);

void		ppam_finish(void);

int		create_exact_match_table(void);

int		populate_table(int td);

void		clean_up(void);

#endif /* __DPA_CLASSIFIER_DEMO_H */
