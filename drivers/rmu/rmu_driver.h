/* Copyright (c) 2012 Freescale Semiconductor, Inc.
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

#ifndef RMU_DRIVER_H
#define RMU_DRIVER_H

/* is x a power of 2? */
#define is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))

#define PAGE_SIZE	0x1000
#define PAGE_MASK	(PAGE_SIZE - 1)

#define MSG_MAX_FRAME_SIZE	4096

#define MSG_OMMR_DES_SEN	0x00100000
#define MSG_OMMR_MUS	0x00000001
#define MSG_OMMR_MUI		0x00000002
#define MSG_OMMR_CIRQ_SIZ	0x0000F000
#define MSG_OMSR_CLEAR		0x1cb3
#define MSG_OMSR_QF		0x00100000
#define MSG_OMSR_MER		0x00001000
#define MSG_OMSR_RETE		0x00000800
#define MSG_OMSR_PRT		0x00100400
#define MSG_OMSR_TE		0x00000080
#define MSG_OMSR_QOI		0x00000020
#define MSG_OMSR_QFI		0x00000010
#define MSG_OMSR_MUB		0x00000004
#define MSG_OMSR_EOMI	0x00000002
#define MSG_OMSR_QEI		0x00000001

#define MSG_OMDATR_EOMIE 0x20000000
#define MSG_OMDATR_DTFLOWLVL 0x0C000000
#define MSG_OMSAR_SEN 0x00000004

#define MSG_IMMR_ME		0x00000001
#define MSG_IMMR_MI		0x00000002
#define MSG_IMMR_SEN		0x00100000
#define MSG_IMMR_FRA_SIZ	0x000F0000
#define MSG_IMMR_CIRQ_SIZ	0x0000F000
#define MSG_IMMR_MIQIE	0x00000040
#define MSG_IMSR_CLEAR		0x491
#define MSG_IMSR_QF		0x00100000
#define MSG_IMSR_MRT		0x00000400
#define MSG_IMSR_TE		0x00000080
#define MSG_IMSR_QFI		0x00000010
#define MSG_IMSR_QE		0x00000002
#define MSG_IMSR_MIQI		0x00000001

#define DBELL_ODMR_DUS	0x00000001
#define DBELL_ODSR_CLEAR	0x1C00
#define DBELL_ODSR_MER	0x00001000
#define DBELL_ODSR_RETE	0x00000800
#define DBELL_ODSR_PRT	0x00000400
#define DBELL_ODSR_DUB	0x00000004
#define DBELL_ODSR_EODI	0x00000002
#define DBELL_IDMR_SEN		0x00100000
#define DBELL_IDMR_CIRQ_SIZ	0x0000F000
#define DBELL_IDMR_DIQIE	0x00000040
#define DBELL_IDMR_DI		0x00000002
#define DBELL_IDMR_DE		0x00000001
#define DBELL_IDSR_CLEAR		0x91
#define DBELL_IDSR_TE		0x00000080
#define DBELL_IDSR_QF		0x00100000
#define DBELL_IDSR_QFI		0x00000010
#define DBELL_IDSR_QE		0x00000002
#define DBELL_IDSR_DIQI		0x00000001

#define MSG_MIN_TX_RING_ENTRY	2
#define MSG_MAX_TX_RING_ENTRY	2048
#define MSG_MIN_RX_RING_ENTRY	2
#define MSG_MAX_RX_RING_ENTRY	2048
#define DBELL_MIN_RX_RING_ENTRY	2
#define DBELL_MAX_RX_RING_ENTRY	2048

struct msg_regs {
	uint32_t ommr;
	uint32_t omsr;
	uint32_t eomdqdpar;
	uint32_t omdqdpar;
	uint32_t eomsar;
	uint32_t omsar;
	uint32_t omdpr;
	uint32_t omdatr;
	uint32_t omdcr;
	uint32_t eomdqepar;
	uint32_t omdqepar;
	uint32_t res1[13];
	uint32_t immr;
	uint32_t imsr;
	uint32_t eimfqdpar;
	uint32_t imfqdpar;
	uint32_t eimfqepar;
	uint32_t imfqepar;
	uint32_t immirir;
	uint32_t res2;
	uint32_t eimhqepar;
	uint32_t imhqepar;
};

struct dbell_regs {
	uint32_t odmr;
	uint32_t odsr;
	uint32_t res0[4];
	uint32_t oddpr;
	uint32_t oddatr;
	uint32_t res1[3];
	uint32_t odretcr;
	uint32_t res2[12];
	uint32_t idmr;
	uint32_t idsr;
	uint32_t eidqdpar;
	uint32_t idqdpar;
	uint32_t eidqepar;
	uint32_t idqepar;
	uint32_t idmirir;
	uint32_t res3;
};

struct msg_tx_desc {
	uint32_t res0;
	uint32_t saddr;
	uint32_t dport;
	uint32_t dattr;
	uint32_t res1;
	uint32_t res2;
	uint32_t dwcnt;
	uint32_t res3;
};
#endif
