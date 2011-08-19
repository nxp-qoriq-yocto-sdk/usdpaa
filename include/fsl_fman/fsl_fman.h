/* Copyright 2011 Freescale Semiconductor, Inc.
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

#ifndef FSL_FMAN_H
#define FSL_FMAN_H

#ifdef __cplusplus
extern "C" {
#endif
/* Status field in FD is updated on Rx side by FMAN with following information.
 * Refer to field description in FM BG */
struct fm_status_t {
	unsigned int reserved0:3;
	unsigned int dcl4c:1; /* Don't Check L4 Checksum */
	unsigned int reserved1:1;
	unsigned int ufd:1; /* Unsupported Format */
	unsigned int lge:1; /* Length Error */
	unsigned int dme:1; /* DMA Error */

	unsigned int reserved2:4;
	unsigned int fpe:1; /* Frame physical Error */
	unsigned int fse:1; /* Frame Size Error */
	unsigned int dis:1; /* Discard by Classification */
	unsigned int reserved3:1;

	unsigned int eof:1; /* Key Extraction goes out of frame */
	unsigned int nss:1; /* No Scheme selected */
	unsigned int kso:1; /* Key Size Overflow */
	unsigned int reserved4:1;
	unsigned int fcl:2; /* Frame Color */
	unsigned int ipp:1; /* Illegal Policer Profile Selected */
	unsigned int flm:1; /* Frame Length Mismatch */
	unsigned int pte:1; /* Parser Timeout */
	unsigned int isp:1; /* Invalid Soft Parser Instruction */
	unsigned int phe:1; /* Header Error during parsing */
	unsigned int frdr:1; /* Frame Dropped by disabled port */
	unsigned int reserved5:4;
} __attribute__ ((__packed__));

#ifdef __cplusplus
}
#endif
#endif				/* FSL_FMAN_H */
