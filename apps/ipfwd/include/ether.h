/**
 \file ether.h
 \brief Ethernet protocol defines and data-types
 */
/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ETHER_H
#define _ETHER_H

#define ETH_DST_MULTICAST 0x1
#define ETH_DST_BROADCAST 0xFF

/**
 \brief	Display a 6 byte device address (MAC) in a readable format.
 */
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

/**
 \brief String format MAC Address for printing
  Assumes character byte array
 */
#define NMAC_STR(buf) \
	buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]

/**
 \brief Double word(64 bit) MAC format for printing
  Assumes Network byte order with MAC addr in lower 6 bytes
 */
#define NMAC_64(addr) \
	((uint8_t  *)&addr)[2], \
	((uint8_t  *)&addr)[3], \
	((uint8_t  *)&addr)[4], \
	((uint8_t  *)&addr)[5], \
	((uint8_t  *)&addr)[6], \
	((uint8_t  *)&addr)[7]

#endif /* ETHER_H */
