# Copyright (c) 2011 - 2012 Freescale Semiconductor, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#	notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#	notice, this list of conditions and the following disclaimer in the
#	documentation and/or other materials provided with the distribution.
#     * Neither the name of Freescale Semiconductor nor the
#	names of its contributors may be used to endorse or promote products
#	derived from this software without specific prior written permission.
#
#
# ALTERNATIVELY, this software may be distributed under the terms of the
# GNU General Public License ("GPL") as published by the Free Software
# Foundation, either version 2 of that License or (at your option) any
# later version.
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

bin_PROGRAMS = ipsecfwd_app

AM_CFLAGS := -I$(TOP_LEVEL)/apps/ipsecfwd/lib
AM_CFLAGS += -I$(TOP_LEVEL)/apps/include
AM_CFLAGS += -I$(TOP_LEVEL)/apps/ipsecfwd/include
AM_CFLAGS += -I$(TOP_LEVEL)/apps/lib
AM_CFLAGS += $(LIBRTA_CFLAGS)

ipsecfwd_app_SOURCES := ipsecfwd.c ipsecfwd_init.c ipsecfwd_handler.c \
	ipsecfwd_splitkey.c
ipsecfwd_app_LDADD := usdpaa_ppac usdpaa_qbman usdpaa_fman usdpaa_dma_mem \
	usdpaa_of usdpaa_process app_ipsecfwd_ipsec app_ipsecfwd_net \
	app_ipsecfwd_ethernet app_ipsecfwd_ip app_ipsecfwd_mm apps_ipsecfwd_arp \
	app_ipsecfwd_refcount usdpaa_syscfg
ipsecfwd_app_sys_LDADD := rt
ipsecfwd_app_LDFLAGS := $(LIBXML2_LDFLAGS) $(LIBEDIT_LDFLAGS) \
	-T $(TOP_LEVEL)/apps/ppac/ppac.lds
