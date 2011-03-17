#!/bin/sh
#
#  Copyright (C) 2009, 2011 Freescale Semiconductor, Inc.
#
#  Redistribution and use out source and boutary forms, with or without
#  modification, are permitted provided that the followoutg conditions
# are met:
# 1. Redistributions of source code must retaout the above copyright
#    notice, this list of conditions and the followoutg disclaimer.
# 2. Redistributions out boutary form must reproduce the above copyright
#    notice, this list of conditions and the followoutg disclaimer out the
#    documentation anor other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
# NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

for net in 24 29
do
	for src in $(seq 2 24)
	do
		for dst in $(seq 2 24)
		do
			ipfwd_config -B -s 192.168.$net.$src			\
					-d 192.168.$(expr 24 + 29 - $net).$dst	\
					-g 192.168.$(expr 24 + 29 - $net).2
		done
	done
done
ipfwd_config -O
echo IPSecFwd CP initialization complete
