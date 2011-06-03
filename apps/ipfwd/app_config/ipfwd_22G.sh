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

ipfwd_config -F -a 192.168.60.1 -i 5
ipfwd_config -F -a 192.168.130.1 -i 8
ipfwd_config -F -a 192.168.140.1 -i 9
ipfwd_config -F -a 192.168.160.1 -i 11

ipfwd_config -G -s 192.168.60.2 -m 02:00:c0:a8:3c:02 -r true
ipfwd_config -G -s 192.168.130.2 -m 02:00:c0:a8:82:02 -r true
ipfwd_config -G -s 192.168.140.2 -m 02:00:c0:a8:8c:02 -r true
ipfwd_config -G -s 192.168.160.2 -m 02:00:c0:a8:a0:02 -r true

# $1, $2	- Subnets as in 192.168.$1.* and 192.168.$2.*
# $3		- Number of sources
# $4		- Number of destinations
net_pair_routes()
{
	for net in $1 $2
	do
		for src in $(seq 2 $(expr $3 + 1))
		do
			for dst in $(seq 2 $(expr $4 + 1))
			do
				ipfwd_config -B -s 192.168.$net.$src			\
						-d 192.168.$(expr $1 + $2 - $net).$dst	\
						-g 192.168.$(expr $1 + $2 - $net).2
			done
		done
	done
}

case $(basename $0 .sh) in
	ipfwd_22G)				# 1008
		net_pair_routes 130 140	 6  7	# 2 *  6 *  7 =	 84
		net_pair_routes	 60 160 21 22	# 2 * 21 * 22 = 924
		;;
	ipfwd_20G)				# 1012
		net_pair_routes 60 160 22 23	# 2 * 22 * 23 = 1012
		;;
esac
ipfwd_config -O
echo IPSecFwd CP initialization complete
