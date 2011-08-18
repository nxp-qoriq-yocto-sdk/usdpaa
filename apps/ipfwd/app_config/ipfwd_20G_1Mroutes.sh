#!/bin/sh
#
#  Copyright (C) 2011 Freescale Semiconductor, Inc.
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

# Script for creating 1M routes
ipfwd_config -F -a 192.168.24.1 -i 5
ipfwd_config -F -a 192.168.29.1 -i 11

ipfwd_config -G -s 192.168.24.2 -m 02:00:c0:a8:3c:02 -r true
ipfwd_config -G -s 192.168.29.2 -m 02:00:c0:a8:a0:02 -r true

ipfwd_config -B -s  192.168.24.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.25.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.26.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.27.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.28.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.1.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.18.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.30.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.31.2 -c 254 -d  192.168.29.2 -n 254 \
-g 192.168.29.2
ipfwd_config -B -s  192.168.29.2 -c 254 -d  192.168.24.2 -n 254 \
-g 192.168.24.2
ipfwd_config -B -s  192.168.2.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.3.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.4.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.5.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.6.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.17.2 -c 254 -d  192.168.24.2 -n 254 -g 192.168.24.2
ipfwd_config -B -s  192.168.20.2 -c 127 -d  192.168.24.2 -n 127 -g 192.168.24.2
echo IPFwd Route Creation complete
