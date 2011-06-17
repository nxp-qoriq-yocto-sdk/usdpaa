#!/bin/sh

# Copyright (c) 2010 Freescale Semiconductor, Inc.
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

# Determine where the top-level bsp.git directory is
TOPDIR="`dirname $0`/.."

# API headers
#INCL="fsl_qman.h fsl_bman.h fsl_pme.h"
INCL="fsl_qman.h fsl_bman.h"

# source files
QMAN="qman_high.c qman_low.h qman_private.h qman_utility.c qman_fqalloc.c"
BMAN="bman_high.c bman_low.h bman_private.h"
#PME2="pme2_high.c pme2_low.c pme2_private.h"

# Location of files in linux
LIN_INCL=$TOPDIR/linux-2.6/include/linux
LIN_BMAN=$TOPDIR/linux-2.6/drivers/staging/fsl_qbman
LIN_QMAN=$TOPDIR/linux-2.6/drivers/staging/fsl_qbman
#LIN_PME2=$TOPDIR/linux-2.6/drivers/staging/fsl_pme2

# Location of files in usd
LWE_INCL=$TOPDIR/usdpaa/include/usdpaa
LWE_BMAN=$TOPDIR/usdpaa/drivers/qbman
LWE_QMAN=$TOPDIR/usdpaa/drivers/qbman
#LWE_PME2=$TOPDIR/usdpaa/drivers/pme2

####$#################
# The rest is script #
######################

DIRECTION=""
IS_STAT="no"
IS_DIFF="no"
IS_MELD="no"
IS_FORCE="no"
CP_UPDATE="--update"

usage () {
	echo "Usage:"
	echo "	dpasync.sh <stat|diff|meld|force> <2linux|2usd>"
	exit 1
}

parse_direction() {
	if [ $1 = "2linux" ]; then
		SRC_INCL=$LWE_INCL
		SRC_BMAN=$LWE_BMAN
		SRC_QMAN=$LWE_QMAN
		#SRC_PME2=$LWE_PME2
		DST_INCL=$LIN_INCL
		DST_BMAN=$LIN_BMAN
		DST_QMAN=$LIN_QMAN
		#DST_PME2=$LIN_PME2
	elif [ $1 = "2usd" ]; then
		SRC_INCL=$LIN_INCL
		SRC_BMAN=$LIN_BMAN
		SRC_QMAN=$LIN_QMAN
		#SRC_PME2=$LIN_PME2
		DST_INCL=$LWE_INCL
		DST_BMAN=$LWE_BMAN
		DST_QMAN=$LWE_QMAN
		#DST_PME2=$LWE_PME2
	else
		usage
	fi
}

if [ $# -lt 1 ]; then
	usage
fi

if [ $1 = "stat" ]; then
	if [ $# -ne 2 ]; then
		usage
	fi
	parse_direction $2
	IS_STAT="yes"
elif [ $1 = "diff" ]; then
	if [ $# -ne 2 ]; then
		usage
	fi
	parse_direction $2
	IS_DIFF="yes"
elif [ $1 = "meld" ]; then
	if [ $# -ne 2 ]; then
		usage
	fi
	parse_direction $2
	IS_MELD="yes"
elif [ $1 = "force" ]; then
	if [ $# -ne 2 ]; then
		usage
	fi
	parse_direction $2
	IS_FORCE="yes"
	CP_UPDATE=""
else
	if [ $# -ne 1 ]; then
		usage
	fi
	parse_direction $1
fi

mycmp() {
	if cmp $1 $2 > /dev/null 2>&1; then
		R=0
	else
		R=1
	fi
	return $R
}

mymeld() {
	DONE="no"
	while [ $DONE = "no" ];
	do
		read -e -p "Examine? (Y/y/N/n/Q/q) "
		if [ $REPLY = "Y" -o $REPLY = "y" ]; then
			meld $1 $2
			DONE="yes"
		elif [ $REPLY = "N" -o $REPLY = "n" ]; then
			DONE="yes"
		elif [ $REPLY = "Q" -o $REPLY = "q" ]; then
			exit 0
		fi
	done
}

process () {
	S=$1
	D=$2
	SS=`basename $S`
	if [ ! -f $S ]; then
		echo "Bad: source file $SS doesn't exist"
		exit 1
	fi
	if [ ! -f $D ]; then
		if [ $IS_DIFF = "yes" ]; then
			echo "New file: $S"
		elif [ $IS_DIFF = "yes" ]; then
			echo "New file: $S" >&2
			diff -u /dev/null $S
		elif [ $IS_MELD = "yes" ]; then
			echo "New file: $S" >&2
			mymeld /dev/null $S
		else
			echo "New: copying $SS"
			cp -a $S $D || exit 1
		fi
	elif mycmp $S $D; then
		if [ $IS_DIFF = "yes" -o $IS_MELD = "yes" ]; then
			echo "File match: $S" >&2
		else
			echo "OK: $SS unchanged"
		fi
	else
		if [ $IS_STAT = "yes" ]; then
			echo "File change: $S"
		elif [ $IS_DIFF = "yes" ]; then
			echo "File change: $S" >&2
			# for diff, we want to see changes in the source
			# relative to the destination, hence the apparently
			# counter-intuitive order of parameters.
			diff -u $D $S
		elif [ $IS_MELD = "yes" ]; then
			echo "File change: $S" >&2
			mymeld $S $D
		else
			echo "Updated: copying $SS"
			cp $CP_UPDATE $S $D || exit 1
			if ! mycmp $S $D; then
				echo "Bad: dest file $SS newer than source"
				exit 1
			fi
		fi
	fi
}

for i in $INCL; do
	process $SRC_INCL/$i $DST_INCL/$i
done

for i in $BMAN; do
	process $SRC_BMAN/$i $DST_BMAN/$i
done

for i in $QMAN; do
	process $SRC_QMAN/$i $DST_QMAN/$i
done

#for i in $PME2; do
#	process $SRC_PME2/$i $DST_PME2/$i
#done
#
