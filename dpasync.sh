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
QBMAN="qman_high.c qman_low.h qman_private.h qman_utility.c bman_high.c bman_low.h bman_private.h"
#PME2="pme2_high.c pme2_low.c pme2_private.h"

# Location of files in linux
LIN_INCL=$TOPDIR/linux/include/linux
LIN_QBMAN=$TOPDIR/linux/drivers/staging/fsl_qbman
#LIN_PME2=$TOPDIR/linux/drivers/staging/fsl_pme2

# Location of files in usd
LWE_INCL=$TOPDIR/usdpaa/include/usdpaa
LWE_QBMAN=$TOPDIR/usdpaa/drivers/qbman
#LWE_PME2=$TOPDIR/usdpaa/drivers/pme2

####$#################
# The rest is script #
######################

DIRECTION=""
IS_STAT="no"
IS_DIFF="no"
IS_MELD="no"
IS_UPDATE="no"
IS_FORCE="no"
REG_EXP="."
CP_UPDATE="--update"

usage () {
	echo "Usage:"
	echo "	dpasync.sh <stat|diff|meld|update|force> <2linux|2usd> [path-regexp]"
	exit 1
}

parse_direction() {
	if [ $1 = "2linux" ]; then
		SRC_INCL=$LWE_INCL
		SRC_QBMAN=$LWE_QBMAN
		#SRC_PME2=$LWE_PME2
		DST_INCL=$LIN_INCL
		DST_QBMAN=$LIN_QBMAN
		#DST_PME2=$LIN_PME2
	elif [ $1 = "2usd" ]; then
		SRC_INCL=$LIN_INCL
		SRC_QBMAN=$LIN_QBMAN
		#SRC_PME2=$LIN_PME2
		DST_INCL=$LWE_INCL
		DST_QBMAN=$LWE_QBMAN
		#DST_PME2=$LWE_PME2
	else
		usage
	fi
}

if [ $# -lt 2 -o $# -gt 3 ]; then
	usage
elif [ $# -eq 3 ]; then
	REG_EXP="$3"
fi

if [ $1 = "stat" ]; then
	parse_direction $2
	IS_STAT="yes"
elif [ $1 = "diff" ]; then
	parse_direction $2
	IS_DIFF="yes"
elif [ $1 = "meld" ]; then
	parse_direction $2
	IS_MELD="yes"
elif [ $1 = "update" ]; then
	parse_direction $2
elif [ $1 = "force" ]; then
	parse_direction $2
	IS_FORCE="yes"
	CP_UPDATE=""
else
	usage
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
		read -e -p "Examine? (Y/n/q) "
		C="x$REPLY"
		if [ $C = "xY" -o $C = "xy" -o "$C" = "x" ]; then
			meld $1 $2
			DONE="yes"
		elif [ $C = "xN" -o $C = "xn" ]; then
			DONE="yes"
		elif [ $C = "xQ" -o $C = "xq" ]; then
			exit 0
		fi
	done
}

process () {
	S=$1
	D=$2
	SS=`basename $S`
	MATCH=`echo "$SS" | egrep "$REG_EXP" > /dev/null 2>&1 && echo "match"`
	if [ "x$MATCH" = "x" ]; then
		echo "Skipping: $i"
	elif [ ! -f $S ]; then
		echo "Bad: source file $SS doesn't exist"
		exit 1
	elif [ ! -f $D ]; then
		if [ $IS_DIFF = "yes" -o $IS_STAT = "yes" ]; then
			echo "New: $SS"
		elif [ $IS_DIFF = "yes" ]; then
			echo "New: $SS" >&2
			diff -u /dev/null $S
		elif [ $IS_MELD = "yes" ]; then
			echo "New: $SS" >&2
			mymeld /dev/null $S
		else
			echo "New: copying $SS"
			cp -a $S $D || exit 1
		fi
	elif mycmp $S $D; then
		if [ $IS_DIFF = "yes" -o $IS_MELD = "yes" ]; then
			echo "Unchanged: $SS" >&2
		else
			echo "Unchanged: $SS"
		fi
	else
		if [ $IS_STAT = "yes" ]; then
			echo "Changed: $SS"
		elif [ $IS_DIFF = "yes" ]; then
			echo "Changed: $SS" >&2
			# for diff, we want to see changes in the source
			# relative to the destination, hence the apparently
			# counter-intuitive order of parameters.
			diff -u $D $S
		elif [ $IS_MELD = "yes" ]; then
			echo "Changed: $SS" >&2
			mymeld $S $D
		else
			echo "Changed: updating $SS"
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

for i in $QBMAN; do
	process $SRC_QBMAN/$i $DST_QBMAN/$i
done

#for i in $PME2; do
#	process $SRC_PME2/$i $DST_PME2/$i
#done
#
