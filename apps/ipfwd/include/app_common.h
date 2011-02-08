/*
 \file app_common.h
 \brief Contains macros and inline functions common to all applications
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

#ifndef _APP_COMMON_H
#define _APP_COMMON_H

#include <stdbool.h>
/*
 * \brief  LOG Levels for printing messages
 * \detail LOG_LEVEL needs to be set in the application
 * before including this file. If not set than
 * a default value of 4 is assumed.
 */

#ifndef LOG_LEVEL
#define LOG_LEVEL 2		/**< Default Log Level */
#endif

#define IDENTITY_MAPPING
/**< For Performance keep identity mapping of virtual and phys addresses*/
#define PRINT_INFO		/**< Info Print level is always ON */
#if (LOG_LEVEL > 4)
#define APP_PRINT(args...)    printf(args)
#else
#define APP_PRINT(args...)
#endif

#if (LOG_LEVEL > 3)
#define APP_DEBUG     printf
#else
#define APP_DEBUG(args...)
#endif

#if (LOG_LEVEL > 2)
#define APP_WARN    printf
#else
#define APP_WARN(args...)
#endif

#if (LOG_LEVEL > 1)
#define APP_ERROR   printf
#else
#define APP_ERROR(args...)
#endif

#ifdef PRINT_INFO
#define APP_INFO   printf
#else
#define APP_INFO(args...)
#endif

/* To Enable Hexdump */
/* #define HEXDUMP_ENABLE */

#ifdef HEXDUMP_ENABLE
#define HEXDUMP(ptr, size) hexdump(ptr, size)
#else
#define HEXDUMP(ptr, size)
#endif

#define MAGIC(n) do {                                           \
	__asm__ __volatile__ ("rlwimi %0,%0,0,%1,%2"             \
				:: "i" (((n) >> 10) & 0x1f),       \
				"i" (((n) >>  5) & 0x1f),       \
				"i" (((n) >>  0) & 0x1f));      \
} while (0)

#define MAGIC_BREAKPOINT MAGIC(0)

#define JIFFY_PER_SEC           (100)	/**< Number of Jiffies per second */

#define CPU_JIFFY_CYCLES        (CPU_HZ / JIFFY_PER_SEC)
/**< Calculates Cycles per jiffy */

#define CPU_JIFFY_MASK          (32 - (__builtin_clz(CPU_JIFFY_CYCLES) - 1))
/**< Mask for reading only the bits that would change when a jiffy passes */

#define MAX_NUM_BMAN_POOLS 64
#define CACHE_LINE_SIZE 64
#endif /* APP_COMMON__H */
