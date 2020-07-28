#ifndef _NAL_H_

#include <stdarg.h>
#include <nexus/defs.h>

#ifdef __NEXUSKERNEL__
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <nexus/formula.h>
#include <nexus/hashtable.h>
#include <nexus/galloc.h>
#include <nexus/user_compat.h>

/* all of the following are here to make bison and flex generated code
 * compile in the kernel 
 */

#define YYMALLOC  nxcompat_alloc
#define YYFREE    nxcompat_free
#define YYFPRINTF fprintf

#ifndef fprintf
#define kernel_printf printk
#define fprintf(file, ...)  printk(__VA_ARGS__)
#define stdin NULL
#define stdout NULL
#define stderr NULL
#define EOF (-1)
typedef int FILE;

static int errno;
#define ENOMEM 1
#define EINVAL 2
#define exit(val) nexuspanic()
#define strtol simple_strtol

#endif /* !fprintf */

#define YYCOPY memcpy

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <nexus/formula.h>
#include <nexus/hashtable.h>

#endif

#include "NAL.tab.h"
#include <nexus/NAL_parser_internal.h>

#endif // _NAL_H_
