/* Nexus OS
   Global definitions header. 

   Only put truly global definitions in here. Place user- or kernel-only 
   definitions in the __defs.h files in their include directories.
 */

#ifndef NEXUS_DEFS_H
#define NEXUS_DEFS_H

#ifdef __NEXUSKERNEL__
#include <stdarg.h>
#include <nexus/__defs.h>
#include <nexus/galloc.h>
#else
/* create a user/include/nexus/__defs.h when needed */
#endif

/* note that machinestructs defines the PAGE_SIZE that is
   actually used in the kernel. XXX: use that instead */
#ifndef PAGESIZE
#define PAGESIZE (4096)
#endif

/* default virtual memory offsets */
#define USERSUPERVISORBEGIN  0xA0000000
#define USERMMAPBEGIN  0x40000000
#define USERHEAPBEGIN  0x10000000

/* minimal required compatibility for code in common 
   give each symbol a nxcompat_ prefix to distinguish it
 */
#ifdef __NEXUSKERNEL__
#define nxcompat_alloc 			galloc
#define nxcompat_calloc 		gcalloc
#define nxcompat_realloc 		grealloc
#define nxcompat_free  			gfree
#define nxcompat_printf			printk
#define nxcompat_fprintf(fstream, ...)	printk(__VA_ARGS__)	
#else
#define nxcompat_alloc 			malloc
#define nxcompat_calloc 		calloc
#define nxcompat_realloc 		realloc
#define nxcompat_free  			free
#define nxcompat_printf			printf
#define nxcompat_fprintf		fprintf

// XXX remove all traces of these calls in shared code
#define galloc				malloc
#define gfree				free
#define printk				printf
#ifndef printk_red
#define printk_red(S, ...) printf("RED" S, ## __VA_ARGS__)
#endif

#endif

/* common macros to give gcc branching hints.
 
   use sparingly: only optimize code that truly needs it.
   remember Knuth's statement about premature optimization */

#ifdef __GNUC__
#define likely(x)     __builtin_expect((x),1)
#define unlikely(x)   __builtin_expect((x),0)
#else
#define likely(x)	(x)
#define unlikely(x)	(x)
#endif

#endif /* NEXUS_DEFS_H */

