/** Nexus OS: various simple definitions for kernelspace code 
 *
 * This file contains globally used function definitions
 *
 * Note the words "globally" and "used" in the above. Please don't put stuff here
 * unless it is (a) used more than once, preferrably many times, and (b) used by
 * more than a single file, preferrably widely used in many files.
 *
 * Don't include this file directly. Include <nexus/defs.h> instead
 */


#ifndef DEFS_H
#define DEFS_H

#include <linux/config.h>
#include <linux/types.h>	// for u64, etc.
#include <linux/string.h>	// for memcpy, etc.
#include <linux/linkage.h>	// for asmlinkage, etc.

#include <asm/io.h>			// for inb, outb

#include <nexus/typedefs.h>
#include <nexus/galloc.h>
#include <nexus/segments.h>
#include <nexus/log.h>
#include <nexus/timing.h>
#include <nexus/printk.h>

void sha1(const char *data, size_t size, char *digest);

extern char nexustime_page[];
#define NEXUSTIME_KVADDR ((unsigned int)(nexustime_page))

#define nmin(a, b) ((a<=b) ? (a) : (b))
#define nmax(a, b) ((a<b) ? (b) : (a))
#define round(a, b)  (((unsigned int)(a/b))*b)

void machine_restart(void);
void nexuspanicfn(const char *filename, int line);
#define nexuspanic() 							\
	do { 								\
		printk_current("panic'ing at %s: %d ", __FILE__, __LINE__); \
		nexuspanicfn(__FILE__,__LINE__);			\
	} while(0)

void assertlf(int linenum, const char *file);
#ifdef assert
#error "assert already defined"
#endif

#ifndef NDEBUG
#define assert(x) 							\
	do { 								\
		if (unlikely(!(x))) 					\
			assertlf( __LINE__, __FILE__); 			\
	} while(0)
#else
#define assert(x) do { 							\
		/* XXX remove the entire statement from codepath */	\
		/*if (unlikely(!(x))) 					\
			; */						\
	} while (0)
#endif
#define ASSERTNOTREACHED() assert(0)

#define NEXUSBOOTNUM get_bootnum()
unsigned int get_bootnum(void);

#include <nexus/config.h>

static inline char *strdup(const char *str) {
  char *rv = galloc(strlen(str) + 1);
  strcpy(rv, str);
  return rv;
}

int nxshell_execute(int argc, char **argv);

struct BasicThread;

#define KERNEL_IPD_ID (0)
extern IPD *kernelIPD;

int shell_init(void);
int keyboard_init(void);
void syscall_init(void);
void pci_init(void);
int vesafb_init(void);
int vesafb_setup(char *options);
void kernelfs_init(void);
void cache_init(void);
void net_init(void);
struct InterruptState;

extern unsigned long nexus_max_pfn;

// Xen Machine-to-physical table, maps frame number
// ( no << PAGE_SHIFT) to physical frame number (no << PAGE_SHIFT)
extern u32 *machine_to_phys;

#endif

