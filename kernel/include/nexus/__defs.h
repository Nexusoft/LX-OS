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
#include <nexus/sha1.h>
#include <nexus/printk.h>

extern char nexustime_page[];
#define NEXUSTIME_KVADDR ((unsigned int)(nexustime_page))

#define nmin(a, b) ((a<=b) ? (a) : (b))
#define nmax(a, b) ((a<b) ? (b) : (a))
#define round(a, b)  (((unsigned int)(a/b))*b)

void machine_restart(void);
void nexuspanicfn(const char *filename, int line);
#define nexuspanic() 							\
	do { 								\
		printk_red("panic'ing at %s: %d ", __FILE__, __LINE__); \
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
#define assert(x) do { } while (0)
#error "NDEBUG DEFINED?"
#endif
#define ASSERTNOTREACHED() assert(0)

#define NEXUSBOOTNUM get_bootnum()
unsigned int get_bootnum(void);

#define CHECK_NOT_INTERRUPT() assert(!nexusthread_in_interrupt(nexusthread_self()))



extern int sseOn;


#define DISABLE_TPM (0)
extern int tpm_present;


#define HASH_CTXLEN 100
#define HASH_LEN 20
#define hash_init(ctx) sha1_init(ctx)
#define hash_update(ctx, buf, len) sha1_update(ctx, buf, len)
#define hash_final(ctx, hash) sha1_final(ctx, hash)
void sha1(unsigned char *input, int len, unsigned char *output);

#include <nexus/config.h>

void nexus_blink(void);
void nexus_leds(unsigned int leds);
void nexus_ledson(void);
void nexus_ledsoff(void);

static inline char *strdup(const char *str) {
  char *rv = galloc(strlen(str) + 1);
  strcpy(rv, str);
  return rv;
}

extern unsigned long tsc_per_jiffie;
#define TSCCONST (tsc_per_jiffie)
#define TSC_PER_TICK (TSCCONST * (1000000 / HZ))

//#define RATE_LIMIT_PERIOD (TSCCONST * 1000) // kwalsh: from clock.c
#define RATE_LIMIT_PERIOD (1000000000)
#define RATE_LIMIT(X) \
	do { \
		static unsigned long long last_time; \
		if(rdtsc64() - last_time > RATE_LIMIT_PERIOD) {	\
			X; \
			last_time = rdtsc64(); \
		} \
	} while(0)


// To introduce a kernel shell command, do something like this
//
// int my_function(int ac, char **av) {
//   printk("kthxbye!"); return 0;
// }
//
// DECLARE_SHELL_COMMAND(foo, my_function, "does nothing useful (no args)");
#define DECLARE_SHELL_COMMAND(cmd, fn, desc) \
	shell_cmd_t SHELL_COMMAND_FN_##cmd = fn; \
	char *SHELL_COMMAND_DESC_##cmd = desc

// if a shell function returns BAD_USAGE, shell will try to be helpful
#define BAD_USAGE -1234

// this just breaks up the monotony of the shell help listing
#define DECLARE_SHELL_COMMAND_GROUP(token, name) \
	char *SHELL_COMMAND_GROUP_##token = name

typedef int (*shell_cmd_t)(int argc, char **argv);

int shell(char *cmd);
char *is_known_filehash(char *hash);

struct BasicThread;
void show_thread_stack(struct BasicThread *thread, unsigned long * esp, char *func_skip_name, unsigned long vaddr);
char *guess_thread_place(struct BasicThread *thread, unsigned long * esp);
void show_stack(unsigned long * esp); // dump stack trace
int trace_pause(void); // useful for debugging
void ubreak(void); // useful for gdb connections
void enable_gdb_mode(char *ignored); // useful for gdb connections

#define KERNEL_IPD_ID (0)
extern IPD *kernelIPD;

void shell_init(void);
void fbmem_init(void);
int keyboard_init(void);
int psaux_init(void);
void syscall_init(void);
void pci_init(void);
int vesafb_init(void);
int vesafb_setup(char *options);
int fbcon_show_logo(int x0, int y0);
void kernelfs_init(void);
void cache_init(void);
void debug_init(void);
void interpose_init(void);
void interpose_test_init0(void);
void net_init(void);
int vortex_init(void);
int tg3_init(void);
struct InterruptState;

extern int breakpoint_do_print;
int /* breakpoint index */ breakpoint_add(int type, int size, unsigned long address);
void /* breakpoint index */ breakpoint_del(int index);
void breakpoint_handle_DB(struct InterruptState *is);
void breakpoint_dump_debug_info(void);
void breakpoint_dump_matches(unsigned long address);

extern void (*nexus_clear_screen)(void);

#define SHAMT (28ULL)
#define DO_DELAY(NAME)						\
      do {							\
	printk_red(#NAME " delay at %d\n", nexustime);	\
	u64 i;							\
	for(i=0; i < (1ULL << SHAMT); i++) {			\
	  static volatile int x = 0;				\
	  x++;							\
	}							\
	printk_red("after delay at %d\n", nexustime);		\
      } while(0)

#define REBOOT_SCANCODE (0x01)
extern int num_zapped_low_ptab;

extern unsigned long nexus_max_pfn;

 // Xen Machine-to-physical table, maps frame number
// ( no << PAGE_SHIFT) to physical frame number (no << PAGE_SHIFT)

// It can be mapped in by Xen processes
extern u32 *machine_to_phys;

////////  Various options  ////////

/// note: try using the shell 'ctsc' command to calibrate the tsc -- if that
// command works for everyone, then TSCCONST_DEFAULT will become obsolete
#define TSCCONST_DEFAULT 3000

/// Lookup symbol names for stack traces?
#define PRETTY_STACK_TRACES 1

/// Use <ESC> for "immediate reboot"
#define REBOOT_ON_ESCAPE_KEY 1

#endif

