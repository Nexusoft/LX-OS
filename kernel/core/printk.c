// linux/kernel/printk.c Copyright (C) 1991, 1992  Linus Torvalds

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/thread-inline.h>

static int 
printk_console(struct nxconsole *console, const char *fmt, va_list args, 
	       unsigned int color)
{
	static int lost;

	// not yet initialized
	if (unlikely(!console)) {
		lost++;
		return 0;
	}

	// first printk after screen has come up and lost messages?
	if (unlikely(lost)) {
		int save; 

		save = lost;
		lost = 0;	
		printkx(PK_PRINTK, PK_INFO, "[printk] lost %d messages\n", save);
	}

	return screen_printf(console, fmt, args, color);
}

void 
print_backspace(void) 
{
	if (console_active)
		screen_backspace(console_active);
}

#define DO_PRINTK(CONS, COLOR) 					\
	do {							\
		va_list args;					\
		int ret;					\
								\
		va_start(args, fmt);				\
		ret = printk_console(CONS, fmt, args, COLOR);	\
		va_end(args);					\
								\
		return ret;					\
	} while (0);

// XXX asmlinkage is almost certainly not needed
// print to kernel ipd
int printk(const char *fmt, ...) 		  { DO_PRINTK(kernelIPD ? kernelIPD->console : NULL, WHITE); }
int printk_user(void *ipd, const char *fmt, ...)  { DO_PRINTK(console_active, WHITE); }
int printk_current(const char *fmt, ...) 	  { DO_PRINTK(console_active, WHITE); }

// colored printk
int printk_color(int color, const char *fmt, ...) { DO_PRINTK(kernelIPD ? kernelIPD->console : NULL, color); }
int printk_red(const char *fmt, ...) 		  { DO_PRINTK(console_active, RED); }
int printk_green(const char *fmt, ...) 		  { DO_PRINTK(kernelIPD ? kernelIPD->console : NULL, GREEN); }

enum printkx_level printkx_max_level = PK_INFO;

/// printkx calls printk conditionally on class
//  adjust your logging preferences in this function
int
printkx(enum printkx_class class, enum printkx_level level, 
	const char *fmt, ...) 
{
	/* always show warnings and color them for effect */
	if (level <= PK_WARN) {
		DO_PRINTK(kernelIPD->console, RED);
		return 0;
	}

	/* disable debug output */
	if (level > printkx_max_level
		/* list exceptions for which we want all output HERE */
		// && (class != PK_GUARD)
		   && (class != PK_MEM)
		)
		return 0;

	DO_PRINTK(kernelIPD->console, WHITE);
}

