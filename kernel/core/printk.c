// linux/kernel/printk.c Copyright (C) 1991, 1992  Linus Torvalds

#include <nexus/defs.h>
#include <nexus/ipd.h>
#include <nexus/device.h>
#include <nexus/screen.h>
#include <nexus/thread-inline.h>

static int 
printk_console(IPD *ipd, const char *fmt, va_list args, unsigned int color)
{
	NexusOpenDevice *nod;
	static int lost;

	// not yet initialized
	if (!kernelIPD) {
		lost++;
		return 0;
	}

	// first printk after screen has come up and lost messages?
	if (lost) {
		int save; 

		save = lost;
		lost = 0;	
		printkx(PK_PRINTK, PK_INFO, "[printk] lost %d messages\n", save);
	}

	// find first screen device for the ipd
	nod = ipd_get_open_device(ipd, DEVICE_VIDEO, -1); 
	if (!nod) 
		return 0;

	return screen_printf(nod, fmt, args, color);
}

void 
print_backspace(void *ipd) 
{
	NexusOpenDevice *nod;
       
	nod = ipd_get_open_device((IPD *) ipd, DEVICE_VIDEO, -1); 
	if (nod) 
		screen_backspace(nod);
}

#define DO_PRINTK(IPD, COLOR) 					\
	do {							\
		va_list args;					\
		int ret;					\
								\
		va_start(args, fmt);				\
		ret = printk_console(IPD, fmt, args, COLOR);	\
		va_end(args);					\
								\
		return ret;					\
	} while (0);

// XXX asmlinkage is almost certainly not needed
// print to kernel ipd
int printk(const char *fmt, ...) { DO_PRINTK(kernelIPD, WHITE); }
int printk_user(void *ipd, const char *fmt, ...) { DO_PRINTK(ipd, WHITE); }
int printk_current(const char *fmt, ...) { DO_PRINTK(focus_current_ipd_special(), WHITE); }

// colored printk
int printk_color(int color, const char *fmt, ...) { DO_PRINTK(kernelIPD, color); }
int printk_red(const char *fmt, ...) 		  { DO_PRINTK(kernelIPD, RED); }
int printk_green(const char *fmt, ...) 		  { DO_PRINTK(kernelIPD, GREEN); }

enum printkx_level printkx_max_level = PK_INFO;

/// printkx calls printk conditionally on class
//  adjust your logging preferences in this function
int
printkx(enum printkx_class class, enum printkx_level level, 
	const char *fmt, ...) 
{
	/* always show warnings and color them for effect */
	if (level <= PK_WARN) {
		DO_PRINTK(kernelIPD, RED);
		return 0;
	}

	/* disable debug output */
	if (level > printkx_max_level && 
		/* list exceptions for which we want all output HERE */
		(class != PK_GUARD))
		return 0;

	DO_PRINTK(kernelIPD, WHITE);
}

