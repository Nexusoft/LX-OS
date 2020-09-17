/*
 *  linux/arch/i386/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Enhanced CPU type detection by Mike Jagdis, Patrick St. Jean
 *  and Martin Mares, November 1997.
 *
 *  Force Cyrix 6x86(MX) and M II processors to report MTRR capability
 *  and Cyrix "coma bug" recognition by
 *      Zoltán Böszörményi <zboszor@mail.externet.hu> February 1999.
 *
 *  Force Centaur C6 processors to report MTRR capability.
 *      Bart Hartgers <bart@etpmod.phys.tue.nl>, May 1999.
 *
 *  Intel Mobile Pentium II detection fix. Sean Gilley, June 1999.
 *
 *  IDT Winchip tweaks, misc clean ups.
 *	Dave Jones <davej@suse.de>, August 1999
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *
 *  Better detection of Centaur/IDT WinChip models.
 *      Bart Hartgers <bart@etpmod.phys.tue.nl>, August 1999.
 *
 *  Memory region support
 *	David Parsons <orc@pell.chi.il.us>, July-August 1999
 *
 *  Cleaned up cache-detection code
 *	Dave Jones <davej@suse.de>, October 1999
 *
 *	Added proper L2 cache detection for Coppermine
 *	Dragan Stancevic <visitor@valinux.com>, October 1999
 *
 *  Added the original array for capability flags but forgot to credit
 *  myself :) (~1998) Fixed/cleaned up some cpu_model_info and other stuff
 *  	Jauder Ho <jauderho@carumba.com>, January 2000
 *
 *  Detection for Celeron coppermine, identify_cpu() overhauled,
 *  and a few other clean ups.
 *  Dave Jones <davej@suse.de>, April 2000
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 *
 *  Added proper Cascades CPU and L2 cache detection for Cascades
 *  and 8-way type cache happy bunch from Intel:^)
 *  Dragan Stancevic <visitor@valinux.com>, May 2000
 *
 *  Forward port AMD Duron errata T13 from 2.2.17pre
 *  Dave Jones <davej@suse.de>, August 2000
 *
 *  Forward port lots of fixes/improvements from 2.2.18pre
 *  Cyrix III, Pentium IV support.
 *  Dave Jones <davej@suse.de>, October 2000
 *
 *  Massive cleanup of CPU detection and bug handling;
 *  Transmeta CPU detection,
 *  H. Peter Anvin <hpa@zytor.com>, November 2000
 *
 *  Added E820 sanitization routine (removes overlapping memory regions);
 *  Brian Moyle <bmoyle@mvista.com>, February 2001
 *
 *  VIA C3 Support.
 *  Dave Jones <davej@suse.de>, March 2001
 *
 *  AMD Athlon/Duron/Thunderbird bluesmoke support.
 *  Dave Jones <davej@suse.de>, April 2001.
 *
 *  CacheSize bug workaround updates for AMD, Intel & VIA Cyrix.
 *  Dave Jones <davej@suse.de>, September, October 2001.
 *
 *  Provisions for empty E820 memory regions (reported by certain BIOSes).
 *  Alex Achenbach <xela@slit.de>, December 2002.
 *
 */

/*
 * This file handles the architecture-dependent parts of initialization
 */
#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/idtgdt.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/initrd.h>
#include <nexus/multiboot.h>
#include <nexus/video.h>
#include <linux/pci.h>
#include <asm/e820.h>


/*
 * Machine setup..
 */

struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

unsigned long mmu_cr4_features;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x10000000;

#define __initdata
#define __init

/*
 * Setup options
 */
struct screen_info screen_info;

struct e820map e820;

static void __init add_memory_region(unsigned long long start,
                                  unsigned long long size, int type)
{
	int x = e820.nr_map;

	if (x == E820MAX) {
	    printk(KERN_ERR "Ooops! Too many entries in the memory map!\n");
	    return;
	}

	e820.map[x].addr = start;
	e820.map[x].size = size;
	e820.map[x].type = type;
	e820.nr_map++;
} /* add_memory_region */

/*
 * Copy the BIOS e820 map into a safe place.
 *
 * Sanity-check it while we're at it..
 *
 * If we're lucky and live on a modern system, the setup code
 * will have given us a memory map that we can use to properly
 * set up memory.  If we aren't, we'll fake a memory map.
 *
 * We check to see that the memory map contains at least 2 elements
 * before we'll use it, because the detection code in setup.S may
 * not be perfect and most every PC known to man has two memory
 * regions: one from 0 to 640k, and one from 1mb up.  (The IBM
 * thinkpad 560x, for example, does not cooperate with the memory
 * detection code.)
 */
static int __init copy_e820_map(multiboot_info_t *mbi)
{
	multiboot_memory_map_t *biosmap;

	for (biosmap = (multiboot_memory_map_t *)mbi->mmap_addr; 
	     biosmap < mbi->mmap_addr + mbi->mmap_length; 
		 biosmap = (multiboot_memory_map_t *)((unsigned long)
		           biosmap + biosmap->size + sizeof(biosmap->size))) {
		unsigned long long start = biosmap->addr;
		unsigned long long size = biosmap->len;
		unsigned long long end = start + size;
		unsigned long type = biosmap->type;

		/* Overflow in 64 bits? Ignore the memory map. */
		if (start > end)
			return -1;

		/*
		 * Some BIOSes claim RAM in the 640k - 1M region.
		 * Not right. Fix it up.
		 */
		if (type == E820_RAM) {
			if (start < 0x100000ULL && end > 0xA0000ULL) {
				if (start < 0xA0000ULL)
					add_memory_region(start, 0xA0000ULL-start, type);
				if (end <= 0x100000ULL)
					continue;
				start = 0x100000ULL;
				size = end - start;
			}
		}
		add_memory_region(start, size, type);
	}
	/* Only one memory region (or negative)? Ignore it */
	if (e820.nr_map < 2)
		return -1;
	return 0;
}

static void __init setup_memory_region(multiboot_info_t *mbi)
{
	char *who = "BIOS-e820";

	if (!CHECK_FLAG(mbi->flags,6))
		nexuspanic();

	/*
	 * Try to copy the BIOS-supplied E820-map.
	 *
	 * Otherwise fake a memory map; one section from 0k->640k,
	 * the next section from 1mb->appropriate_mem_k
	 */
	if (copy_e820_map(mbi) < 0) {
		e820.nr_map = 0;
		// let's try with multiboot
		add_memory_region(0, mbi->mem_lower << 10, E820_RAM);
		add_memory_region(HIGH_MEMORY, mbi->mem_upper << 10, E820_RAM);
  	}

} /* setup_memory_region */

/* mbi is valid when passed in */
void __init setup_arch(char **cmdline_p, multiboot_info_t *mbi)
{
	// commandline arguments are no longer supported (April 24, 2010)
	if (cmdline_p)
		nexuspanic();

	if (CHECK_FLAG(mbi->flags,12)) {
		/* the only non-vesa field actually used
		 * we cheat here because it's always vesa mode ?
		 */
		screen_info.orig_video_isVGA = VIDEO_TYPE_VLFB;
		
		screen_info.lfb_width = mbi->framebuffer_width;
		screen_info.lfb_height = mbi->framebuffer_height;
		screen_info.lfb_depth = mbi->framebuffer_bpp;
		screen_info.lfb_base = mbi->framebuffer_addr;
		screen_info.lfb_linelength = mbi->framebuffer_pitch;

		/* only RGB supported */
		if (mbi->framebuffer_type != MULTIBOOT_FRAMEBUFFER_TYPE_RGB)
			nexuspanic();	

		screen_info.red_size = mbi->framebuffer_red_mask_size;
		screen_info.red_pos = mbi->framebuffer_red_field_position;
		screen_info.green_size = mbi->framebuffer_green_mask_size;
		screen_info.green_pos = mbi->framebuffer_green_field_position;
		screen_info.blue_size = mbi->framebuffer_blue_mask_size;
		screen_info.blue_pos = mbi->framebuffer_blue_field_position;

		// the rest of the fields are not used or unavailable from multiboot
	}

	setup_memory_region(mbi);
}

