/*
 * arch/i386/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */
#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/devicelog.h>

void * __ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags, int ioremap_protect)
{
	unsigned long last_addr;
	unsigned int vaddr;

	//printk("ioremap 0x%x, %d\n", phys_addr, size);

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	/*
	 * Don't remap the low PCI/ISA area, it's always mapped..
	 */
	if (phys_addr >= 0xA0000 && last_addr < 0x100000){
	  printk("io remapping PCI/ISA area 0x%lx!!\n", phys_addr);
	  //XXX return a pointer to virtual address
	  nexus_leds(7);
	  nexuspanic();
	}

	//XXX is it already mapped and getting mapped again or what?
	vaddr = remap_physical_pages(kernelMap, phys_addr, size, 1, 0);
	printk("mapped 0x%lx to 0x%x\n", phys_addr, vaddr);

	if(ioremap_protect)
	  //if(0)
	  kernel_log_region_add(vaddr, size);

	flushglobalTLB();

	return (void *)vaddr;
}
void iounmap(void *addr)
{
  //XXX DAN: implement this
  kernel_log_region_dump_logs();
  printk("iounmap\n");
  nexuspanic();
#if 0
	if (addr > high_memory)
		return vfree((void *) (PAGE_MASK & (unsigned long) addr));
#endif
}

