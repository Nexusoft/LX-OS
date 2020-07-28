/*
 * Dynamic DMA mapping support.
 *
 * On i386 there is no hardware dynamic DMA address translation,
 * so consistent alloc/free are merely page allocation/freeing.
 * The rest of the dynamic DMA mapping interface is implemented
 * in asm/pci.h.
 */

#include <asm/types.h>
//#include <linux/mm.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <asm/io.h>

#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/synch.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#define PCIPAGES 0xa0000000

#define __init
#define __initdata
#define __devinit

//DAN: ret=dd32f000 

void *pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
			   dma_addr_t *dma_handle)
{
	void *ret;
	ret = getKernelPages((size + PAGESIZE - 1)/ PAGESIZE);
	//printk("PCI_ALLOC_CONSISTENT 0x%p %d\n", ret, (size + PAGESIZE - 1)/ PAGESIZE);
	if (ret != NULL) {
	  memset(ret, 0, size);
	  *dma_handle = VIRT_TO_PHYS(ret);
	}

	return ret;
}

void pci_free_consistent(struct pci_dev *hwdev, size_t size,
			 void *vaddr, dma_addr_t dma_handle)
{
  //printk("PCI_FREE_CONSISTENT 0x%p %d\n", (unsigned int)vaddr, (size + PAGESIZE - 1) / PAGESIZE);
  freeKernelPages(vaddr, (size + PAGESIZE - 1) / PAGESIZE);
}
