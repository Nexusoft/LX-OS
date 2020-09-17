/** NexusOS: network packet allocation

    Nexus uses pages as packet buffers.

    To interoperate with linux device drivers, we have to save space
    for sharedinfo and skb Careful. Some NICs like e1000 (VMware's,
    and some revs of the hardware) overwrite the end of their buffer.
    This is fine under Linux because the requested buffer size (2050)
    is rounded up to the next highest power of 2 by the slab allocator.
    This code gets around the problem by always allocating a 4KB SKB

    We also append on the page itself 
    - the skbuff header, 
    - a hook for the page queue
    - a length field (the only metadata used by Nexus)

    Final page layout is:

    	[eth][rest of packet..] ... [skb_shared_info][sk_buff][qitem][16b len]

    UPDATE 2010-12-21: to support blind drivers that lack access to their data
                       pages, we had to move skb's out of the datapage
 */

#ifdef __NEXUSKERNEL__
#include <nexus/synch-inline.h>
#include <nexus/user_compat.h>
#else
#include <stdio.h>
#include <string.h>
#include <nexus/sema.h>
#endif

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/machine-structs.h>
#include <nexus/Mem.interface.h>

#ifndef PAGE_SIZE
#error "page size definition is missing"
#endif

void *
nxnet_alloc_page(void)
{
  void *page = NULL;

#ifdef __NEXUSKERNEL__
  page = (void *) Map_alloc(kernelMap, 1, 1, 0, vmem_kernel);
#else
  page = (void *) Mem_GetPages(1, 0);
#endif
    
  if (!page)
    nxcompat_fprintf(stderr, "[skb] allocation failed\n");
 
  return page;
}

void
nxnet_free_page(void *vaddr)
{
#ifdef __NEXUSKERNEL__
  Map_free(kernelMap, (unsigned long) vaddr, 1);
#else
  Mem_FreePages((unsigned long) vaddr, 1);
#endif
}

/** embed the length parameter */
void
nxnet_page_setlen(void *page, unsigned short len)
{
  *(unsigned short *) (page + PAGE_SIZE - sizeof(unsigned short)) = len;
}

unsigned short
nxnet_page_getlen(void *page)
{
  return *(unsigned short *) (page + PAGE_SIZE - sizeof(unsigned short));
}

