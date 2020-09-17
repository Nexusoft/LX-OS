/** NexusOS: allocation for device drivers 
             Nexus uses Linux sk_buffs, 
	     this file translates between skbs and data pages */

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/net.h>

#ifdef NEXUS_UDRIVER	// userspace driver
#include <nexus/devicecompat.h>
#include <linux/string.h>
#else			// kernel driver
#include <linux/skbuff.h>
#include <asm/atomic.h>
#endif

#define PAGE_LENSTART	(PAGESIZE - sizeof(unsigned short))
#define PAGE_SKBSTART   (PAGE_LENSTART - sizeof(struct QItem) \
	               	               - sizeof(struct sk_buff))
#define PAGE_DATAEND 	(PAGE_SKBSTART - sizeof(struct skb_shared_info) - 1)

/** Initialize a memory page as sk_buff */
void *
nxnet_init_skb(void *data, unsigned long paddr)
{
  struct sk_buff *skb;
  struct skb_shared_info *shinfo;

#if NXCONFIG_DEVICE_BLIND
  skb = nxcompat_calloc(1, sizeof(*skb));
#else
  skb = data + PAGE_SKBSTART;
  memset(skb, 0, sizeof(struct sk_buff));
#endif

  // set up data pointers
  skb->mac.raw = skb->head = skb->data = skb->tail = data;
  skb->end = data + PAGE_DATAEND;
  skb->real_dev = (void*) paddr;	// embed phys. address in unused field

  // set up other variables
  atomic_set(&skb->users, 1);
#if !NXCONFIG_DEVICE_BLIND
  skb->len = nxnet_page_getlen(data);
#endif
  skb->cloned = 0;
  skb->data_len = 0;

  // set up shared mem structure
  shinfo = skb_shinfo(skb);
#if !NXCONFIG_DEVICE_BLIND
  memset(shinfo, 0, sizeof(*shinfo));
  atomic_set(&shinfo->dataref, 1);
#endif

  return skb;
}

/** Allocate an skb, try a slab cache first */
struct sk_buff *
alloc_skb(unsigned int size, int gfp_mask) 
{
  void *page;
  unsigned long paddr;

  if (size > PAGE_DATAEND + 1) {
    nxcompat_printf("[skb] allocation request too large\n");
    return NULL;
  }

  page = nxnet_alloc_page();
#ifdef __NEXUSKERNEL__
  paddr = fast_virtToPhys_locked(curt->ipd->map, (unsigned long) page, 1, 1);
#else
  paddr = Mem_GetPhysicalAddress(page, PAGE_SIZE);
#endif
  return nxnet_init_skb(page, paddr);
}

#ifndef __NEXUSKERNEL__
/** Like alloc_skb, but also return the physical address.
    Uses protected kernel pages, to blind the driver to packet contents */
struct sk_buff *
alloc_skb_ex(unsigned int size, int gfp_mask, unsigned long *paddr) 
{
  unsigned long vaddr;

  if (size > PAGE_DATAEND + 1) {
    nxcompat_printf("[skb] allocation request too large\n");
    return NULL;
  }

  vaddr = Device_mem_alloc(1, paddr);
  return nxnet_init_skb((void *) vaddr, *paddr);
}
#endif

void 
free_skb(struct sk_buff * skb) 
{
  void *page;
  
#if NXCONFIG_DEVICE_BLIND
  if (skb->head)
  	nxnet_free_page(skb->head);
  nxcompat_free(skb);
#else
  page = (void*) (((unsigned long) skb) & ~(PAGESIZE - 1));
  nxnet_free_page(page);
#endif
}

void 
__kfree_skb(struct sk_buff *skb)
{
  free_skb(skb);
}

#ifdef __NEXUSKERNEL__

#define SKB_MAXSTACKLEN 32
static struct sk_buff *skbstack[SKB_MAXSTACKLEN];
static int skbstack_off;

/** Replenish queue
    Only up until half full, to leave room for free_skb_int */
void
prealloc_skb_int(void)
{
	int i, lvl;
	
	lvl = disable_intr();
	while (skbstack_off < SKB_MAXSTACKLEN >> 1)
		skbstack[skbstack_off++] = alloc_skb(0, 0); // fairly arbitrary parameters
	restore_intr(lvl);
}

/** Return an skbuff without sleeping: callable in interrupt context 
    Requires preallocation with prealloc_skb_int

    NOT multithread safe (nor needed: run with interrupts disabled)
 */
struct sk_buff *
alloc_skb_int(void)
{
	struct sk_buff *skb;
	int lvl;

	lvl = disable_intr();
	if (!skbstack_off) {
		printk_red("Warning: allocation in interrupt context. XXX fix\n");
		prealloc_skb_int();	// better not be in interrupt ctx
	}

	skb = skbstack[--skbstack_off];
	restore_intr(lvl);
	
	return skb;
}

void
free_skb_int(struct sk_buff *skb)
{
#if 0
	int lvl;
	
	lvl = disable_intr();
	if (skbstack_off < SKB_MAXSTACKLEN)
		skbstack[skbstack_off++] = skb;
//	else
//		printk_red("[net] page lost\n");
	restore_intr(lvl);
#else
  // HACK: may not sleep in interrupt. skip locking and free directly
  // XXX fix properly: should never try to free in interrupt!
extern int Map_remove(Map *m, unsigned int vaddr);
unsigned int page;

  page =  (((unsigned long) skb) & ~(PAGESIZE - 1));
  Map_remove(kernelMap, page);
#endif
}

#else
struct sk_buff *
alloc_skb_int(void)
{
	return alloc_skb(0, 0);
}

void
free_skb_int(struct sk_buff *skb)
{
	free_skb(skb);
}
#endif

