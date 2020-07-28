/** NexusOS: Self-contained skbuff 

    Some allocators (e.g. dlmalloc()) perform poorly with large 
    numbers of memalign()'ed allocations. So, do our own allocation 
    using Mem_GetPages() 					
 */

#include <asm/bitops.h>
#include <assert.h>
#include <string.h>

#include <nexus/defs.h>
#include <nexus/sema.h>
#include <nexus/device.h>
#include <nexus/nexuseth.h>
#include <nexus/libc-protos.h>
#include <nexus/devicecompat.h>
#include <nexus/Mem.interface.h>

#define FIRST_SKB_HINT (USERMMAPBEGIN)
#define MAX_CACHED_SKB (1000)

Sema free_list_sema = SEMA_MUTEX_INIT;
static struct sk_buff_head free_list; // All buffers are aligned pages
static void *next_skb_hint = (void *) FIRST_SKB_HINT;

struct sk_buff *alloc_skb(unsigned int size, int gfp_mask) {
  static int initialized;

  if(size > PAGESIZE) {
    return NULL;
  }

  P(&free_list_sema);

  if (!initialized) {
    initialized = 1;
    skb_queue_head_init(&free_list);
  }

  struct sk_buff *skb;
  unsigned char *data;

  if(skb_queue_empty(&free_list)) {
    skb = (struct sk_buff *) malloc(sizeof(struct sk_buff));

    // Save space for sharedinfo
    // Careful. Some NICs like e1000 (VMware's, and some revs of the
    // hardware) overwrite the end of their buffer.  This is fine under
    // Linux because the requested buffer size (2050) is rounded up to
    // the next highest power of 2 by the slab allocator.
    // This code gets around the problem by always allocating a 4KB SKB
    data = (unsigned char *) Mem_GetPages(1, (uint32_t) next_skb_hint);

    if (!data) {
      printf("Out of memory while allocating skb\n");
      free(skb);
      V_nexus(&free_list_sema);
      return NULL;
    }

    next_skb_hint = data + PAGESIZE;

  } else {
    skb = __skb_dequeue(&free_list);
    data = skb->head;
  }
  V_nexus(&free_list_sema);
 
  memset(skb, 0, sizeof(struct sk_buff));

  skb->head = skb->data = skb->tail = data;
  skb->end = data + PAGESIZE - sizeof(struct skb_shared_info);

  /* Set up other state */
  atomic_set(&skb->users, 1);
  skb->len = 0;
  skb->cloned = 0;
  skb->data_len = 0;

  struct skb_shared_info *shinfo = skb_shinfo(skb);
  memset(shinfo, 0, sizeof(*shinfo));
  atomic_set(&shinfo->dataref, 1);

  return skb;
}

void free_skb(struct sk_buff * skb) {
  P(&free_list_sema);
  if(skb_queue_len(&free_list) < MAX_CACHED_SKB) {
    // queue at head to try to improve locality
    __skb_queue_head(&free_list, skb);
  } else {
    Mem_FreePages((uint32_t)skb->head, 1);
    free(skb);
  }
  V_nexus(&free_list_sema);
}

void __kfree_skb(struct sk_buff *skb){
  free_skb(skb);
}

