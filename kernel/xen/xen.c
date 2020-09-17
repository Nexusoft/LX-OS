#include <nexus/defs.h>
#include <nexus/mem.h>
#include <nexus/thread.h>
#include <nexus/thread-private.h>
#include <nexus/xen-defs.h>
#include <nexus/idtgdt.h>
#include <asm/system.h> // for mb(), read_cr0()
#include <asm/param.h>
#include <asm/errno.h>
#include <asm/cpufeature.h>
#include <linux/smp.h>

#include <asm/bitops.h>
#include <xen/xen.h>
#include <xen/arch-x86_32.h>
#include <xen/callback.h>

#include <nexus/segments.h>
#include <nexus/xen-syscalls.h>

#include <nexus/clock.h>
#include <nexus/kbd.h>

#include <nexus/hashtable.h>
#include <nexus/synch-inline.h>

#define DISAS_EXTERN_PROTOS_ONLY
#define PRINT printk_red

#define AREA_TABLE_BUCKETS (16)

// If true, Xen nested exceptions (e.g. exceptions thrown during
// exception handling) aborts the process
int opt_abort_on_nested_exception = 0;

KernelThreadState *thread_Xen_checkAndGetKTS(BasicThread *t) {
  assert(nexusthread_isXen(t));
  return thread_getKTS(t);
}

static KernelThreadState *getMyKTS(void) {
  return thread_Xen_checkAndGetKTS(nexusthread_self());
}

static shared_info_t *thread_getSharedInfo(BasicThread *target) {
  assert(nexusthread_isXen(target));
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(target);
  if(kts->shared_info_mfn != 0) {
    return (shared_info_t *)
      PHYS_TO_VIRT(kts->shared_info_mfn << PAGE_SHIFT);
  } else {
    return NULL;
  }
}

static shared_info_t *xen_currentSharedInfo(void) {
  return thread_getSharedInfo(nexusthread_self());
}

typedef void (*VIRQ_bind_t)(BasicThread *thread, int virq_num);
typedef void (*VIRQ_unbind_t)(BasicThread *thread, int virq_num);

typedef struct VIRQDesc {
  VIRQ_bind_t bind;
  VIRQ_unbind_t unbind;
} VIRQDesc;

typedef struct VIRQState {
  int target_channel;
  void *context; // Space for VIRQ-specific context
} VIRQState;

static void start_virq_timer(BasicThread *thread, int virq_num);
static void stop_virq_timer(BasicThread *thread, int virq_num);

static void start_virq_kbd(BasicThread *thread, int virq_num);
static void stop_virq_kbd(BasicThread *thread, int virq_num);

VIRQDesc VIRQ_table[NUM_VIRQS] = {
  [VIRQ_TIMER] = {
    .bind = start_virq_timer,
    .unbind = stop_virq_timer,
  },
  [VIRQ_CONSOLE] = { 
    .bind = start_virq_kbd, 
    .unbind = stop_virq_kbd,
  },
  // [VIRQ_VMOUSE] // requires no initialization
};

static void TimerContext_registerNew(BasicThread *thread, unsigned long expiration,int is_periodic);
static void pass_to_cpl1_generic(NexusTrapInfo *ti, int have_error_code, 
				 enum SpecialProcessing special,
				 const char *str, InterruptState *is);

static void time_sync_init(void);
void xen_init(void) {
  // Initialize tables

  time_sync_init();
}

int xendom_registerCallback(struct callback_register *reg) {
  assert(inXenDomain());
  KernelThreadState *kts = getMyKTS();

  unsigned long *selector_to_change;
  unsigned long *address_to_change;
  switch(reg->type) {
  case CALLBACKTYPE_event:
    selector_to_change = &kts->callbacks.event_selector;
    address_to_change = &kts->callbacks.event_address;
    break;
  case CALLBACKTYPE_failsafe:
    selector_to_change = &kts->callbacks.failsafe_selector;
    address_to_change = &kts->callbacks.failsafe_address;
    break;
  case CALLBACKTYPE_nmi:
    selector_to_change = &kts->callbacks.nmi_selector;
    address_to_change = &kts->callbacks.nmi_address;
    break;
  default:
  printk_red("callback_op: unsupported type %d\n", reg->type);
  return -ENOSYS;
  }
  reg->address.cs = cs_makeValid(reg->address.cs);
  *selector_to_change = reg->address.cs;
  *address_to_change = reg->address.eip;
  return 0;
}

// Map into kernel / VMM read-only range

// Since we don't truncate the VMM range, these pages are available to
// supervisor

static PageTableEntry *xendom_kernelMap_lookupPTE(__u32 vaddr) {
  KernelThreadState *kts = getMyKTS();
  assert(NEXUS_DOMAIN_KERNELMAP_START <= vaddr  &&
	 vaddr < NEXUS_DOMAIN_KERNELMAP_END);
  return
    &(((PageTableEntry *) VADDR(kts->per_domain_ptable))[PTAB_OFFSET(vaddr)]);
}

static Page *xendom_kernelMap_lookup(__u32 vaddr) __attribute__((unused));
static Page *xendom_kernelMap_lookup(__u32 vaddr) {
  PageTableEntry *pte = xendom_kernelMap_lookupPTE(vaddr);
  if(!pte->present) {
    //printk_red("(%p=>!presnet)\n", (void *)vaddr);
    return NULL;
  } else {
    //printk_red("(%p=>%d)\n", (void *)vaddr, pte->pagebase);
    return &frameTable[pte->pagebase];
  }
}

// Returns true if flush is needed
static int xendom_kernelMap_mapPage(__u32 vaddr, Page *target) {
  PageTableEntry *real_pte = xendom_kernelMap_lookupPTE(vaddr),
    new_pte, *pte = &new_pte;
  pte->present = (target != NULL) ? 1 : 0;
  pte->rw = 1;
  pte->user = 0;
  pte->writethrough = 0;
  pte->uncached = 0;
  pte->accessed = 1;
  pte->dirty = 1;
  pte->reserved = 0;
  pte->globalpage = 0;
  pte->free = 0;

  pte->pagebase = (target != NULL) ? (PADDR(target) >> PAGE_SHIFT) : 0;
  // printk_red("%p pte %x\n", (void *) vaddr, *(__u32 *)pte);
  
  int changed = PageTableEntry_isFlushNeeded(*real_pte, *pte);
  *real_pte = new_pte;
  return changed;
}

static void xendom_kernelMap_remapGDT(void) {
  KernelThreadState *kts = getMyKTS();
  int i;
  for(i=0; i < FULL_GDT_PAGESIZE; i++) {
    xendom_kernelMap_mapPage(NEXUS_DOMAIN_GDT_VADDR(i),
			     kts->xen_gdt.gdt_pages[i]);
  }
  flushTLB();
}

int thread_Xen_verifyDomainTablePDE(BasicThread *target, int offset, __u32 val) {
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(target);
  assert(offset == PDIR_OFFSET(NEXUS_DOMAIN_KERNELMAP_START));
  return val == *(__u32*)&kts->per_domain_pdeval;
}

static void xendom_copyGDTPage(SegmentDescriptor *dest_base, 
			       SegmentDescriptor *src_base) {
  int i;
  for(i=0; i < GDT_ENTRIES_PER_PAGE; i++) {
    dest_base[i] = src_base[i];
  }
}

void xendom_setupDomainPagetable(void) {
  void *new_ptable;
  // Set up per-domain page table
  // This page table is owned by Nexus (hence not modifiable by guests)
  // It also resides past the end of the guest segment

  // Note that this needs to be called after Map_Xen_initFTTypes()
  KernelThreadState *kts = getMyKTS();

  // Allocate a new page table for 4MB domain-specific kernel map;
  // starts out zero
  DirectoryEntry *pde = 
    Map_getPDE(nexusthread_current_map(),
	       NEXUS_DOMAIN_KERNELMAP_START);

  new_ptable = getKernelPages(1);
  pagememzero_n((__u32)new_ptable, 1);
  
  kts->per_domain_ptable = PHYS_TO_PAGE(VIRT_TO_PHYS(new_ptable));
  // This page reverts to kernel ownership to protect against user modifications
  kts->per_domain_ptable->owner = 0;

  // Allocate new pages for GDT
  int i;
  for(i=0; i < FIRST_RESERVED_GDT_PAGE; i++) {
    void *new_page = getKernelPages(1);
    assert(new_page != NULL);
    kts->xen_gdt.gdt_pages[i] = PHYS_TO_PAGE(VIRT_TO_PHYS(new_page));
    pagememzero_n((__u32)new_page, 1);
  }
  // Reserved pages
  for(i=FIRST_RESERVED_GDT_PAGE; i < FULL_GDT_PAGESIZE; i++) {
    kts->xen_gdt.gdt_pages[i] = 
      PHYS_TO_PAGE(VIRT_TO_PHYS((char *)&boot_gdt_table[0] + i * PAGE_SIZE));
  }

  // Map in the GDT
  xendom_kernelMap_remapGDT();

  // Link in the new domain maps. Must do this after it is initialized
  // with a usable GDT to prevent problems with processor GDT accesses
  // seeing invalid state
  pde->physaddr = VIRT_TO_PHYS(new_ptable) >> PAGE_SHIFT;
  kts->per_domain_pdeval = *pde;
}

static int DescriptorTableEntries_toPages(int entries) {
  return (entries + (GDT_ENTRIES_PER_PAGE - 1)) / 
      GDT_ENTRIES_PER_PAGE;
}

int xendom_vGDT_set(unsigned long *frame_list, int entries) {
  // GDT switch is an expensive operation involving 56KB of memory
  // copy. This is OK because GDT switch is rare
  KernelThreadState *kts = getMyKTS();
  int num_pages = DescriptorTableEntries_toPages(entries);
  assert(num_pages <= FIRST_RESERVED_GDT_PAGE);

  IPD *ipd = nexusthread_current_ipd();
  BasicThread *t = nexusthread_self();
  int i;
  for(i=0; i < num_pages; i++) {
    // Check new pages
    unsigned long frame_mfn = frame_list[i];
    Page *p = Page_Xen_fromMFN_checked(frame_mfn);
    if(p == NULL) {
      printk_red("gdt check[%d]: bad page %x\n", i, frame_mfn);
      return -EINVAL;
    }

    if(Page_Xen_Type_get(ipd, t, p, FT_GDT) != 0) {
      printk_red("gdt check[%d]: verification failed\n", i);

      // Roll back gets that succeeded
      int j;
      for(j=0; j < i; j++) {
	Page_Xen_Type_put(ipd, t, 
		  Page_Xen_fromMFN_checked(frame_list[j]), 
		  FT_GDT);
      }
      return -EINVAL;
    }
  }

  {
    int old_num_pages = 
      DescriptorTableEntries_toPages(kts->xen_gdt.entries);
    for(i=0; i < old_num_pages; i++) {
      Page_Xen_Type_put(ipd, t, 
		Page_Xen_fromMFN_checked(kts->xen_gdt.frame_list[i]), 
		FT_GDT);
    }
  }

  for(i=0; i < num_pages; i++) {
    Page *p = Page_Xen_fromMFN_checked(frame_list[i]);
    xendom_copyGDTPage((SegmentDescriptor *) 
		       VADDR(kts->xen_gdt.gdt_pages[i]),
		       (SegmentDescriptor *) VADDR(p));
  }
  xendom_kernelMap_remapGDT();

  // Save a copy of the frame list for xendom_vGDT_toReal() (used for
  // update_descriptor)
  memcpy(&kts->xen_gdt.frame_list[0], frame_list,
	 num_pages * sizeof(frame_list[0]));
  kts->xen_gdt.entries = entries;
  return 0;
}

SegmentDescriptor *xendom_vGDT_toReal(unsigned long maddr) {
  // Probe for the page that contains this machine address
  KernelThreadState *kts = getMyKTS();
  int num_pages = DescriptorTableEntries_toPages(kts->xen_gdt.entries);
  int i;
  for(i=0; i < num_pages; i++) {
    assert(kts->xen_gdt.gdt_pages[i] != NULL);
    unsigned long mfn = kts->xen_gdt.frame_list[i];
    if((mfn << PAGE_SHIFT) == (maddr & PAGE_MASK)) {
      // Found match
      Page *real_page = kts->xen_gdt.gdt_pages[i];
      // printk_red("Match at %d, offset %x\n", i, maddr & PAGE_OFFSET_MASK);
      return (SegmentDescriptor *)
	(VADDR(real_page) | (maddr & PAGE_OFFSET_MASK));
    }
  }
  printk_red("vGDT to real: no matches!\n");
  return NULL;
}

void thread_Xen_vLDT_writeReal(BasicThread *ut) {
  KernelThreadState *kts = thread_getKTS(ut);
  write_ldt(NEXUS_DOMAIN_LDT_START, kts->xen_ldt.num_entries);
}

static int xendom_remap_LDT(void) {
  KernelThreadState *kts = getMyKTS();
  int need_flush = 0; // only flush if mappings change
  int i;

  IPD *ipd = nexusthread_current_ipd();
  BasicThread *t = nexusthread_self();
  Map *m = nexusthread_current_map();

  // last_new_page is exclusive
  int last_new_page = 
    (kts->xen_ldt.num_entries + LDT_ENTRIES_PER_PAGE - 1)  / 
    LDT_ENTRIES_PER_PAGE;
  int num_old_put = 0;

  for(i=0; i < FULL_LDT_PAGESIZE; i++) {

    // Put type of old page
    Page *old_page = 
      Page_Xen_fromVirt_checked(m, NEXUS_DOMAIN_LDT_START + i * PAGE_SIZE);
    if(old_page != NULL) {
      num_old_put++;
      Page_Xen_Type_put(ipd, t, old_page, FT_LDT);
    }

    if(i < last_new_page) {
      Page *p = 
	Page_Xen_fromVirt_checked(m, kts->xen_ldt.base + i * PAGE_SIZE);
      if(p != NULL && Page_Xen_Type_get(ipd, t, p, FT_LDT) == 0) {
	need_flush |= 
	  xendom_kernelMap_mapPage(NEXUS_DOMAIN_LDT_START + 
				   i * PAGE_SIZE, p);
      } else {
	printk_red("Could not remap LDT at %p[%d]\n", kts->xen_ldt.base, i);
	// XXX This might be due to a page that needs to be mapped back in in the guest
	// We assume that this is not the case and zero out the LDT
	const int paranoid = 1;
	if(paranoid) {
	  printk_red("Being paranoid and zeroing out LDT\n");
	  int j;
	  for(j=0; j < FULL_LDT_PAGESIZE; j++) {
	    // Unmap the LDT
	    xendom_kernelMap_mapPage(NEXUS_DOMAIN_LDT_START + j * PAGE_SIZE, NULL);
	  }

	  for(j=0; j < i; j++) {
	    // Roll back gets
	    Page *p = 
	      Page_Xen_fromVirt_checked(m, kts->xen_ldt.base + j * PAGE_SIZE);
	    Page_Xen_Type_put(ipd, t, p, FT_LDT);
	  }

	  write_ldt(NEXUS_DOMAIN_LDT_START, 0);
	  kts->xen_ldt.base = 0;
	  kts->xen_ldt.num_entries = 0;
	  // Error path, doesn't matter if it is slow
	  flushTLB();
	  return -EINVAL;
	}
	printk_red("More general handling not implemented\n");
	assert(0);
      }
    } else {
      // New LDT does not have mappings this high up, zap the old ones
      // if they are already present
      __u32 curr_page = NEXUS_DOMAIN_LDT_START + i * PAGE_SIZE;
      if(fast_virtToPhys(m, curr_page, 0, 0)) {
	need_flush |= xendom_kernelMap_mapPage(curr_page, NULL);
      }
    }
  }

  printk_red("<< put %d old >>", num_old_put);

  thread_Xen_vLDT_writeReal(t);
  if(need_flush) {
    flushTLB();
  }
  return 0;
}

int xendom_vLDT_set(unsigned int base_address, int num_entries) {
  KernelThreadState *kts = getMyKTS();

  if( (base_address & PAGE_OFFSET_MASK) != 0 ) {
    printk_red("virtual LDT must be page-aligned\n");
    return -EINVAL;
  }
  kts->xen_ldt.base = base_address;
  kts->xen_ldt.num_entries = num_entries;

  // Everything checks out, do the remapping
  return xendom_remap_LDT();
}

int xendom_vm_assist(unsigned int cmd, unsigned int type) {
  // Derived from Xen
  assert(inXenDomain());
  KernelThreadState *kts = getMyKTS();

  if ( type > MAX_VMASST_TYPE )
    return -EINVAL;
  switch ( cmd )
    {
    case VMASST_CMD_enable:
      set_bit(type, &kts->vm_assist.mode);
      return 0;
    case VMASST_CMD_disable:
      clear_bit(type, &kts->vm_assist.mode);
      return 0;
    }

  return -ENOSYS;
}

static void EventChannelState_destroy(BasicThread *t, struct EventChannelState *ecs);

void xendom_KTS_free(BasicThread *t, KernelThreadState *kts) 
{
  Page *p;
  int i;
  
  if (kts->traps)
    gfree(kts->traps);
  
  if (kts->event_state)
    EventChannelState_destroy(t, kts->event_state);
  
  if (kts->per_domain_ptable)
    freeKernelPages(kts->per_domain_ptable, 1);
  
  for(i = 0; i < FULL_GDT_PAGESIZE; i++) {
    p = kts->xen_gdt.gdt_pages[i];
    if (p)
      freeKernelPages(p, 1);
  }
}

typedef struct EventChannel {
  EventChannelData config;
} EventChannel;

struct EventChannelState {
  // Configuration information. Mostly static, except for virq context
  VIRQState virqs[NUM_VIRQS];
  EventChannel channels[NUM_EVENT_CHANNELS];

  struct {
    int has_waiter; // Sema is only V'ed if has_waiter == 1 ; this limits the amount of sema imbalance due to V()
    int waiter_version;
    int signal_version;
    Sema *sema;
  } block;
};

static EventChannelState *EventChannelState_new(void) {
  EventChannelState *ecs;
  ecs = (EventChannelState *)galloc(sizeof(EventChannelState));
  int i;
  for(i=0; i < NUM_VIRQS; i++) {
    memset(&ecs->virqs[i], 0, sizeof(VIRQState));
    ecs->virqs[i].target_channel = EVENT_CHANNEL_NONE;
  }

  for(i=0; i < NUM_EVENT_CHANNELS; i++) {
    memset(&ecs->channels[i], 0, sizeof(EventChannel));
    ecs->channels[i].config = 
      ( (EventChannelData) {
	.type = XEN_EC_UNBOUND,
	    } );
  }
  ecs->channels[0].config.type = XEN_EC_RESERVED;
  ecs->channels[EVTCHAN_STORE].config.type = XEN_EC_STORE;
  ecs->channels[EVTCHAN_CONSOLE].config.type = XEN_EC_CONSOLE;

  ecs->block.has_waiter = 0;
  ecs->block.waiter_version = 0;
  ecs->block.signal_version = 0;
  ecs->block.sema = sema_new();
  return ecs;
}

static void EventChannelState_destroy(BasicThread *t, struct EventChannelState *ecs) {
  int i;
  for(i=0; i < NUM_VIRQS; i++) {
    if(ecs->virqs[i].target_channel != EVENT_CHANNEL_NONE) {
      if(VIRQ_table[i].unbind != NULL) {	
	VIRQ_table[i].unbind(t, i);
      }
    }
  }
  sema_destroy(ecs->block.sema);
  gfree(ecs);
}

static EventChannelState *
EventChannelState_get(KernelThreadState *kts, int do_alloc) {
  if(unlikely(kts->event_state == NULL)) {
    if(do_alloc) {
      kts->event_state = EventChannelState_new();
    }
  }
  return kts->event_state;
}

#if 0
struct XenHWState {
  IPD *client_ipd; // kernel client IPD. Used to initialize vnic_client
  VNIC_Client *vnic_client;
  VNIC_Server *vnic_server;

  Sema rx_queue_mutex;
  dlist_head_list rx_queue;
  IPD *rx_ipd;

  int virq_enabled;
  BasicThread *consumer_thread;
  int consumer_virq;
};

static XenHWState *XenHWState_new(KernelThreadState *kts) {
  XenHWState *rv = galloc(sizeof(XenHWState));
  rv->client_ipd = NULL;
  rv->vnic_client = NULL;
  rv->vnic_server = NULL;
  rv->rx_queue_mutex = ((Sema) SEMA_MUTEX_INIT);
  sema_set_type(&rv->rx_queue_mutex, SEMATYPE_THREAD);
  dlist_init_head(&rv->rx_queue);
  rv->rx_ipd = kernelIPD;

  rv->virq_enabled = 0;
  rv->consumer_thread = NULL;
  rv->consumer_virq = -1;
  return rv;
}

static XenHWState *
XenHWState_get(KernelThreadState *kts, int do_alloc) {
  XenHWState *rv = kts->xen_hw_state;
  if(rv == NULL) {
    if(do_alloc) {
      rv = kts->xen_hw_state = XenHWState_new(kts);
    }
  }
  return rv;
}

static void vnet_up_tx_handler(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx) {
  printk_red("vnet got new packet?\n");
  assert(0);
}

static void vnet_down_tx_handler(IPD_ID source_ipd, Call_Handle call_handle, void *_ctx) {
  XenHWState *hw = _ctx;
  NetComp_Packet *pkt = NetComp_Packet_new(call_handle);

  P(&hw->rx_queue_mutex);
  dlist_insert_tail(&hw->rx_queue, &pkt->link);
  V(&hw->rx_queue_mutex);

  if(hw->virq_enabled) {
    thread_Xen_sendVIRQ(hw->consumer_thread, hw->consumer_virq);
  }
}

static void XenHWState_destroy(BasicThread *t, XenHWState *hw) {
  ipd_del(hw->client_ipd);
  VNIC_destroy_server(hw->vnic_client->control_port);
  VNIC_destroy_client(hw->vnic_client);

  dlist_head *_pkt, *_next_pkt;
  P(&hw->rx_queue_mutex);
  dlist_head_walk_safe(&hw->rx_queue, _pkt, _next_pkt) {
    dlist_unlink(_pkt);
    NetComp_Packet *pkt = CONTAINER_OF(NetComp_Packet, link, _pkt);
    NetComp_Packet_destroy(pkt, 1);
  }
  V(&hw->rx_queue_mutex);
  sema_dealloc(&hw->rx_queue_mutex);
  gfree(hw);
}
#endif // Xen_HW

int xendom_VIRQ_checkAndBind(int virq_num, int channel_num) {
  assert(inXenDomain());
  assert(channel_num != EVENT_CHANNEL_NONE);

  if(!(0 <= virq_num && virq_num < NUM_VIRQS)) {
    printk_red("bad virq num %d\n", virq_num);
    return -1;
  }
  EventChannelState *ecs = EventChannelState_get(getMyKTS(), 1);
  VIRQState *virq = &ecs->virqs[virq_num];
  if(virq->target_channel != EVENT_CHANNEL_NONE) {
    printk_red("virq %d already bound to %d\n", 
	       virq_num, virq->target_channel);
    return -1;
  }

  VIRQDesc *vdesc = &VIRQ_table[virq_num];

  if(vdesc->bind != NULL) {
    vdesc->bind(nexusthread_self(), virq_num);
  }

  virq->target_channel = channel_num;

  printk_red("binding %d to %d\n", virq_num, channel_num);
  return 0;
}

static int xendom_VIRQ_unbind(int virq_num) {
  // Internal use only. EventChannel unbind will also call this
  // function to wipe corresponding VIRQ entry ; that interface should
  // be used instead.
  assert(inXenDomain());
  assert(0 <= virq_num && virq_num < NUM_VIRQS);

  EventChannelState *ecs = EventChannelState_get(getMyKTS(), 0);
  assert(ecs != NULL);

  VIRQState *virq = &ecs->virqs[virq_num];
  if(virq->target_channel == EVENT_CHANNEL_NONE) {
    printk_red("unbind: virq %d not bound!\n", virq_num);
    return -1;
  }

  VIRQDesc *vdesc = &VIRQ_table[virq_num];
  if(vdesc->unbind != NULL) {
    vdesc->unbind(nexusthread_self(), virq_num);
  }

  virq->target_channel = EVENT_CHANNEL_NONE;
  return 0;
}

int xendom_EventChannel_checkAndBind
	(int channel_num, EventChannelData data) {
  assert(inXenDomain());
  EventChannelState *ecs = EventChannelState_get(getMyKTS(), 1);

  switch(data.type) {
  case XEN_EC_VIRQ:
    // OK, fall through
    break;
  case XEN_EC_IPI:
    // No-op
    break;
  default:
    printk_red("Unknown EC type %d\n", data.type);
    return -1;
  }

  if(channel_num == EVENT_CHANNEL_ANY) {
    // find a free channel
    int found = 0;
    int i;
    for(i=0; i < NUM_EVENT_CHANNELS; i++) {
      if(ecs->channels[i].config.type == XEN_EC_UNBOUND) {
	found = 1;
	break;
      }
    }
    if(!found) {
      printk_red("no free event channels\n");
      return -1;
    }
    channel_num = i;
  }
  printk_red("binding to %d\n", channel_num);

  assert(channel_num != EVENT_CHANNEL_NONE);
  ecs->channels[channel_num].config = data;
  return channel_num;
}

int xendom_EventChannel_unbind(int channel_num) {
  assert(inXenDomain());
  assert(channel_num != EVENT_CHANNEL_NONE);
  
  EventChannelState *ecs = EventChannelState_get(getMyKTS(), 0);
  if(ecs == NULL) {
    printk_red("Unbind: no event state???\n");
    return -1;
  }
  EventChannel *channel = &ecs->channels[channel_num];
  
  if(channel->config.type == XEN_EC_UNBOUND) {
    printk_red("Unbind of %d: not bound!\n", channel_num);
    return -1;
  }
  if(channel->config.type == XEN_EC_VIRQ) {
    int virq_num = channel->config.virq.virq_num;
    printk_red("unbinding virq %d\n", virq_num);
    xendom_VIRQ_unbind(virq_num);
  }
  memset(channel, 0, sizeof(*channel));
  channel->config.type = XEN_EC_UNBOUND;
  return 0;
}

static void xendom_thread_kick(BasicThread *t) {
  assert(nexusthread_isXen(t));
  EventChannelState *ecs = EventChannelState_get(thread_Xen_checkAndGetKTS(t), 0);
  if(ecs == NULL) {
    return;
  }
  if(ecs->block.has_waiter &&
     ecs->block.signal_version != ecs->block.waiter_version) {
    ecs->block.signal_version = ecs->block.waiter_version;
    V(ecs->block.sema);
  }
}

void xendom_sti(void) {
  assert(inXenDomain());
  shared_info_t *shinfo = xen_currentSharedInfo();
  vcpu_info_t *vcpu = &shinfo->vcpu_info[0];
  vcpu->evtchn_upcall_mask = 0;
}
void xendom_block(void) {
  assert(inXenDomain());
  EventChannelState *ecs = EventChannelState_get(getMyKTS(), 0);
  if(ecs == NULL) {
    printk_red("block: no ecs\n");
    return;
  }

  ecs->block.waiter_version++;
  ecs->block.has_waiter = 1;
  // mb() after has_waiter, rather than after both is ok for the following reason:

  // an interrupt seeing the old version is equivalent to situation
  // where interrupt was slightly earlier (e.g. it was missed), which
  // is an acceptable serialization

  mb();
  while(1) {
    // Keep P()'ing until an interrupt from the corresponding version
    P(ecs->block.sema);
    if(ecs->block.signal_version == ecs->block.waiter_version) {
      break;
    } else {
      printk_red("bad unblock\n");
    }
  }
  mb();
  ecs->block.has_waiter = 0;
}

int xendom_setSingleShotTimer(unsigned long expiration) {
  assert(inXenDomain());
  TimerContext_registerNew(nexusthread_self(), expiration, 0);
  return 0;
}

void ipd_Xen_sendVIRQ(IPD *ipd, int virq_num) {
  // Get the controller virq
  assert(ipd->xen.cpu0 != NULL);
  // For now, just send the VIRQ to the active thread. If we ever go
  // to SMP, we may implement IRQ routing table.
  thread_Xen_sendVIRQ(ipd->xen.cpu0, virq_num);
}

void thread_Xen_sendVIRQ(BasicThread *target, int virq_num) {
  assert(0 <= virq_num && virq_num < NUM_VIRQS);
  EventChannelState *ecs = EventChannelState_get(thread_Xen_checkAndGetKTS(target), 0);
  if(ecs == NULL) {
    // not yet ready for interrupts
    return;
  }
  VIRQState *virq = &ecs->virqs[virq_num];

  if(virq->target_channel != EVENT_CHANNEL_NONE) {
    thread_Xen_setPendingEvent(target, virq->target_channel);
  }
}

int xendom_send_virq(int virq_num) {
  assert(inXenDomain());
  if(!(0 <= virq_num && virq_num < NUM_VIRQS)) {
    printk_red("send_virq: out of bound (%d)!\n", virq_num);
    return -SC_INVALID;
  }
  IPD *ipd = nexusthread_current_ipd();
  ipd_Xen_sendVIRQ(ipd, virq_num);
  return 0;
}

static int last_edge_tick;
void thread_Xen_setPendingEvent(BasicThread *target, int channel_num) {
  int intlevel = disable_intr();
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(target);
  shared_info_t *shinfo = thread_getSharedInfo(target);
  vcpu_info_t *vcpu = &shinfo->vcpu_info[0];
  assert(shinfo != NULL);

  // Set pending flag for the channel
  const int word_size = sizeof(unsigned long) * 8;
  int word_index = channel_num / word_size;
  int bit_index = channel_num % word_size;

  // Use test_bit to be consistent with test_and_set_bit
  int mask_sel = test_bit(bit_index, &shinfo->evtchn_mask[word_index]);
  if(mask_sel) {
    // printk_red("msel");
    // This channel is masked and should not deliver events
    goto out;
  }

  // Channel processing
  int old_val_channel = 
    test_and_set_bit(bit_index, &shinfo->evtchn_pending[word_index]);

  // CPU-specific processing

  // Check to see if a bit in the same 32 channel group has been
  // delivered to the CPU and not cleared
  int old_val_cpu = 
    test_and_set_bit(word_index, &vcpu->evtchn_pending_sel);

  int old;
  old = vcpu->evtchn_upcall_pending; // debugging only
  int old_upcall_pending_cpu = swapb(&vcpu->evtchn_upcall_pending, 0xff);

  // Kick the target thread if it might be sleeping

  // XXX Putting this here makes the kick happen on any valid new
  // event. Should this only occur on an edge?

  xendom_thread_kick(target);

  // The pending notifications are all set. Now see if this generates an edge.
  // printk_red("(s=>%d)", target->id);
  if(old_val_channel || old_val_cpu || old_upcall_pending_cpu) {
    // Cases tested:
    // Not an edge for this channel
    // Not an edge for the channel group
    // CPU already has pending event

    // printk_red("(%d%d%d)", !!old_val_channel, !!old_val_cpu, !!old_upcall_pending_cpu);
    // printk_red("@[%p:%lu]", (char *)vcpu->arch.pad[0], vcpu->arch.pad[1]);
    goto out;
  }

  // CPU should be notified
  kts->hasEventEdge = 1;
  last_edge_tick = nexustime;

  // For SMP, we'd probably put a check to see if the target is local;
  // if remote, send IPI to force pendingEvent check within bounded
  // time.
 out:
  restore_intr(intlevel);
}

void nexusthread_Xen_dispatchPendingEvent(BasicThread *t, InterruptState *is) {
  if(!GUEST_FAULT(is)) {
    // The guest can't make sense of an EIP in Nexus; don't deliver
    // event until we get to a point in execution where is->eip is in
    // guest

    // don't go to out_restore: interrupts not yet disabled!
    return;
  }

  int intlevel = disable_intr();
  // This is always true on uniproc
  assert(nexusthread_self() == t);

  // CPU-specific interrupt mask checking / filtering is done here
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(t);
  shared_info_t *shinfo = thread_getSharedInfo(t);
  if(shinfo == NULL) {
    goto out_restore;
  }
  vcpu_info_t *vcpu = &shinfo->vcpu_info[0];

  int should_deliver_event = !vcpu->evtchn_upcall_mask && 
    (kts->hasEventEdge || vcpu->evtchn_upcall_pending);
  if(!should_deliver_event) {
    goto out_restore;
  }

  kts->hasEventEdge = 0;

  // Disable further virtual interrupts. Guest will re-enable
  vcpu->evtchn_upcall_mask = 0xff;
  assert(EventChannelState_get(kts, 0) != NULL);
  
  NexusTrapInfo ti = {
    .pending = 0,
    .cs = kts->callbacks.event_selector,
    .address = kts->callbacks.event_address,
  };
  pass_to_cpl1_generic(&ti, 0, NONE, "Event", is);
 out_restore:
  restore_intr(intlevel);
}

int xendom_setFastTrap(int offset) {
  // FastTrap supports Linux syscall (0x80) and Xen syscall (0x81)
  printk("set fast trap not implemented!\n");
  return -EINVAL;
}

static inline int copy_from_user_exact(void *to, void *from, unsigned long n) {
  // XXX HACK does not do all necessary access, exception checks
  if(from+n > (void*)XEN_LIMIT) return 1;
  memcpy(to, from, n);
  return 0;
#if 0
  return (copy_from_user(to,from,n) == n) ? 0 : 1;
#endif
}
static inline int copy_to_user_exact(void *to, void *from, unsigned long n) {
  // XXX HACK, does not do all necessary access, exception checks
  // For instance, this can be used to screw up device drivers
  if(to+n > (void*) XEN_LIMIT) return 1;
  memcpy(to, from, n);
  return 0;
#if 0
  return ((copy_to_user(to,from,n)) == n) ? 0 : 1;
#endif
}

int xendom_setExceptionStack(u32 level, u32 ss, u32 esp) {
  if(!inXenDomain()) {
    return -EINVAL;
  }
  KernelThreadState *kts = getMyKTS();
  switch(level) {
  case 1:
    kts->ss1 = sel_makeValid(ss);
    kts->esp1 = esp;
    break;
  case 2:
    kts->ss2 = sel_makeValid(ss);
    kts->esp2 = esp;
    break;
  default:
    printk("Invalid level\n");
    return -EINVAL;
  }
  if(0) {
    printk("ss1: %x esp1: %x ss2: %d esp2: %x\n", kts->ss1, kts->esp1,
	   kts->ss2, kts->esp2);
  }
  KernelThreadState_syncTSS(kts);
  return 0;
}

int xendom_setTrapTable(trap_info_t *new_entries) {
  if(!inXenDomain())
    return -EINVAL;
  
  KernelThreadState *kts = getMyKTS();
  if(!kts->traps)
    kts->traps = gcalloc(MAX_IDT_ENTRIES, sizeof(NexusTrapInfo));

  Map *m = nexusthread_current_map();
  trap_info_t *uti_p;
  int count = 0;
  for(uti_p = new_entries; ; uti_p++, count++) {
    trap_info_t uti;
    if(peek_user(m, (__u32)uti_p, &uti, sizeof(uti)) != 0) {
      printk_red("Access error in IDT setup!\n");
      return -EACCES;
    }
    if(uti.address == 0) {
      // termination of input
      break;
    }
    if(uti.vector >= MAX_IDT_ENTRIES) {
      printk_red("invalid vector %d\n", uti.vector);
      return -EINVAL;
    }
    NexusTrapInfo *ti = &kts->traps[uti.vector];
    uti.cs = cs_makeValid(uti.cs);
    ti->cs = uti.cs;
    ti->address = uti.address;
    assert((ti->cs & 0x3) >= 1);
  }
  return 0;
}

int xendom_set_iopl(int new_iopl) {
  KernelThreadState *kts = getMyKTS();
  if(!(1 <= new_iopl && new_iopl <= 3)) {
    printk_red("invalid iopl %d\n", new_iopl);
    return -EINVAL;
  }
  kts->xen_regs.iopl = new_iopl;
  return 0;
}

int xendom_registerSharedMFN(unsigned int shared_info_mfn) {
  if(!inXenDomain()) {
    return -EINVAL;
  }
  KernelThreadState *kts = getMyKTS();
  kts->shared_info_mfn = shared_info_mfn;
  return 0;
}

// N.B. The VMM_PDIR range is not considered for reference counting
// and self-loop detection
int xendom_set_VMM_PDIR(int pdoffset, unsigned int *entries, int len) {
  BasicThread *t = nexusthread_self();
  KernelThreadState *kts = getMyKTS();
  __u32 check_entries[MAX_VMM_PDIR_LEN];
  Map *m = nexusthread_current_map();

  if(kts->vm_assist.len != 0) {
    printk_red("set_VMM_PDIR(): can only be called once!\n");
    return -EINVAL;
  }

  if(!(0 <= len && len <= MAX_VMM_PDIR_LEN)) {
    printk_red("set_VMM_PDIR(): bad len %d\n", len);
    return -EINVAL;
  }
  if(!(0 <= pdoffset && pdoffset + len <= PDIR_OFFSET(NEXUS_START))) {
    printk_red("set_VMM_PDIR(): bad bounds\n");
    return -EINVAL;
  }

  if(peek_user(m, (__u32)&entries[0], &check_entries[0], 
	       len * sizeof(entries[0])) != 0) {
    return -EACCES;
  }

  // Check each pdir
  int i;
  for(i = 0; i < len; i++) {
    if(!verify_pde(NULL, t, pdoffset + i, check_entries[i], 1)) {
      printk_red("set_VMM_PDIR(): entry %d bad\n", i);
      return -EINVAL;
    }
  }
  kts->vm_assist.pdoffset = pdoffset;
  memcpy(&kts->vm_assist.entries[0], &check_entries[0], 
	 len * sizeof(check_entries[0]));
  kts->vm_assist.len = len;
  return 0;
}

void Page_Xen_PDIR_init(IPD *ipd, BasicThread *t, Page *p) {
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(t);
  DirectoryEntry *de = (DirectoryEntry *)VADDR(p);
  int i;
  for(i = 0; i < kts->vm_assist.len; i++) {
    int pdoffset = kts->vm_assist.pdoffset + i;
    if(0) {
      printk_red("[%d]: %x=>%x ", pdoffset, 
		 ((__u32 *)de)[pdoffset],
		 kts->vm_assist.entries[i]);
    }
    ((__u32 *)de)[pdoffset] = kts->vm_assist.entries[i];
  }
}

int inXenDomain(void) {
    return nexusthread_isXen(nexusthread_self());
}

#define DBG_FMEMCPY 0
static inline int fmemcpy(int to_seg, void *to_addr, void *from, int len) {
  // XXX This code does NOT install the necessary exception handlers
  // to trap bad SS, etc
  if(DBG_FMEMCPY) {
    printk("fmemcpy %p => %x:%p ", from, to_seg, to_addr);
    int i;
    printk(" from : ");
    for(i=0; i < len / 4; i++) {
      printk("( %08x ) ", ((int*)from)[i]);
    }
    printk(" to0 : ");
    for(i=0; i < len / 4; i++) {
      printk("( %08x ) ", ((int*)to_addr)[i]);
    }
  }
  u32 result, ignore1;
  __asm__ __volatile__ (
			"movl %4, %0\n"
			"movl %3, %1\n"
			"pushl %%es\n"
			"movl %2, %%es\n"
			"1: rep movsb %%ds:(%0), %%es:(%1)\n" // fault point
			"xor %0, %0\n" // 0 in result = success
			"99: popl %%es\n" // resume point

	   ".section __nexus_ex_table,\"a\"\n"
	   "	.int 1b\n"
	   "	.int 10f\n"
	   ".previous\n"
	   ".section .fixup, \"ax\"\n"
	   "10:\n"
	"	movl $-1, %0\n" // -1 = failure
	   "	jmp 99b\n"
	   ".previous\n"

			: "=S" (result), "=D" (ignore1) : "a" (to_seg), "b" (to_addr), "d" (from), "c" (len) );
  if(DBG_FMEMCPY) {
    int i;
    printk(" to1 : ");
    for(i=0; i < len / 4; i++) {
      printk("( %08x ) ", ((int*)to_addr)[i]);
    }
  }
  return result;
}

const __u32 BOUNCE_FLAG_MASK = 
  ~(X86_EFLAGS_VM|X86_EFLAGS_RF|X86_EFLAGS_NT|X86_EFLAGS_TF);

static inline void setup_intra_bounce_frame(u8 *dstc, u32 cs, u32 eip, u32 eflags) {
  // This function is not currently being used
  // "intra" means same CPL
    /* Layout is
       EFLAGS
       CS
       EIP */
  u32 *dst = (u32*) dstc;
  dst[2] = eflags & BOUNCE_FLAG_MASK;
  dst[1] = cs;
  dst[0] = eip;
}

static void setup_inter_bounce_frame(u8 *dstc, u32 cs, u32 eip, u32 eflags,
				     u32 ss, u32 esp) {
  // "inter" means different CPL
    /* Layout is
       SS
       ESP
       EFLAGS
       CS
       EIP */
  u32 *dst = (u32*) dstc;
  dst[4] = ss;
  dst[3] = esp;
  dst[2] = eflags & BOUNCE_FLAG_MASK;
  dst[1] = cs;
  dst[0] = eip;
}

extern void kill_current_domain(void);
extern void nexus_gpf(InterruptState *is);

void dump_int(void *dest, int count) {
  int i;
  printk("%p ", dest);
  for(i=0; i < count; i++) {
    printk("( %08x ) ", ((int*)dest)[i]);
  }
}

static void pass_to_cpl1_generic(NexusTrapInfo *ti, int have_error_code, 
		  enum SpecialProcessing special,
		  const char *str, InterruptState *is) {
#define DUMP_ARGS()							\
  do {									\
    printk("cpl(%d,%d,%d,%s), is=", number, have_error_code, special, str); \
    dump_regs_is(is);							\
  } while(0)

  assert(inXenDomain());

  struct KernelThreadState *kts = getMyKTS();

  u32 dest_stack_top;
  int temp[6];
  // u8 trap_dpl;
  u16 trap_cs;
  u32 trap_address;
  shared_info_t *shared_info = xen_currentSharedInfo();

  // XXX Pending exception is not properly detected
  if(ti->pending) {
    if(opt_abort_on_nested_exception) {
      printk("Nested interrupt being passed to cpl1 ; aborting\n");
      dump_regs_is(is);
      kill_current_domain();
      ASSERTNOTREACHED();
    } else {
      printk("Nested exception detected, not aborting\n");
    }
  }
  trap_cs = ti->cs;
  trap_address = ti->address;

  /* Acking is done by the app setting the value by itself*/
  ti->pending = 0;

  /* Validate the code segment every time */
  if ( !VALID_CODESEL(trap_cs) ) {
    printk("ti->cs:eip = %x:%x, %x:%x\n", ti->cs, (unsigned)ti->address, trap_cs, trap_address);
    printk("pass_to_cpl1(%s): invalid code selector (%d) to return to, generating a fatal GP\n", str, trap_cs);
    nexus_gpf(is);
  }
  if((is->cs & 0x3) == 1) {
    // Careful. This is a recursive activation. We must push the new
    // activation onto the stack using is->esp
    u8 *copy_start;
    int len;
#define SET_ERRORCODE()				\
    *(int *)&is->errorcode = is->errorcode;
    if(have_error_code) {
      SET_ERRORCODE();
      copy_start = (u8 *)&is->errorcode;
      len = 16;
    } else {
      copy_start = (u8 *)&is->eip;
      len = 12;
    }
    dest_stack_top = is->esp - len;
    // printk_red("%s %p @ %p", str, (void*)dest_stack_top, is->eip); // dump_regs_is(is); show_stack((void *)is->esp);
    // printk_red("fmemcpy(%d,%x,%p,%p,[%d])", nexusthread_self()->id, kts->ss1, (u8 *)dest_stack_top, copy_start, len);
    if(fmemcpy(kts->ss1, (u8 *)dest_stack_top, copy_start, len) != 0) {
      printk_red("recursive activation copy error, failsafe callback not implemented!\n");
      assert(0);
    }
    // We need to change the ESP *after* copying the trap frame,
    // otherwise the updated esp will be used in that frame.
    is->esp = dest_stack_top;
    //printk("...\n");
  } else {
    u8 *copy_start;
    int len;
    if(have_error_code) {
      SET_ERRORCODE();
      copy_start = (u8 *)&is->errorcode;
      len = 24;
#undef SET_ERRORCODE
    } else {
      copy_start = (u8 *)&is->eip;
      len = 20;
    }
    dest_stack_top = kts->esp1 - len;
    // printk("different cpl"); printk(" to %x:%p ", is->cs, (void*)is->eip); dump_int(copy_start, len / 4);
    if(fmemcpy(kts->ss1, (u8 *)dest_stack_top, copy_start, len) != 0) {
      printk_red("3=>1 activation copy error, failsafe callback not implemented!\n");
      assert(0);
    }
  }

  /* Set up a frame for use with iret */
  setup_inter_bounce_frame((u8*)temp, trap_cs, trap_address, is->eflags,
			   kts->ss1, dest_stack_top);
  switch(special) {
  case NONE:
    break;
  case LOAD_DR6:
    printk_red("load_dr6 not tested\n");
    __asm__ __volatile__("movl %0, %%db6" : : "r" (kts->xen_regs.dr6));
    break;
  case LOAD_CR2:
    shared_info->vcpu_info[0].arch.cr2 = kts->xen_regs.cr2;
    break;
  }

  __asm__ __volatile__ (
	// We don't know what kind of register munging will be needed to get %1, so do this at the very beginning. We'll pop %esp to this value
	"pushl %1 ; " // %esp of bounce frame

	// We can't simply pop IS because the bounce frame is above
	// the IS on the stack
	"movw 0(%0), %%gs ; movw 4(%0), %%fs ; movw 8(%0), %%es ; "
	"pushl 12(%0) ;" // Save DS on stack ; restore it from stack after all other restores, otherwise there will be GPF due to truncated segment
	// We're using %ebx, so restore it at the end
	"movl 20(%0), %%ecx ; "
	"movl 24(%0), %%edx ; "
	"movl 28(%0), %%esi	; "
	"movl 32(%0), %%edi	 ; "
	"movl 36(%0), %%ebp ; "
	"movl 40(%0), %%eax ; "
	"movl 16(%0), %%ebx ; " // %ebx is handled specially because it points to IS
	"popl %%ds ;"
	"popl %%esp ;"
	"iret\n" /* XXX This iret needs to be added to exception handling table */
	: /* No output constraints ; C compiler state invalid at this point */
	: "b" (is), "g" (&temp[0]));
#undef DUMP_ARGS
}

void pass_to_cpl1_trap(int number, int have_error_code, 
		       enum SpecialProcessing special,
		       const char *str, InterruptState *is) {
  KernelThreadState *kts = getMyKTS();

  if (!kts->traps) {
    printk("[xen] INT %d: no trap handler\n", number);
    dump_regs_is(is);
    kill_current_domain();
  }

  pass_to_cpl1_generic(&kts->traps[number],
		       have_error_code, special, str, is);
}

// Int 1

#define DR_TRAP0        (0x1)           /* db0 */
#define DR_TRAP1        (0x2)           /* db1 */
#define DR_TRAP2        (0x4)           /* db2 */
#define DR_TRAP3        (0x8)           /* db3 */
#define EF_TF (0x00000100)

void do_xen_debug(InterruptState *is, unsigned condition) {
  KernelThreadState *kts = getMyKTS();

#if 0
  // XXX ashieh: This looks important, and should be put back in once
  // I understand it.
  /* Mask out spurious debug traps due to lazy DR7 setting */
  if ( (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) &&
       (d->thread.debugreg[7] == 0) )
    {
      __asm__("movl %0,%%db7" : : "r" (0));
      goto out;
    }
#endif

  if ( !GUEST_FAULT(is) )
    {
      /* Clear TF just for absolute sanity. */
      is->eflags &= ~EF_TF;
      /*
       * We ignore watchpoints when they trigger within Xen. This may happen
       * when a buffer is passed to us which previously had a watchpoint set
       * on it. No need to bump EIP; the only faulting trap is an instruction
       * breakpoint, which can't happen to us.
       */
      return;
    }

  // Set debug register to condition
  kts->xen_regs.dr6 = condition;
  pass_to_cpl1_trap(1, 0, LOAD_DR6, "debug", is);
  ASSERTNOTREACHED();
}

void do_xen_int3(InterruptState *is) {
  pass_to_cpl1_trap(3,0,NONE,"int3",is);
  ASSERTNOTREACHED();
}

static int emulate_forced_invalid_op(InterruptState *regs);

void do_xen_invalid_op(InterruptState *is) {
  if ( !GUEST_FAULT(is) ) {
    printk("invalid op in kernel\n");
    goto fault_in_kernel;
  }

  if(emulate_forced_invalid_op(is) != 0) {
    // handled, return to user with is
    return;
  }
  pass_to_cpl1_trap(6,0,NONE,"invalid_op",is);
  ASSERTNOTREACHED();

 fault_in_kernel:
  printk_red("Nexus: invalid op!\n");
  dump_regs_is(is);
  nexuspanic();
}

void do_xen_nm(InterruptState *is) {
  if(!GUEST_FAULT(is)) {
    goto xen_nm_in_kernel;
  }
  // #NM stack frame does not have error code
  pass_to_cpl1_trap(7, 0, NONE, "NM", is);
  ASSERTNOTREACHED();

 xen_nm_in_kernel:
  printk_red("<< Xen NM in kernel! >>\n");
  dump_regs_is(is);
  nexuspanic();
}


void do_xen_pfault(InterruptState *is) {
    KernelThreadState *kts = getMyKTS();
    unsigned long addr = 0;

    if(0){
      printk_red("[xen] PF %p", (void *)is->eip); 
    
      unsigned char inst[4];
      if(peek_user(nexusthread_current_map(), is->eip, inst, 4) >= 0)
	printk_red("%02x %02x %02x %02x", inst[0], inst[1], inst[2], inst[3]);

      //dump_regs_is(is);
    }
#if 0
    perfc_incrc(page_faults);
#endif

    // Xen layer will do MMU write access checks, shadow page tables, LDT handling, etc
    __asm__ __volatile__ ("movl %%cr2,%0" : "=r" (addr) : );
    //printk_red("**** Xen pfault at %p (%p) ", (void *)addr, (void*)is->eip); 

    if ( !GUEST_FAULT(is) )
        goto xen_fault;

    Selector cs = Selector_from_u32(is->cs);
    if(test_bit(VMASST_TYPE_writable_pagetables,
		&kts->vm_assist.mode) && 
       ((is->errorcode & 0xf) ==  
	(PFEC_write_access | PFEC_page_present)) /* write*/ &&
       (cs.rpl == GUEST_PL) /* from supervisor mode */ ) {
      // Check if target is a page table

      __u32 paddr = fast_virtToPhys(nexusthread_current_map(), addr & PAGE_MASK, 0, 0);
      Page *page = (paddr != 0) ? PHYS_TO_PAGE(paddr) : NULL;
      if(page != NULL && 
	 page->owner == nexusthread_current_ipd()->id && 
	 page->type == FT_PTABLE) {

	if((addr & 0x3) != 0) {
	  // Advisory, for detecting guest weirdness.
	  // The userspace disassembler should be smart enough to deal
	  // with this.
	  printk_red("warning: wr_ptable write to %p not aligned!\n",
		     (void *)addr);
	}

	// This is a supervisor write to a writable page table (some
	// PTE).  Pass the trap to userspace for decoding and further
	// processing (e.g. issue MMU hypercall). PFEC_nexus_wrptable
	// requests this type of special processing
      
	// This processing is best suited for Nexus, since the VMM does
	// not see the page table types.
	is->errorcode |= PFEC_nexus_wr_ptable;

	// printk_red("(passing wr_ptable(%p) to VMM (%x))", addr, (int)is->errorcode);
      }
    }

    if(0 && is->errorcode & PFEC_nexus_wr_ptable)
      printk_green("(");

    if(0) {
      printk_red("<< pfault @ %p >>", addr);
      dump_regs_is(is);
    }

    kts->xen_regs.cr2 = addr;
    pass_to_cpl1_trap(14, 1, LOAD_CR2, "page fault", is);
    return;

 xen_fault:

#if 0
    // XXX Need to do exception table search for all domains
    if ( likely((fixup = search_exception_table(regs->eip)) != 0) )
    {
        perfc_incrc(copy_user_faults);
        if ( !d->mm.shadow_mode )
            DPRINTK("Page fault: %08x -> %08lx\n", regs->eip, fixup);
        regs->eip = fixup;
        return;
    }
#endif

#if 0
    // XXX Possibly useful debugging checks that should be investigated later
    if ( addr >= PAGE_OFFSET )
    {
        unsigned long page;
        page = l2_pgentry_val(idle_pg_table[addr >> L2_PAGETABLE_SHIFT]);
        printk("*pde = %08lx\n", page);
        if ( page & _PAGE_PRESENT )
        {
            page &= PAGE_MASK;
            page = ((unsigned long *) __va(page))[(addr&0x3ff000)>>PAGE_SHIFT];
            printk(" *pte = %08lx\n", page);
        }
#ifdef MEMORY_GUARD
        if ( !(regs->error_code & 1) )
            printk(" -- POSSIBLY AN ACCESS TO FREED MEMORY? --\n");
#endif
    }
#endif

    printk_red("FATAL PAGE FAULT\n"
          "[error_code=%04x, eip=%p]\n"
          "Faulting linear address might be %08lx\n",
	       is->errorcode, (void *)is->eip, addr);
    dump_regs_is(is);
    nexuspanic();
    return;
}

void do_xen_sysenter(InterruptState *is) {
  printk_red("Xen sysenter not implemented!!!\n");
  nexuspanic();
}

void do_xen_systrap(InterruptState *is) {
  printk_green("[xen] systrap(%x)", is->entry_vector);
  pass_to_cpl1_trap(is->entry_vector, 0, NONE, "systrap", is);
}

/// VIRQ_TIMER handling
// Implemented with Nexus alarm

typedef struct TimerContext {
  Alarm *alarm;
  UThread *target_thread;

  int is_periodic;
} TimerContext;

#define VIRQ_GENERIC_DEFS					\
  UThread *ut;						\
  ut = (UThread *)thread;				\
  EventChannelState *ecs =				\
    EventChannelState_get(thread_getKTS(thread), 0);	\
  VIRQState *vstate = &ecs->virqs[VIRQ_TIMER];

#define VIRQ_TIMER_DEFS VIRQ_GENERIC_DEFS

static void virq_timer_fire(void *ctx);

static TimerContext *
TimerContext_new(UThread *ut, int is_periodic) {
  // XXX reenable when reviving XEN: nexusthread_get((BasicThread *)ut);
  TimerContext *ctx = galloc(sizeof(TimerContext));
  assert(ctx != NULL);
  ctx->alarm = NULL;
  ctx->target_thread = ut;
  ctx->is_periodic = is_periodic;
  return ctx;
}

#define NEXT_PERIODIC (nexustime + XEN_CLOCK_PERIOD)

static unsigned long absolute_to_delta(unsigned long expiration) {
  unsigned long t = nexustime;
  if(expiration < t) {
    return 0;
  } else {
    return expiration - t;
  }
}

static void TimerContext_registerNew(BasicThread *thread, unsigned long expiration,int is_periodic) {
  if(is_periodic) {
    expiration = NEXT_PERIODIC;
  }
  VIRQ_TIMER_DEFS;

  int intlevel = disable_intr();
  TimerContext *ctx = TimerContext_new(ut, is_periodic);
  vstate->context = ctx;
  ctx->alarm = 
    register_alarm(absolute_to_delta(expiration), virq_timer_fire, ctx);
  restore_intr(intlevel);
}

static void TimerContext_destroy(TimerContext *ctx) {
  // XXX reenable when reviving XEN: nexusthread_put((BasicThread *)ctx->target_thread);
  gfree(ctx);
}

static void start_virq_timer(BasicThread *thread, int virq_num) {
  assert(virq_num == VIRQ_TIMER);
  TimerContext_registerNew(thread, 0 /* ignored */, 1);
}

static void stop_virq_timer(BasicThread *thread, int virq_num) {
  VIRQ_TIMER_DEFS;

  TimerContext *ctx = vstate->context;

  // Prevent alarm from firing when we might have deallocated ctx
  int intlevel = disable_intr();
  deregister_alarm(ctx->alarm);
  TimerContext_destroy(ctx);
  restore_intr(intlevel);
}

static void virq_timer_fire(void *_ctx) {
  TimerContext *ctx = (TimerContext *)_ctx;

  thread_Xen_sendVIRQ((BasicThread *)ctx->target_thread, VIRQ_TIMER);
  if(ctx->is_periodic && 
     // if the thread is dead, don't schedule more alarms, and zap the
     // reference count so that it can get reaped
     ctx->target_thread->schedstate != DEAD) {
    ctx->alarm = 
      register_alarm(absolute_to_delta(NEXT_PERIODIC), virq_timer_fire, ctx);
  } else {
    TimerContext_destroy(ctx);
  }
}

static void start_virq_kbd(BasicThread *thread, int virq_num) {
  //if (thread->ipd->console && thread->ipd->console->keyboard)
    //kbd_set_xen_irq_thread(thread->ipd->console->keyboard, thread);
}

static void stop_virq_kbd(BasicThread *thread, int virq_num) {
  //if (thread->ipd->console && thread->ipd->console->keyboard)
    //kbd_set_xen_irq_thread(thread->ipd->console->keyboard, NULL);
}

#undef VIRQ_TIMER_DEFS
#undef NEXT_PERIODIC

//////////////////
/// Shared memory timing state
/// This section is taken almost verbatim from Xen

struct GlobalTime {
  __u64 local_tsc_stamp; /* TSC at last update of time vals.  */
  __u64 stime_local_stamp; /* Time, in nanosecs, since boot.    */
  struct {
    int mul_frac;
    int shift;
  } tsc_scale;
} global_xen_time;

static void update_vcpu_system_time(vcpu_info_t *v);

static void time_sync_fire(void *_ctx) {
  // Update the time parameters

  // TODO: This is a quick and dirty solution. Implement proper
  // resynchronization later.
  global_xen_time.local_tsc_stamp = rdtsc64();
  global_xen_time.stime_local_stamp =  // ns since boot
    (((__u64)nexustime) * 1000000000ULL) / HZ;

  /*
   * From comment in xen.h:
   */
    /*
     * Current system time:
     *   system_time + // Note: in ns!
     *   ((((tsc - tsc_timestamp) << tsc_shift) * tsc_to_system_mul) >> 32)
     * CPU frequency (Hz):
     *   ((10^9 << 32) / tsc_to_system_mul) >> tsc_shift
     */
  /*
    RATE = ((10^9 << 32) / tsc_to_system_mul) >> tsc_shift
    RATE << tsc_shift = ((10^9 << 32) / tsc_to_system_mul)
    tsc_to_system_mul = (10^9 << 32) / (RATE << tsc_shift)
   */

  __u64 tsc_delta_in_update = 
    ((__u64)XEN_CLOCK_SYNC_PERIOD) * nxclock_rate_hz;

  // Compute amount of right shift to prevent 64 bit overflow after
  // multiplication with tsc_mul, with safety factor of 2.
  int shamt;
  for(shamt = 0; ((tsc_delta_in_update * 2) >> shamt) > UINT_MAX; shamt++) 
    { /* do nothing */  }
  // This code was tested for shamt = 0 (e.g., processors of <= 2 GHZ)
  // Code below should work for other shamt, but hasn't been tested

  global_xen_time.tsc_scale.mul_frac = 
    (1000000000ULL << 32) / (tsc_delta_in_update >> shamt);
  // Positive tsc_scale.shift means left shift
  global_xen_time.tsc_scale.shift = -shamt;

  if(0) {
    printk_red("(local_tsc=%lu,stime=%lu,mul_frac=%u,shift=%d)\n", 
	       (__u32) global_xen_time.local_tsc_stamp,
	       (__u32) global_xen_time.stime_local_stamp,
	       global_xen_time.tsc_scale.mul_frac,
	       global_xen_time.tsc_scale.shift);

  }

  Alarm *a;
  a = register_alarm(XEN_CLOCK_SYNC_PERIOD, time_sync_fire, NULL);
  assert(a != NULL);
}

static void time_sync_init(void) {
  time_sync_fire(NULL);

  // Start timer for time synchronization updates
  // As in Xen 3.0, schedule an update every second
  Alarm *a;
  a = register_alarm(XEN_CLOCK_SYNC_PERIOD, time_sync_fire, NULL);
  assert(a != NULL);
}

static void thread_Xen_updateTime(BasicThread *target) {
  assert(nexusthread_isXen(target));
  shared_info_t *shinfo = thread_getSharedInfo(target);
  if(shinfo == NULL) {
    return;
  }
  vcpu_info_t *vcpu_info = &shinfo->vcpu_info[0];
  update_vcpu_system_time(vcpu_info);
}

static void set_slow_syscall_trap(void) {
  set_fast_trap(LINUX_SYSCALL_VECTOR, 0, 0);
}

void thread_Xen_switchIn(BasicThread *target) {
  thread_Xen_updateTime(target);
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(target);

  if(kts->xen_regs.cr0 & X86_CR0_TS) {
    stts();
  } else {
    clts();
  }
  if(likely(kts->traps != NULL &&
	    kts->traps[LINUX_SYSCALL_VECTOR].cs != 0)) {
    set_fast_trap(LINUX_SYSCALL_VECTOR, 
		  kts->traps[LINUX_SYSCALL_VECTOR].cs,
		  kts->traps[LINUX_SYSCALL_VECTOR].address);
  } else {
    set_slow_syscall_trap();
  }
}

void thread_Xen_switchOut(BasicThread *target) {
  KernelThreadState *kts = thread_Xen_checkAndGetKTS(target);
  kts->xen_regs.cr0 = read_cr0();
  set_slow_syscall_trap();
}

void xendom_fpu_taskswitch(int set) {
  KernelThreadState *kts = 
    thread_Xen_checkAndGetKTS(nexusthread_self());

  if(set) {
    stts();
  } else {
    clts();
  }
  kts->xen_regs.cr0 = read_cr0();
}

static inline void version_update_begin(u32 *version)
{
    /* Explicitly OR with 1 just in case version number gets out of sync. */
    *version = (*version + 1) | 1;
    wmb();
}

static inline void version_update_end(u32 *version)
{
    wmb();
    (*version)++;
}

static inline void __update_vcpu_system_time(vcpu_info_t *vcpu_info)
{
    struct vcpu_time_info *u = &vcpu_info->time;

    version_update_begin(&u->version);

    u->tsc_timestamp     = global_xen_time.local_tsc_stamp;
    u->system_time       = global_xen_time.stime_local_stamp;
    u->tsc_to_system_mul = global_xen_time.tsc_scale.mul_frac;
    u->tsc_shift         = (s8)global_xen_time.tsc_scale.shift;

    version_update_end(&u->version);
}

static void update_vcpu_system_time(vcpu_info_t *vcpu_info)
{
    if ( vcpu_info->time.tsc_timestamp !=
         global_xen_time.local_tsc_stamp )
        __update_vcpu_system_time(vcpu_info);
}

/////////////////////////////
//// Non-virtualized instruction trap

// Xen kernels prefix non-trapping instructions that must be
// virtualized with a UD2 so that they are forced into the VMM

// This code is adapted from Xen
#define EXCRET_fault_fixed (1)

#define xen_major_version() (3)
#define xen_minor_version() (0)
// static int supervisor_mode_kernel = 0;

int cpuid_hypervisor_leaves(uint32_t idx, 
			    uint32_t *eax, uint32_t *ebx, 
			    uint32_t *ecx, uint32_t *edx)
{
  idx -= 0x40000000;
  if ( idx > 2 )
    return 0;

  switch ( idx )
    {
    case 0:
      *eax = 0x40000002; /* Largest leaf        */
      *ebx = 0x566e6558; /* Signature 1: "XenV" */
      *ecx = 0x65584d4d; /* Signature 2: "MMXe" */
      *edx = 0x4d4d566e; /* Signature 3: "nVMM" */
      break;

    case 1:
      *eax = (xen_major_version() << 16) | xen_minor_version();
      *ebx = 0;          /* Reserved */
      *ecx = 0;          /* Reserved */
      *edx = 0;          /* Reserved */
      break;

    case 2:
      *eax = 1;          /* Number of hypercall-transfer pages */
      *ebx = 0x40000000; /* MSR base address */
      *ecx = 0;          /* Features 1 */
      *edx = 0;          /* Features 2 */
      break;

    default:
      BUG();
    }

  return 1;
}

static void propagate_page_fault(__u32 target, int ignored) {
  printk_red("Propagate page fault not implemented!\n");
  assert(0);
}

static int emulate_forced_invalid_op(InterruptState *regs)
{
  Map *m = nexusthread_current_map();
  char sig[5], instr[2];
  uint32_t a, b, c, d;
  unsigned long eip, rc;

  a = regs->eax;
  b = regs->ebx;
  c = regs->ecx;
  d = regs->edx;
  eip = regs->eip;

  /* Check for forced emulation signature: ud2 ; .ascii "xen". */
  if ( (rc = peek_user(m, (__u32) eip, sig, sizeof(sig))) != 0 )
    {
      propagate_page_fault(eip + sizeof(sig) - rc, 0);
      return EXCRET_fault_fixed;
    }
  if ( memcmp(sig, "\xf\xbxen", sizeof(sig)) )
    return 0;
  eip += sizeof(sig);

  /* We only emulate CPUID. */
  if ( ( rc = peek_user(m, (__u32) eip, instr, sizeof(instr))) != 0 )
    {
      propagate_page_fault(eip + sizeof(instr) - rc, 0);
      return EXCRET_fault_fixed;
    }
  if ( memcmp(instr, "\xf\xa2", sizeof(instr)) )
    return 0;
  eip += sizeof(instr);

  __asm__ ( 
	   "cpuid"
	   : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
	   : "0" (a), "1" (b), "2" (c), "3" (d) );

  if ( regs->eax == 1 )
    {
      /* Modify Feature Information. */
      clear_bit(X86_FEATURE_VME, &d);
      clear_bit(X86_FEATURE_DE,  &d);
      clear_bit(X86_FEATURE_PSE, &d);
      clear_bit(X86_FEATURE_PGE, &d);
      // if ( !supervisor_mode_kernel )
      clear_bit(X86_FEATURE_SEP, &d);
      // if ( !IS_PRIV(current->domain) )
      clear_bit(X86_FEATURE_MTRR, &d);
    }
  else
    {
      (void)cpuid_hypervisor_leaves(regs->eax, &a, &b, &c, &d);
    }

  regs->eax = a;
  regs->ebx = b;
  regs->ecx = c;
  regs->edx = d;
  regs->eip = eip;

  return EXCRET_fault_fixed;
}

static __u32 *Descriptor_from_Selector_helper(Selector sel) {
  KernelThreadState *kts = 
    thread_Xen_checkAndGetKTS(nexusthread_self());
  __u32 *desc;
  if(sel.ti) {
    // LDT
    if(sel.index >= kts->xen_ldt.num_entries) {
      return NULL;
    }
    desc = (__u32 *)
      (NEXUS_DOMAIN_LDT_START + sel.index * sizeof(SegmentDescriptor));
  } else {
    // GDT
    if((0 <= sel.index && sel.index < kts->xen_gdt.entries) || 
       (FIRST_RESERVED_GDT_ENTRY <= sel.index && 
	sel.index <= LAST_RESERVED_GDT_ENTRY)) {
      desc = (__u32 *)
	(NEXUS_DOMAIN_GDT_START + sel.index * sizeof(SegmentDescriptor));
    } else {
      return NULL;
    }
  }
  return desc;
}

int Descriptor_from_Selector(Selector sel, SegmentDescriptor *rv) {
  __u32 *desc = Descriptor_from_Selector_helper(sel);
  if(desc == NULL) {
    return -1;
  }
  memcpy(rv, desc, sizeof(*rv));
  return 0;
}

/* 
   Most of this code is taken from Xen 3.0.
*/
int xendom_fixup_seg(Selector sel, unsigned long offset) {
  if(sel.rpl == 0) {
    printk_red("can't fixup rpl = 0");
    return -1;
  }
  if(!sel.ti) {
    if(sel.index >= FIRST_RESERVED_GDT_ENTRY) {
      printk_red("can't flip a reserved GDT entry\n");
      return -1;
    }
  }

  Map *m = nexusthread_current_map();
  __u32 *desc = Descriptor_from_Selector_helper(sel);
  // Get pointer to descriptor

  // Check to see that the pointer is mapped
  if(desc == NULL || fast_virtToPhys(m, (__u32) desc, 0, 0) == 0) {
    printk_red("cannot flip not present descriptor\n");
    return -1;
  }

  unsigned long a = desc[0], b = desc[1], base, limit;

  /* Decode base and limit. */
  int err = 0;
  if ( (b & (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|
	     _SEGMENT_G|_SEGMENT_CODE|_SEGMENT_DPL)) !=
       (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|_SEGMENT_G|_SEGMENT_DPL) ) {
    printk_red("Bad segment %08lx:%08lx\n", a, b);
    goto fail;
  }

  base  = SegmentDescriptor_get_base32(*(SegmentDescriptor*)desc, &err);
  if(err != 0) {
    printk_red("Bad segment %08lx:%08lx\n", a, b);
    goto fail;
  }
  limit = SegmentDescriptor_get_limit32(*(SegmentDescriptor*)desc, &err);
  if(err != 0) {
    printk_red("Bad segment %08lx:%08lx\n", a, b);
    goto fail;
  }

  if ( b & _SEGMENT_EC )
    {
      /* Expands-down: All the way to zero? Assume 4GB if so. */
      if ( ((base + limit) < PAGE_SIZE) && (offset <= limit)  )
        {
	  /* Flip to expands-up. */
	  limit = NEXUS_START - base;
	  goto flip;
        }
    }
  else
    {
      /* Expands-up: All the way to Xen space? Assume 4GB if so. */
      if ( ((NEXUS_START - (base + limit)) < PAGE_SIZE) &&
	   (offset > limit) )
        {
	  /* Flip to expands-down. */
	  limit = -(base & PAGE_MASK);
	  goto flip;
        }
    }
 fail:
  return -1;
 flip:
  limit = (limit >> 12) - 1;
  a &= ~0x0ffff; a |= limit & 0x0ffff;
  b &= ~0xf0000; b |= limit & 0xf0000;
  b ^= _SEGMENT_EC; /* grows-up <-> grows-down */

  desc[0] = a;
  desc[1] = b;
  return 0;
}
