syscall Xen {

  decls {
    // for application
    int Xen_PreInit(void);

    // for kernel
    struct InterruptState;
    int Xen_PreInit_handler(struct InterruptState *is);

    struct mmu_update;
    struct mmuext_op;
    struct multicall_entry;
    struct trap_info;
  }
  decls __callee__ {
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/syscall-defs.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/thread-private.h>" }
    includefiles { "<nexus/machineprimitives.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/mem.h>" }
    includefiles { "<xen/xen-compat.h>" }
    includefiles { "<xen/xen.h>" }
    includefiles { "<xen/event_channel.h>" }
    includefiles { "<xen/sched.h>" }
    includefiles { "<xen/callback.h>" }
    includefiles { "<xen/physdev.h>" }
    includefiles { "<asm/errno.h>" }
    includefiles { "<asm/param.h>" } // for HZ

    includefiles { "<xen-private/cpumask.h>" }
    includefiles { "<nexus/net.h>" }
    includefiles { "<nexus/thread-inline.h>" }

    includefiles { "\"Net.interface.h\"" } // for Router_Recv
    // for decoding the bitmaps in mmu_op MULTI

    int Xen_PreInit_handler(struct InterruptState *is) {
      /*
	Switch IPD to Xen mode. The only currently allowed state transition is
	NATIVE => XEN

	- Returns to caller as CPL1 (CS,DS,ES,FS,GS override)

	{ // removed 
	- All page table entries above NEXUS_VMM_START and below
	NEXUS_START are changed to System
	}

	- All pages associated with page tables are marked with
	appropriate Xen type

	- Zap any PTEs below NEXUS_VMM_START (not necessary, but good
	for sanity checking)

	Xen mode has the following semantics:
	- All future GetPages pages are mapped as System, to simplify MMU design
	- TLS is rendered invalid
	- Enables the other Xen syscalls and specialized trap handling
	- On exit of the IPD, all pages used for machine
	(e.g. !FT_RDWR) pages are deallocated

	// TODO
	Change GDT (no GDT entries to above KERNELVADDR)
	The default Nexus GDT contains such entries
      */
      printk_red("pre_init()");
      IPD *ipd = nexusthread_current_ipd();
      if(ipd->xen.cpu0 != NULL) {
	printk_red("IPD already has a Xen controller thread!\n");
	return -SC_INVALID;
      }
      switch(ipd->type) {
      case NATIVE:
	// OK
	break;
      case XEN:
	printk_red("IPD is already xen!\n");
	return -SC_INVALID;
      default:
	// unknown ipd type
	nexuspanic();
      }
      if(ipd->threadcount != 1) {
	printk_red("IPD has %d != 1 threads!\n", ipd->threadcount);
	return -SC_INVALID;
      }
      
      // Scan through memory map.
      // [0,NEXUS_VMM_START] => raise error

      // We used to do :
      // 	[NEXUS_VMM_START, NEXUS_START)=> set to supervisor
      // but this is now the responsibility of userspace
      u32 vaddr;
      Map *m = nexusthread_current_map();
      int num_unmapped = 0;
      for(vaddr = 0; vaddr < NEXUS_VMM_START; vaddr += PAGESIZE) {
	int flags;
	flags = Map_getPageFlags(m, vaddr);
	if(!(flags & PAGEFLAG_NULL) // PTE valid (e.g. non-null parent PDE)
	   && (flags & PAGEFLAG_PRESENT)
	   && (flags & PAGEFLAG_USER)) {
	  // pages already below NEXUS_VMM_START and should be removed
	  if(0) {
	    u32 paddr = fast_virtToPhys_nocheck(m, vaddr);
	    printk_red("(%d) User page found at %p (=>%p)! (can't have any below NEXUS_VMM_START)\n", flags, vaddr, paddr);
	  }
	  unmap_pages(m, vaddr, 1);
	  num_unmapped++;
	}
      }
      printk_red("%d pages unmapped\n", num_unmapped);

      // Walk through page table and change to Xen page flags
      Map_Xen_initFTTypes(m, ipd);

      Map_setAnonCleanup(m, ipd);

      // All tests pass, go through with it
      ipd->type = XEN;
      ipd->xen.cpu0 = nexusthread_self();

      // Set up per-domain page table (covers 4MB)
      // This is a per-domain, kernel-owned portion of the address space.
      // Currently, it is used to store the GDT

      // This must be after Map_Xen_initFTTypes() because we are about
      // to set the owner of this page to Nexus
      // This must also be after ipd->type = XEN due to assertions in xen.c
      xendom_setupDomainPagetable();

      is->cs = KXENCS;
      is->ds = KXENDS;
      is->es = KXENDS;
      is->ss = KXENDS;

      // Nexus maintains the invariant that the Xen domains always own
      // the FPU state
      nexusthread_fpu_trap();

      // struct BasicThread *thread = nexusthread_self();
      printk_red("done with pre_init()");
      return 0;
    }

    // Currently supports only uniprocessor
    static int vcpumask_check(void *vcpumask) {
      cpumask_t mask;
      if(!peek_user(nexusthread_current_map(),
		    (__u32)vcpumask, &mask.bits, sizeof(mask.bits))) {
	printk("vcpumask access error\n");
	return -EACCES;
      }
      /* check mask to verify that only processor 0 is selected */
      if(!(cpus_weight(mask) == 1 && first_cpu(mask) == 0)) {
	printk("Strange CPU mask passed in!\n");
	return -EINVAL;
      }
      return 0;
    }
  }

  decls __caller__ {
    // Xen_PreInit() is a custom system call due to non-standard return
    // (to CPL1 instead of CPL3)
    int Xen_PreInit(void) {
      int rv = nexuscall0(SYS_Xen_PreInit_CMD);
      // TLS is not usable from Xen VMM
      __errno_use_tls = 0;
      // Can't use sysenter from cpl1
      __syscall_use_sysenter = 0;
      return rv;
    }
  }

  /* 
     Allocate numpgs contiguous physical pages. Returns the physical
     address of the first page, NULL if error (e.g. out of memory).
  */
  interface unsigned AllocPages(int numpgs) {
#define CHECK_XEN()						\
    if(nexusthread_current_ipd()->type != XEN) {		\
      printk_red("%s: not called for Xen IPD\n", __FUNCTION__);	\
      return -SC_INVALID;					\
    }

    IPD *ipd = nexusthread_current_ipd();
    
    void *vaddr = getKernelPages(numpgs);
    if(vaddr == NULL) {
      return (unsigned) NULL;
    } else {
      __u32 paddr = VIRT_TO_PHYS(vaddr);
      Page *page = PHYS_TO_PAGE(paddr);
      int i;
      pagememzero_n(VADDR(page), numpgs);
      for(i=0; i < numpgs; i++) {
	page->owner = ipd->id;
	page->type = FT_RDWR;
	page->xenrefcnt = 0;
      }
      return paddr;
    }
  }

  interface int FreePages(unsigned int paddr, int numpgs) {
    // XXX FreePages is not integrated properly with reference count system
    // printk_red("Xen FreePages() is not correct!\n");
    CHECK_XEN();
    int rv = 
      freeKernelPages_Xen(nexusthread_current_ipd(), paddr, numpgs);
    if(rv == 0) {
      return 0;
    } else {
      printk_red("Xen_FreePages(): error code %d from page free\n", rv);
      return -SC_ACCESSERROR;
    }
  }

  interface unsigned int GetPDBR(void) {
    CHECK_XEN();
    // Get the base pointer of xen
    Map *map = nexusthread_current_map();
    Page *pdbr_page = Map_getRoot(map);
    return PADDR(pdbr_page);
  }

  interface unsigned int ReadPDBR(char *dest) {
    CHECK_XEN();
    Map *m = nexusthread_current_map();
    return 
      poke_user(m, (__u32) dest, (char *)VADDR(Map_getRoot(m)), PAGE_SIZE);
  }

  interface int GetMach2Phys(unsigned int *physbase_p, int *num_pages_p) {
    CHECK_XEN();
    Map *m = nexusthread_current_map();
    int rv;

    __u32 paddr = VIRT_TO_PHYS(machine_to_phys);
    assert((paddr & PAGE_OFFSET_MASK) == 0);
    int num_pages = XEN_MPT_LEN / PAGE_SIZE;

    rv = poke_user(m, (__u32)physbase_p, &paddr, sizeof(*physbase_p));
    if(rv) return -SC_ACCESSERROR;
    rv = poke_user(m, (__u32)num_pages_p, &num_pages, sizeof(*num_pages_p));
    if(rv) return -SC_ACCESSERROR;

    return 0;
  }

  interface int RegisterSharedMFN(unsigned int shared_info_mfn) {
    CHECK_XEN();
    Page *page = Page_Xen_fromMFN_checked(shared_info_mfn);
    if(page == NULL || page->type != FT_RDWR) {
      printk_red("shared_info_mfn must be owned & FT_RDWR!\n");
      return -EINVAL;
    }
    return xendom_registerSharedMFN(shared_info_mfn);
  }

  // Set a range of memory addresses that are copied into every pinned
  // L2 table (e.g. PDIR)
  interface int Set_VMM_PDIR(int pdoffset, unsigned int *entries, int len) {
    CHECK_XEN();
    return xendom_set_VMM_PDIR(pdoffset, entries, len);
  }

  //  VNet interface. Send and Receive are done with uncooked packets,
  //  e.g. packets with link headers

  // Bring up a virtual NIC. An IRQ must already be bound to it
  // The MAC address of the NIC is output to assigned_mac
  interface int VNet_Init(int vnic_num, char *assigned_mac) {
    printk_red("%s no longer supported!\n", __FUNCTION__);
    return -1;
  }

  interface int VNet_Send(int vnic_num, char *user_data, int len) {
    printk_red("%s no longer supported!\n", __FUNCTION__);
    return -1;
  }

  interface int VNet_HasPendingRecv(int vnic_num) {
    printk_red("%s no longer supported!\n", __FUNCTION__);
    return -1;
  }

  interface int /* length */ VNet_Recv(int vnic_num, char *data, int len) {
    printk_red("%s no longer supported!\n", __FUNCTION__);
    return -1;
  }

  interface int DeliverVIRQ(int virq_num) {
    // Deliver VIRQ on behalf of VMM
    CHECK_XEN();
    return xendom_send_virq(virq_num);
  }

  // Xen hypervisor calls

  // Unless otherwise stated, these hypervisor calls are equivalent to
  // those of Xen 3.0

  interface long H_mmu_update(struct mmu_update *ureqs, unsigned int count,
			     unsigned int *pdone, unsigned int dom_id) {
#define INVALID() do { printk_red("mmu_update(): invalid at %d", __LINE__); goto invalid; } while(0)
    CHECK_XEN();
    IPD *ipd = nexusthread_current_ipd();
    Map *m = nexusthread_current_map();

    int i;
    for(i=0; i < count; i++) {
      mmu_update_t req;
      if(peek_user(m, (__u32) &ureqs[i], &req, sizeof(req)) != 0) {
	printk_red("mmu_update access error\n");
	return -EACCES;
      }

      unsigned int ptr = req.ptr;
      unsigned int val = req.val;
      int update_type = ptr & 0x3;
      ptr &= ~0x3;

      switch(update_type) {
      case MMU_NORMAL_PT_UPDATE: {
	int offset = (ptr & PAGE_OFFSET_MASK) >> 2;

	if((ptr >> PAGE_SHIFT) >= maxframenum) {
	  printk_red("H_mmu_update(type=%d): ptr %p is outside of physical address range\n",
		     update_type, (void *) ptr);
	  return -EINVAL;
	}

	Page *page = PHYS_TO_PAGE(ptr);
	if( !(page->ram && page->owner == ipd->id) ) {
	  // ownership check is done below
	  printk_red("H_mmu_update: target %p is not ram page (%d) or wrong owner (%d %d)\n",
		     (void *) ptr, page->ram, page->owner, ipd->id);
	  return -EINVAL;
	}

	__u32 *dest_loc = &((__u32*)VADDR(page))[offset];
	// Don't do verification or update if value matches
	if(*dest_loc != val) {
	  switch(page->type) {
	  case FT_PDIRECTORY:
	    if(!verify_pde(page, nexusthread_self(), offset, val, 1)) {
	      INVALID();
	    }
	    // Put old value
	    put_pde(page, offset, *dest_loc);
	    /* Fall through to write */
	    break;
	  case FT_PTABLE:
	    if(page->u.fb.is_mapped) {
	      printk_red("warning: updating fb ptable\n");
	      nexusthread_dump_regs_stack(nexusthread_self());
	      page->u.fb.is_mapped = 0;
	      printk_green("looping");  while(1);
	    }
	    if(!verify_pte(val)) {
	      INVALID();
	    }
	    /* Fall through to write */
	    break;
	  case FT_RDWR:
	    // Let this pass through as if it was a regular write
	    /* Fall through to write */
	    break;
	  case FT_LDT:
	  case FT_GDT:
	    printk_red("Can't MMU_update on a *DT!\n");
	    return -EINVAL;
	  case FT_NRDWR:
	    // this doesn't make any sense; no nexus pages should be owned by Xen domain
	  default:
	    // frame table corruption!!!
	    assert(0);
	  }
	  // success, write the value
	  // sanity check address computations
	  assert( 
		 (((__u32) dest_loc) & PAGE_OFFSET_MASK) == 
		 (((__u32) ptr) & PAGE_OFFSET_MASK)
		 );
	  *dest_loc = val;
	}
	break;
      }
      case MMU_MACHPHYS_UPDATE: {
	if(m2p_update(ipd, ptr, val) != 0) {
	  printk_red("failure at %d\n", i);
	  INVALID();
	}
	break;
      }
      default:
	printk_red("MMU_update: unknown sub-type %d\n", update_type);
	INVALID();
      }
    }
    if(pdone != NULL) {
      assert(sizeof(i) == sizeof(*pdone));
      if(poke_user(m, (__u32) pdone, &i, sizeof(*pdone)) != 0) {
	printk_red("mmu_update(): could not put done\n");
	return -EINVAL;
      }
    }
    return 0;
  invalid:
    return -EINVAL;
  }

  decls __callee__ {
    static int pinHelper(int pintype, __u32 mfn) {
      Page *page = Page_Xen_fromMFN_checked(mfn);
      if(page == NULL) {
	return -EINVAL;
      }

      int rv = Page_Xen_Type_pin(nexusthread_current_ipd(),
			      nexusthread_self(), page, pintype);
      if(rv != 0) {
	printk_red("pintotype(%x=>%d) error %d\n", mfn, pintype, rv);
	return rv;
      }
      return 0;
    }

    typedef  long (*hypercall_table_t)(int ign0, int ign1, char *ign2, int is_async,
				       long a0, long a1, 
				       long a2, long a3,
				       long a4, long a5);
    extern unsigned long hypercall_table[];
    extern const int num_hypercalls;
  }
  // Xen implementation in xen/arch/x86/mm.c, do_mmuext_op
  interface long H_mmuext_op(struct mmuext_op *ops, unsigned int count, unsigned int *pdone, unsigned int foreigndom) {
    CHECK_XEN();

    IPD *ipd = nexusthread_current_ipd();
    BasicThread *t = nexusthread_self();
    // foreigndom is ignored
    if(foreigndom != DOMID_SELF) {
      printk("wrong domain id\n");
      return -EINVAL;
    }

    struct mmuext_op op;
    int i;
    Map *m = nexusthread_current_map();
    for(i=0; i < count; i++) {
      if(peek_user(m, (__u32)&ops[i], &op, sizeof(op)) != 0) {
	printk_red("mmuext_op access error at %d\n", i);
	return -EINVAL;
      }
      switch(op.cmd) {
      case MMUEXT_TLB_FLUSH_MULTI:
	{
	  int rv = vcpumask_check(op.arg2.vcpumask);
	  if(rv != 0) {
	    return rv;
	  }
	}
      case MMUEXT_TLB_FLUSH_LOCAL:
      case MMUEXT_TLB_FLUSH_ALL:
	// printk_red("<Xen_Flush>");
	flushTLB();
	break;
      case MMUEXT_PIN_L1_TABLE: {
	int rv = pinHelper(FT_PTABLE, op.arg1.mfn);
	if(rv != 0) {
	  return rv;
	}
	break;
      }
      case MMUEXT_PIN_L2_TABLE: {
	// printk_red("<<Pin %x>>", op.arg1.mfn);
	__u32 mfn = op.arg1.mfn;
	Page *page = Page_Xen_fromMFN_checked(mfn);
	if(page == NULL) {
	  return -EINVAL;
	}
	Page_Xen_PDIR_init(ipd, t, page);

	int rv = pinHelper(FT_PDIRECTORY, op.arg1.mfn);
	if(rv != 0) {
	  return rv;
	}
	break;
      }
      case MMUEXT_NEW_BASEPTR: {
	// Check type of target
	__u32 mfn = op.arg1.mfn;
	Page *page = Page_Xen_fromMFN_checked(mfn);
	if(page == NULL) {
	  return -EINVAL;
	}

	Page_Xen_PDIR_init(ipd, t, page);

	int rv = Page_Xen_Type_get(ipd, t, page, FT_PDIRECTORY);
	if(rv) {
	  printk_red("New PDIR %p is not OK!\n", (void *)mfn);
	  return -EINVAL;
	}

	Map *m = nexusthread_current_map();
	Page *old_pdbr_page = Map_getRoot(m);
	Page_Xen_Type_put(NULL,NULL, old_pdbr_page, FT_PDIRECTORY);

	// __u32 newPDBR = PADDR(page);
	// printk_red("cr3=%p", (void*) newPDBR);

	int intlevel = disable_intr();
	Map_setPDBR(m, page);
	Map_activate(m, t);
	restore_intr(intlevel);
	break;
      }
      case MMUEXT_INVLPG_MULTI: {
	int rv = vcpumask_check(op.arg2.vcpumask);
	if(rv != 0) {
	  return rv;
	}
      }
      case MMUEXT_INVLPG_ALL:
      case MMUEXT_INVLPG_LOCAL:
	flushTLB_one(op.arg1.mfn);
	break;
      case MMUEXT_SET_LDT: {
	int rv = xendom_vLDT_set(op.arg1.linear_addr, op.arg2.nr_ents);
	if(rv != 0) {
	  return rv;
	}
	break;
      }
      case MMUEXT_UNPIN_TABLE: {
	__u32 mfn = op.arg1.mfn;
	Page *page = Page_Xen_fromMFN_checked(mfn);
	// printk_red("<<Unpin %x>>", mfn);
	if(page == NULL) {
	  printk_red("Unpin table: could not get target %x", mfn);
	  return -EINVAL;
	}
	if(page->type != FT_PDIRECTORY) {
	  printk_red("Unpin table: target is wrong type\n");
	  return -EINVAL;
	}
	if(!(page->xenrefcnt & PAGE_TYPE_PINNED)) {
	  printk_red("Unpin: target is not pinned\n");
	  return -EINVAL;
	}
	Page_Xen_Type_unpin(nexusthread_current_ipd(), nexusthread_self(), 
			    page, FT_PDIRECTORY);
	break;
      }
      default:
	printk_red("MMUEXT op %d not implemented\n", op.cmd);
	if(1) {
	  return -EINVAL;
	} else {
	  printk_red("ignoring mmuext error ");
	  continue;
	}
	/*
	  MMUEXT_PIN_L4_TABLE
	  MMUEXT_PIN_L3_TABLE
	  MMUEXT_PIN_L2_TABLE
	  MMUEXT_SET_LDT
	*/
      }
    }
    int done = i;
    if(pdone != NULL) {
      if(poke_user(nexusthread_current_map(), (__u32)pdone, &done, sizeof(done)) != 0) {
	printk_red("could not poke pdone in mmuext\n");
	return -EACCES;
      }
    }
    return 0;
  }

  interface long H_set_callbacks(unsigned long event_selector,
		    unsigned long event_address,
		    unsigned long failsafe_selector,
		    unsigned long failsafe_address) {
    CHECK_XEN();
    int rv;
    struct callback_register event = {
      .type = CALLBACKTYPE_event,
      .flags = 0,
      .address.cs = event_selector,
      .address.eip = event_address,
    };
    rv = xendom_registerCallback(&event);
    if(rv != 0) {
      printk_red("setCallbacks: registerCallback(event) failed\n");
      return rv;
    }

    struct callback_register failsafe = {
      .type = CALLBACKTYPE_failsafe,
      .flags = CALLBACKF_mask_events,
      .address.cs = failsafe_selector,
      .address.eip = failsafe_address,
    };
    rv = xendom_registerCallback(&failsafe);
    if(rv != 0) {
      printk_red("setCallbacks: registerCallback(failsafe) failed\n");
      return rv;
    }

    return 0;
  }

  interface long H_set_trap_table(struct trap_info *user_table) {
    CHECK_XEN();
    // user_table is variable length. Termination is marked by
    // user_table[k].address == 0
    return xendom_setTrapTable(user_table);
  }

  interface long H_stack_switch(unsigned long ss, unsigned long esp) {
    CHECK_XEN();
    // printk_red("(stack switch %lx:%p)", ss, (void*)esp);
    return xendom_setExceptionStack(1, ss, esp);
  }

  interface long H_event_channel_op(int cmd, void *_user_op) {
    CHECK_XEN();
    Map *m = nexusthread_current_map();

    switch(cmd) {
    case EVTCHNOP_bind_virq: {
      evtchn_bind_virq_t bind_virq;
      evtchn_bind_virq_t *user_bind_virq = _user_op;
      int rv = peek_user(m, (__u32) user_bind_virq, &bind_virq, sizeof(bind_virq));
      if(rv != 0) {
	printk_red("error reading event_channel_op!\n");
	return -EACCES;
      }

      if(bind_virq.vcpu != 0) {
	printk_red("VIRQ bind: invalid vcpu %d specified!\n", bind_virq.vcpu);
	return -EINVAL;
      }
      int virq_num = bind_virq.virq;

      EventChannelData ecd;
	      ecd.type = XEN_EC_VIRQ;
	      ecd.virq.virq_num = virq_num;
      int channel_num = xendom_EventChannel_checkAndBind
	( EVENT_CHANNEL_ANY, ecd );
      if(channel_num < 0) {
	printk_red("Could not find port for VIRQ\n");
	return -EINVAL;
      }
      rv = xendom_VIRQ_checkAndBind(virq_num, channel_num);
      if(rv < 0) {
	printk_red("VIRQ either invalid or already bound\n");
	rv = -EINVAL;
	goto virq_unwind0;
      }
      assert(sizeof(user_bind_virq->port) == sizeof(channel_num));
      if( poke_user(m, (__u32) &user_bind_virq->port, &channel_num,
		    sizeof(user_bind_virq->port)) != 0 ) {
	int unbind_rv;
	rv = -EACCES;
	printk_red("Could not write out VIRQ bind result\n");
      virq_unwind0:
	unbind_rv = xendom_EventChannel_unbind(channel_num);
	assert(unbind_rv == 0);
	return rv;
      }
      break;
    }
    case EVTCHNOP_send: {
      static int last_port = -1;
      evtchn_send_t args;
      if(peek_user(m, (__u32)_user_op, &args, sizeof(args)) != 0) {
	printk_red("channel_op_send(): could not read\n");
	return -EACCES;
      }
      if(last_port != args.port) {
	printk_red("Ignoring EVTCHNOP_send(%d)\n", args.port);
	last_port = args.port;
      }
      return -ENOSYS;
    }
    case EVTCHNOP_bind_ipi: {
      struct evtchn_bind_ipi args;
      if(peek_user(m, (__u32)_user_op, &args, sizeof(args)) != 0) {
	printk_red("event_channel_op.bind_ipi(): could not peek args");
	return -EACCES;
      }
      if(args.vcpu != 0) {
	printk_red("event_channel_op.bind_ipi(): vcpu %d specified!\n",
                   args.vcpu);
	return -EINVAL;
      }
      EventChannelData ecd;
	      ecd.type = XEN_EC_IPI;
	      ecd.virq.virq_num = EVENT_CHANNEL_ANY;
      int channel_num = xendom_EventChannel_checkAndBind
	( EVENT_CHANNEL_ANY, ecd );
      if(channel_num < 0) {
	printk_red("could not bind IPI\n");
	return -EINVAL;
      }
      args.port = channel_num;
      if(poke_user(m, (__u32)_user_op, &args, sizeof(args)) != 0) {
	printk_red("event_channel_op.bind_ipi(): could not poke args");
	int rv;
	rv = xendom_EventChannel_unbind(channel_num);
	assert(rv == 0);
	return -EACCES;
      }
      break;
    }
    case EVTCHNOP_close: {
      evtchn_close_t args;
      if(peek_user(m, (__u32)_user_op, &args, sizeof(args)) != 0) {
	printk_red("event_channel.close(): could not peek args");
	return -EACCES;
      }
      if(args.port < 0 || args.port > NUM_EVENT_CHANNELS) {
	printk_red("invalid port number\n");
	return -EINVAL;
      }
      printk_red("unbinding %d\n", args.port);
      return xendom_EventChannel_unbind(args.port);
    }
    default:
      printk_red("Unknown event_channel_op %d!\n", cmd);
      return -ENOSYS;
    }
    return 0;
  }

  interface long H_set_timer_op(unsigned long timeout_high, unsigned long timeout_low) {
    /* Request a timer event to be sent at the specified system time (time in nanoseconds since system boot). */
    CHECK_XEN();
    __u64 timeout = timeout_high;
    timeout <<= 32;
    timeout |= timeout_low;

    int ticks =
      (timeout * HZ) / 
      1000000000 /* ns per second */ ;

    // XXX Maybe we want to busy-wait here
    if(ticks == 0) {
      ticks = 1;
    }
    xendom_setSingleShotTimer(nexustime + ticks);
    return 0;
  }

  interface long H_arch_sched_op(int cmd, unsigned long arg) {
    CHECK_XEN();
    switch(cmd) {
    case SCHEDOP_yield:
      printk("SCHEDOP_yield, not implemented\n");
      return -ENOSYS;
    case SCHEDOP_poll:
      printk("SCHEDOP_poll, not implemented\n");
      return -ENOSYS;
    case SCHEDOP_block: {
      // This the virtualized version of the HLT instruction

      // From the manual: "removes the calling domain from the run
      // queue and causes it to sleep until an event is delivered to
      // it. No extra arguments are passed to this command."

      // SCHEDOP_block implicitly enables interrupts
      xendom_sti();
      xendom_block();
      break;
    }
    }
    return 0;
  }

  interface long H_callback_op(int cmd, void *arg) {
    CHECK_XEN();
    Map *m = nexusthread_current_map();
    switch(cmd) {
    case CALLBACKOP_register: {
      struct callback_register reg;
      if(peek_user(m, (__u32) arg, &reg, sizeof(reg)) != 0) {
	printk_red("callback_register: could not access %p\n", arg);
	return -EACCES;
      }
      return xendom_registerCallback(&reg);
    }
    case CALLBACKOP_unregister:
      printk_red("callbackop_unregister not implemented\n");
      return -ENOSYS;
    default:
      printk_red("unknown callbackop %d\n", cmd);
      return -ENOSYS;
    }
    ASSERTNOTREACHED();
  }

  interface long H_vm_assist(unsigned int cmd, unsigned int type) {
    CHECK_XEN();
    return xendom_vm_assist(cmd, type);
  }

  // Up to 16 frames, but may not overlap with the guest GDT entries
  interface long H_set_gdt(unsigned long *frame_list, int entries) {
    CHECK_XEN();
    if(entries > FIRST_RESERVED_GDT_ENTRY) {
      printk_red("set_gdt(): too many entries\n");
      return -EINVAL;
    }
    Map *m = nexusthread_current_map();
    unsigned long frames[FULL_GDT_PAGESIZE];
    // 512 entries per page
    int num_pages = 
      (entries + (GDT_ENTRIES_PER_PAGE - 1)) / 
      GDT_ENTRIES_PER_PAGE;
    if(peek_user(m, (__u32)frame_list, frames,
		 num_pages * sizeof(frame_list[0])) != 0) {
      printk_red("error copying frame list from user\n");
      return -EACCES;
    }
    return xendom_vGDT_set(frames, entries);
  }

  // Returns 0 if all hypercalls succeeded.

  // If a hypercall is not implemented by the kernel, returns the
  // offset of the hypercall so the user app can resume
  interface long H_multicall(struct multicall_entry *call_list, int nr_calls) {
    CHECK_XEN();
    // Xen starts off with a check to see if the multi-call was
    // re-entered; we do not.

    Map *m = nexusthread_current_map();
    int i;
    for(i=0; i < nr_calls; i++) {
      multicall_entry_t ent;
      if(peek_user(m, (__u32)&call_list[i], &ent, sizeof(ent)) != 0) {
	printk_red("multicall: error peeking at %d (%p)\n", i, &call_list[i]);
	return -EFAULT;
      }
      long result;
      if(likely(0 <= ent.op && ent.op < num_hypercalls)) {
	hypercall_table_t handler = (hypercall_table_t) hypercall_table[ent.op];
	result = 
	  handler
	  (-1, -1, NULL, 0,
	   ent.args[0], ent.args[1],
	   ent.args[2], ent.args[3],
	   ent.args[4], ent.args[5]);
	// printk_red("mc[%d/%d](%d=>%ld)", i, nr_calls, ent.op, result);
	if(result == -ENOSYS) {
	  printk_red(" %d=>%p =>enosys ", ent.op, handler);
	}
      } else {
	result = -ENOSYS;
      }
      if(poke_user(m, (__u32)&call_list[i].result, &result, sizeof(result)) != 0) {
	printk_red("multicall: error poking at %d\n", i);
	return -EFAULT;
      }
      if(result == -ENOSYS) {
	printk_red("multicall error %d=>%ld at %d\n", ent.op, result, i);
	return i;
      }
    }
    return 0;
  }

  interface long H_fpu_taskswitch(int set) {
    CHECK_XEN();
    xendom_fpu_taskswitch(set);
    return 0;
  }

  interface long H_update_descriptor(unsigned int _ma_low,
				     unsigned int _ma_high,
				     unsigned int _desc_low,
				     unsigned int _desc_high) {
    CHECK_XEN();
    unsigned long long ma = _ma_high;
    ma = (ma << 32) | _ma_low;
    unsigned long long desc = _desc_high;
    desc = (desc << 32) | _desc_low;

    Page *page = Page_Xen_fromMFN_checked(ma >> PAGE_SHIFT);
    if(page == NULL) {
      printk_red("update_descriptor(): bad ma %p%p\n", 
		 (__u32)(ma >> 32), (__u32)ma);
      return -EINVAL;
    }
    __u64 *real_loc = NULL;
    switch(page->type) {
    case FT_GDT:
      // No special checks needed for GDT, since the reserved pages are
      // owned by kernel, not user
      real_loc = (__u64 *)xendom_vGDT_toReal(ma);
      goto do_descriptor_check_and_write;

    case FT_LDT:
      real_loc = NULL;

    do_descriptor_check_and_write: ;
      // Sanity check the update before falling through to write
      if(unlikely( ! (check_and_fix_descriptor((unsigned long *)&desc) && 
		      ((ma & (sizeof(SegmentDescriptor) - 1))) == 0)
		   )) {
	printk_red("update_descriptor(): descriptor check failed, or alignment check failed\n");
	return -EINVAL;
      }
      goto do_write;

    case FT_RDWR: {
      do_write: ;
      char *dest = (char *)VADDR(page) + (ma & PAGE_OFFSET_MASK);
      memcpy(dest, &desc, sizeof(SegmentDescriptor));
      if(real_loc != NULL) {
	// Since GDT is shadowed, we need to copy the value to the real place
	memcpy(real_loc, &desc, sizeof(SegmentDescriptor));
      }
      //printk_red("updating (pt=%d) descriptor to %p%p", page->type, 
      //   ((__u32 *)&desc)[1], ((__u32 *)&desc)[0]);
      return 0;
    }
    default:
      printk_red("update_descriptor(): target page type is %d!\n", page->type);
      return -EINVAL;
    }
    ASSERTNOTREACHED();
  }

  interface long H_physdev_op (int cmd, void *_args) {
    CHECK_XEN();
    Map *m = nexusthread_current_map();
    switch(cmd) {
    case PHYSDEVOP_set_iopl: {
      struct physdev_set_iopl set_iopl;
      if(peek_user(m, (__u32)_args, &set_iopl, sizeof(set_iopl)) != 0) {
	printk_red("error copying iopl spec\n");
	return -EFAULT;
      }
      return xendom_set_iopl(set_iopl.iopl);
    }
    default:
        printk_red("physdev_op(%d) not implemented!\n", cmd);
        return -ENOSYS;
    }
  }
}
