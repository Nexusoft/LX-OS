syscall Thread {
  decls __callee__ {
    includefiles { "<nexus/defs.h>"}
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/machineprimitives.h>" }
    includefiles { "<nexus/clock.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/thread-private.h>" }
    includefiles { "<nexus/thread-inline.h>" }
    includefiles { "<nexus/segments.h>" }
    includefiles { "<nexus/ddrm.h>" }
    includefiles { "<nexus/djwilldbg.h>" }
    includefiles { "<asm/param.h>" }
    includefiles { "Mem.interface.h" }
  }

  interface  __NoGenErrno__ void 
  Yield(void) 
  {
    nexusthread_yield();
  }

  /** Kill all threads in the process EXCEPT the caller */
  interface void 
  KillAll(void) 
  {
    ipd_killall(nexusthread_current_ipd());
  }

  /** Kill the caller thread */
  interface void 
  Exit(int exit_status, unsigned int base_page, unsigned int npages) 
  {
    if (npages > 0)
      Mem_FreePages_Handler(-1, -1, NULL, 0,
			    base_page, npages);
 
    nexusuthread_current()->exit_status = exit_status;
    nexusthread_exit();
  }

  // wakes anyone waiting for the current thread
  interface void  
  Notify(int notify_status) 
  {
    nexusuthread_current()->exit_status = notify_status;
    nexusthread_notify(curt);
  }

  /// Fork the current process. Follows posix semantics.
  //
  //  XXX really shouldn't be here, but in IPD.sc, or so. 
  //  XXX is still broken
  interface int 
  ForkProcess(void) 
  {
	  return ipd_fork(nexusthread_current_ipd(), nexusthread_self(),
			  NULL, NULL)->id;
  }

  interface int Fork(void *pc, void *esp_or_hint, int npages,
		     void *initial_stack, int initial_stack_len) {
    /* Audited 6/4/2006 for safe arg usage */

    // This way of doing fork is crufty; should just provide pc, sp,
    // and let user create the stack

    // pc: Eventually is passed down to initialize_ustate, where it is
    // used to initialize eip: Safe (a bad PC will GPF immediately)

    // If npages == 0, the stack has been preallocated. ESP is the initial esp.

    // Else, allocate the new pages, using esp as the initial
    // hint. Use initial_stack is only used to populate stack when
    // npages > 0

    Map *currentmap = nexusthread_current_map();
    UThread *ut;

    void *esp;
    if(npages > 0) {
      // Caller wants us to do the allocation
      // Piggy backed allocation
      __u32 hint = (__u32)esp_or_hint;
      if(hint & (PAGESIZE - 1)) {
	printk_red("Thread_Fork() hint (%p) must be page aligned\n", 
		   (void *)hint);
	return -SC_INVALID;
      }
      __u32 vaddr = Mem_GetPages_Handler(-1, -1, NULL, 0, npages, hint);
      if(vaddr == 0) {
	printk_red("Thread_Fork(): out of memory (asked for %d @ %p)!\n", 
		   npages, hint);
	return -SC_NOMEM;
      }
      if(0 && vaddr != hint) {
	printk_red("Thread_Fork(): Stack not on hint (%p %p %d)\n",
		   vaddr, hint, npages);
      }

      esp = (char *)vaddr + npages * PAGESIZE;
      esp -= initial_stack_len;
      if(peek_user(currentmap, (__u32) initial_stack, esp, initial_stack_len) != 0) {
	printk_red("Thread_Fork(): Error copying initial stack\n");
	Mem_FreePages_Handler(-1, -1, NULL, 0, (__u32) vaddr, npages);
	return -SC_ACCESSERROR;
      }
    } else {
      // Already allocated by caller
      esp = esp_or_hint;
    }


    DDRM *ddrm;
    int dbg = 0;
    thread_callback_t pre_fork_hook = NULL;
    void *pre_fork_data = NULL;
    printk_djwill("FORK: looking for ddrm...for ipd %d\n", nexusthread_current_ipd()->id);
    ddrm = ipd_get_ddrm(nexusthread_current_ipd());
    if(ddrm != NULL){
      pre_fork_hook = ddrm_register_device_thread;
      pre_fork_data = ddrm;
    }

    ut = nexusuthread_create(currentmap, (unsigned int)pc, (__u32)esp, 
			     nexusthread_current_ipd(), 
			     pre_fork_hook, pre_fork_data); /* register
							    thread in
							    ddrm if
							    necessary */
    nexusthread_start((BasicThread *)ut, 0);
    return nexusthread_id((BasicThread*)ut);
  }

  interface void 
  USleep(int usec) 
  {
    usec /= USECPERTICK;
    if (!usec)
	    usec = 1;
    nexusthread_sleep(usec);
  }
  
  interface void 
  UnlockAndUSleep(int usec, unsigned int *spinlock)
  {
    int spl, zero = 0;

    spl = disable_intr();
    poke_user(nexusthread_current_map(), (unsigned int) spinlock, 
	      (void *) &zero, sizeof(int));
    nexusthread_sleep(usec/USECPERTICK);
    restore_intr(spl);
  }

  interface int  
  Block(int *lock, int msecs) 
  {
    int intlevel, zero = 0, ret;

    intlevel = disable_intr();
    
    // give up lock
    if (lock)
      poke_user(nexusthread_current_map(), (unsigned int) lock, &zero, sizeof(int));

    ret = nexusthread_block(msecs);
    
    restore_intr(intlevel);
    return ret;
  }

  interface __NoGenErrno__ void 
  Unblock(int thread_id) 
  {
    nexusthread_unblock(thread_id);
  }
  
  interface int 
  GetProcessID(void) 
  {
    return nexusthread_current_ipd()->id;
  }

  interface int 
  GetID(void) 
  {
    return nexusthread_id(nexusthread_self());
  }

  interface int 
  CancelSleep(int target_thread_id) 
  {
    BasicThread *t = nexusthread_find(target_thread_id);
    IPD *ipd = nexusthread_current_ipd();

    if (!t)
      return -SC_INVALID;
    if (t->type != USERTHREAD) {
      nexusthread_put(t);
      return -SC_INVALID;
    }
    if (!ipd || ipd != nexusthread_get_base_ipd(t)) {
      nexusthread_put(t);
      return -SC_NOPERM;
    }

    int rv = nexusthread_cancelsleep(t);
    nexusthread_put(t);
    return rv;
  }

  interface int Kill(int thread_id) {
    BasicThread *t = nexusthread_find(thread_id);
    IPD *ipd = nexusthread_current_ipd();
    
    if (!t)
      return -SC_INVALID;
    if (t->type != USERTHREAD) {
      nexusthread_put(t);
      return -SC_INVALID;
    }
    if (!ipd || ipd != nexusthread_get_base_ipd(t)) {
      nexusthread_put(t);
      return -SC_NOPERM;
    }

    int rv = nexusthread_kill(t);
    nexusthread_put(t);
    return rv;
  }

  interface int 
  SetMyTCB(void *tcb) 
  {
    BasicThread *t = nexusthread_self();
    assert(t->type == USERTHREAD);
    UThread *ut = (UThread *)t;

    ut->kthread->kts->user_tcb = tcb;

    set_local_tcb(tcb);
    __asm__ __volatile__ ( "movl %0, %%gs" : : "r" (KSHMEM_GS));
    return 0;
  }

  interface int 
  RegisterTrap(int idx, void *trap_fn) 
  {
    return ipd_register_trap(nexusthread_current_ipd(), idx, (unsigned)trap_fn);
  }

  interface int 
  RegisterWatchpoint(int type, int size, void *addr)
  {
	return breakpoint_add(type, size, (unsigned long)addr);
  }

  interface void 
  UnRegisterWatchpoint(int idx) 
  {
	breakpoint_del(idx);
  }

  interface void 
  Reboot(void)
  {
    machine_restart();
  }

}
