syscall Thread {

  decls __callee__ {
    includefiles { "<nexus/defs.h>"}
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/machineprimitives.h>" }
    includefiles { "<nexus/clock.h>" }
    includefiles { "<nexus/guard.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/attest.h>" }
    includefiles { "<nexus/thread-private.h>" }
    includefiles { "<nexus/thread-inline.h>" }
    includefiles { "<nexus/synch.h>" }
    includefiles { "<nexus/guard.h>" }
    includefiles { "<nexus/segments.h>" }
    includefiles { "<nexus/djwilldbg.h>" }
    includefiles { "<asm/param.h>" }
    includefiles { "Mem.interface.h" }

  }

  interface  __NoGenErrno__ void 
  Yield(void) 
  {
    nexusthread_yield();
  }

  /** Where threads go to die.. */
  interface void
  ExitThread(void)
  {
    nexusthread_kill(curt);
  }

  /** Kill the process */
  interface void 
  Exit(int exit_status, unsigned int base_page, unsigned int npages) 
  {
    curt->ipd->exit_status = exit_status;
    ipd_kill(curt->ipd);
  }

  // pthread thread fork
  interface int 
  Fork(void *pc, void *esp_or_hint, int npages,
       void *initial_stack, int initial_stack_len) 
  {
    BasicThread *thread;
    unsigned long vaddr;
    void *esp;
    int lvl;

    lvl = disable_intr();

    if (npages > 0) {
      // Caller wants us to do the allocation
      
      // sanity check input
      vaddr = (unsigned long) esp_or_hint;
      if (vaddr & (PAGESIZE - 1)) {
	printk_red("%s: alloc not page aligned\n", __FUNCTION__); 
	restore_intr(lvl);
	return -SC_INVALID;
      }
      if (initial_stack_len > (npages << PAGE_SHIFT)) {
	printk_red("%s: stack out of bounds\n", __FUNCTION__);
	restore_intr(lvl);
	return -SC_NOMEM;
      }
     
      // allocate memory
      vaddr = Mem_GetPages_Handler(-1, -1, NULL, 0, npages, vaddr);
      if (vaddr == 0) {
	printk_red("%s: alloc failed\n", __FUNCTION__);
	restore_intr(lvl);
	return -SC_NOMEM;
      }

      // place stack at end of newly allocated region (grows down, after all)
      esp = (char *) vaddr + (npages * PAGESIZE);
      esp -= initial_stack_len;
      peek_user(curr_map, (__u32) initial_stack, esp, initial_stack_len);
    } else {
      // Already allocated by caller
      esp = esp_or_hint;
    }

    thread = (void *) nexusuthread_create((unsigned int) pc, (__u32) esp, curt->ipd);
    nexusthread_start_noint(thread, 0);
    restore_intr(lvl);
    return thread->id;
  }

  // Sleep for at least @param usec. 
  // Do NOT call this for delays << 1ms. Use busy waiting instead.
  interface void 
  USleep(int usec) 
  {
    nexusthread_usleep(usec);
  }
  
  /** Nexus version of getpid() */
  interface int 
  GetProcessID(void) 
  {
    return curt->ipd->id;
  }

  /** Nexus version of getppid() */
  interface int
  GetParentID(void)
  {
    return curt->ipd->parent ? curt->ipd->parent->id : 0;
  }

  interface unsigned long long
  Times(int do_process, int do_user)
  {
    return nexusthread_times(curt, do_process, do_user);
  }

  interface int 
  GetID(void) 
  {
    return curt->id;
  }

  interface int 
  SetMyTCB(void *tcb) 
  {
    curt->kthread->kts->user_tcb = tcb;
    set_local_tcb(tcb);
    __asm__ __volatile__ ( "movl %0, %%gs" : : "r" (KSHMEM_GS));
    return 0;
  }

  interface int 
  RegisterTrap(int idx, void *trap_fn) 
  {
    return ipd_register_trap(curt->ipd, idx, (unsigned)trap_fn);
  }

  interface void 
  Reboot(void)
  {
    machine_restart();
  }

  /** Insert the credential 'process:<pid> speaksfor sha1.<<processbytes>> */
  interface int
  Sha1_AddCred(void) 
  {
	  return nxattest_sha1_addcred();
  }

  /** Receive the process hash */
  interface int
  Sha1_Get(int pid, char *sha1) 
  {
	  return nxattest_sha1_get(pid, sha1);
  }

  /** Generate a certificate
      ``kernel says process:X speaksfor sha1<<0xab..>>'' */
  interface int
  Sha1_GetCert(int pid, char *filepath) 
  {
	  return nxattest_sha1_getcert(pid, filepath);
  }

  /** Have the kernel generate a PEM-encoded signed label
      ``kernel says process:X says <stmt>'' 
    
      @param filepath must be at least 128B */
  interface int
  Sha1_Says(void *stmts, char *filepath)
  {
	  return nxattest_sha1_says(curt->ipd, (char **)stmts, filepath, 0);
  }

  /** Have the kernel generate a certificate with kernel signed statement
      ``process:X says <stmt>'' 
   
      @param filepath must be at least 128B */
  interface int
  Sha1_SaysCert(void *stmts, char *filepath)
  {
	  return nxattest_sha1_says(curt->ipd, (char **)stmts, filepath, 1);
  }

  /** Lowlevel CPU reservation interface: attach process->account */
  interface int
  Sched_SetProcessAccount(int pid, int account)
  {
	  return nxsched_process_setaccount(ipd_find(pid), account);
  }

  /** Lowlevel CPU reservation interface: lookup process->account */
  interface int
  Sched_GetProcessAccount(int pid)
  {
	  IPD *ipd;

	  ipd = ipd_find(pid);
	  if (!ipd)
		  return -1;

	  return ipd->account;
  }

  /** Lowlevel CPU reservation interface: attach cpuquantum->account */
  interface int
  Sched_SetQuantumAccount(int quantum, int account)
  {
	  return nxsched_quantum_setaccount(quantum, account);
  }

  interface int
  SetName(char * name)
  {
	  return nexusthread_setname(name);
  }

  /** Kernel lock interface for futexes 
      @return -1 on failure, 0 on timeout, 1 on wake */
  interface int
  CondVar_Wait(int *lock, unsigned int *wq, int usecs, 
               int *release_val, unsigned int *release_wq)
  {
	return nxcondvar_wait(lock, wq, usecs, release_val, release_wq);
  }

  /** kernel lock interface for futexes 
      @return 1 if someone was awoken, 0 otherwise */
  interface int
  CondVar_Signal(int *lock, unsigned int *wq)
  {
	  return nxcondvar_signal(lock, wq);
  }

  interface int
  CondVar_Broadcast(int *wq)
  {
	  return nxcondvar_broadcast(wq);
  }

  /** Release kernel counterpart to user semaphore */
  interface int
  CondVar_Free(int wq)
  {
	  return nxwaitqueue_free(wq);
  }

  interface int
  SetPrivileges_Start(void)
  {
	  return nxkguard_record_begin();
  }

  interface int
  SetPrivileges_Stop(void)
  {
	  return nxkguard_record_end();
  }

  interface int
  SetPrivilege(unsigned int operation, 
	       unsigned long long obj_upper,
	       unsigned long long obj_lower)
  {
	  struct nxguard_object obj;

	  obj.upper = obj_upper;
	  obj.lower = obj_lower;
	  return nxkguard_allow(curt->ipd->id, operation, obj);
  }
  
  /** Disable use of a system call or message
      This action irrevocably reduces process capabilities, 
      implementing a source for of trust */
  interface int
  DropPrivilege(unsigned int operation, 
		unsigned long long obj_upper,
		unsigned long long obj_lower)
  {
	  struct nxguard_object obj;

	  obj.upper = obj_upper;
	  obj.lower = obj_lower;
	  return nxkguard_drop(curt->ipd->id, operation, obj);
  }

}

