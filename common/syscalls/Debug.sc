syscall Debug {
  decls {
    includefiles {	
	    "<nexus/fs.h>"			// XXX remove together with nxguard_..
	}
    enum IPCBreakdown {
      // CALL_SYSCALL,
      CALL_CHANNEL_LOOKUP = 1,

      CALL_SETUP = 2, // happens 2x
      CALL_DISPATCH = 3,

      // Context switch: nexuskthread_restorestate_asm

      // RECV_SYSCALL,
      RECV_CHANNEL_LOOKUP = 4,
      // RETURN_SYSCALL,
      RETURN_THREAD_LOOKUP = 5,
      RETURN_COPY = 6,

      // TRANSFER_SYSCALL

      TRANSFER_FROM = 7,
      TRANSFER_TO = 8,
      TRANSFER_INTERPOSE = 9,

      CALL_INTERPOSE = 10,
      GLOBAL_IPC = 11,

      // Other datapoints:
      // Client think time: client ipd count
      // Server think time: server ipd count
      // Client-side copies: copy mark &&  Call()
      // Server-side copies: copy mark && ( RecvCall() || Return() )
    };

    enum IPCBreakdown2 {
      // pass 0
      CONTEXT_SETUP = 1,
      CALL_RENDEZ = 2,

      // pass 1
      THREAD_FIND = 3,
      EDGESET_FIND = 4,
    };

  }

  decls __callee__ {
    includefiles { "<nexus/defs.h>",
	"<nexus/ipd.h>",
	"<nexus/mem.h>",
	"<nexus/machineprimitives.h>",
	"<nexus/log.h>",
	"<nexus/synch.h>",
	"<nexus/synch-inline.h>",
	"<nexus/thread.h>",
	"<nexus/clock.h>",
	"<nexus/guard.h>",
	"<nexus/thread-private.h>",
	"<nexus/malloc_checker.h>",
	"<nexus/tftp.h>",
	}
    int fpudebug = 0;
    NexusLog *regression_log;
  }

  interface void DumpPageUtilization(void){
    dump_page_utilization();
  }

  /* send a file with the kernel tftp (useful when debugging user filesystems) */
  interface int KernelTftp(char *ufilename, int namelen, unsigned char *udata, int datalen){
    char *filename = (char *)galloc(namelen+1);
    char *data = (char *)galloc(datalen);
    int dbg = 0;

    peek_user(nexusthread_current_map(), (unsigned int)ufilename, filename, namelen);
    filename[namelen] = 0;
    peek_user(nexusthread_current_map(), (unsigned int)udata, data, datalen);

    if(dbg)printk_red("TFTP: filename=%s, datalen=%d\n", filename, datalen);

    return send_file(filename, data, datalen);
  }

  /* turn on malloc recording for the kernel */
  interface int CheckDups(unsigned int vaddr) {
    check_multiple_mapping(nexusthread_current_map(), vaddr);
    return 0;
  }

  interface void KillCache(void) {
	unsigned int oldcr0 = readcr0();
	writecr0((oldcr0 & ~(1 << 29)) | (1 << 30));
  }

  /** Set guard goal using a NAL expression.

     @param goal is a NAL statement that must be proven. 
            NULL clears all policies.
     @param glen is the length of goal without \0

     @return 0 on success, -1 on failure. */
  interface int 
  guard_chgoal(FSID object, int operation, char *goal, int glen) {
	char *kgoal = NULL;
	
	// XXX we should copy object and glen user copy_from_user

	// sanity check input
	if (glen < 0 || glen > 200) {
		printk_current("Goal length out of bounds\n");
		return -1;
	}

	// copy goal
	if (glen) {
		kgoal = nxcompat_alloc(glen + 1);
		peek_user_fast((unsigned int) goal, kgoal, glen);
		kgoal[glen] = 0;
	}

	// call actual guard function
	nxguard_chgoal(object, operation, kgoal);

	if (kgoal)
		nxcompat_free(kgoal);

	return 0;
  }

  /** Change the interface */
  interface void 
  guard_chproof(char *deduction, int dlen)
  {
#if 0
	  char *kdeduction;
	  
	// sanity check input
	if (dlen < 0 || dlen > 400) {
		printk_current("Goal length out of bounds\n");
		return -1;
	}

	// copy goal
	if (dlen) {
		kdeduction = nxcompat_alloc(dlen + 1);
		peek_user_fast((unsigned int) deduction, kdeduction, dlen);
		kdeduction[dlen] = 0;
	}

	nxguard_chproof(nexusthread_current_ipd()->id, kdeduction, dlen);
	
	if (kdeduction)
		nxcompat_free(kdeduction);
#endif
  }

  interface int PagesUsed(void){
    return Map_pagesused(nexusthread_current_map());
  }

  interface void FPUDebug(void) {
    fpudebug = ((fpudebug + 1) % 2);
  }

  interface int
    Null(int foo) {
    /* audited 5/31/2006: good */
    return foo;
  }

  interface int
    TimeInterrupt(int foo) {
    /* audited 5/31/2006: good */
    int i;
    extern unsigned int nexustime;
    int orig_time = nexustime;
    const int total = 10000000;
    for(i=0; i < total; i++) {
      int intlevel = disable_intr();
      restore_intr(intlevel);
    }
    int elapsed = nexustime - orig_time;
    printk("interrupt time %d in %d\n", total, elapsed);
    return elapsed;
  }

  interface int
    PeekUser(char *source, int len) {
    char *buf = galloc(len);
    int rv = peek_user(nexusthread_current_map(), (unsigned int)source, buf, len);
    gfree(buf);
    return rv;
  }

  interface int
    PokeUser(char *source, int len) {
    char *buf = galloc(len);
    int rv = poke_user(nexusthread_current_map(), (unsigned int)source, buf, len);
    gfree(buf);
    return rv;
  }

  interface int
    TransferUser(char *dest, char *source, int len) {
    char *buf = galloc(len);
    int rv = peek_user(nexusthread_current_map(), (unsigned int)source, buf, len);
    if(rv == 0) {
      rv = poke_user(nexusthread_current_map(), (unsigned int)dest, buf, len);
    }
    gfree(buf);
    return rv;
  }

  decls __callee__ {
    Sema *p0, *p1;
  }
  interface int
    PServer(int x) {
#define TEST_COUNT (1/*00000*/)
    if(p0 == NULL) {
      p0 = sema_new();
      p1 = sema_new();
    }

    int i;
    for(i=0; i < x; i++) {
      P(p0);
      V(p1);
    }
    return i;
  }

  interface int
    PClient(int x) {
#if 0
    if(p0 == NULL) {
      p0 = sema_new();
      p1 = sema_new();
    }
#endif
    int i;
    for(i=0; i < x; i++) {
      V(p0);
      P(p1);
    }
    return i;
  }

  interface int
    RecvCallDelay(int x) {
	/// deprecated XXX:remove
	return -1;
  }

  // Check to see if the target thread exists
  interface int
    ThreadCheck(int id) {
    BasicThread *t = nexusthread_find(id);
    if(t != NULL) {
      nexusthread_put(t);
      return 1;
    }
    return 0;
  }

  interface int cancel_shell_wait(void) {
    // XXX This doesn't do proper locking, but that doesn't matter
    // because this is used only in emergency debugging
    extern BasicThread *shell_wait_thread;
    if(shell_wait_thread != NULL) {
      V(shell_wait_thread->waitsema);
      return 0;
    } else {
      printk_red("cancel_shell_wait: shell is not waiting on anything!\n");
      return -1;
    }
  }

  interface void printk_msg(const char *msg) {
	int intlevel = disable_intr();

#if 0
	char copy[80];

	// copy from kernel:mem.c (yech)
	int peek_strlen(Map *m, unsigned int virtaddr) {
	  int i;
	  char c;
	  for(i=0; ; i++) {
	    if(peek_user(m, virtaddr + i, &c, 1) != 0) {
	      return -SC_ACCESSERROR;
	    }
	    if(c == '\0') {
	      return i;
	    }
	    // safety
	    if (i == 80)
	      restore_intr(intlevel);
	      return -SC_ACCESSERROR;
	  }
	}

	// get length
	int len = peek_strlen(nexusthread_current_map(), (unsigned int) msg);
	if (len > 79) {
	      printk_red("[debug pid.%d] --message too long-- \n", 
			  nexusthread_current_ipd()->id);
	      restore_intr(intlevel);
	      return;
	}

	// copy data to kernel
	peek_user(nexusthread_current_map(), (unsigned int) msg, copy, len);
	copy[len] = 0;

	// print
	printk_red("[debug pid=%d t=%d] %s\n", 
		   nexusthread_current_ipd()->id, curt->id, copy);
#else
	printk_red("[debug pid=%d t=%d] %s\n", 
		   nexusthread_current_ipd()->id, curt->id, msg);
#endif
	restore_intr(intlevel);
  }

  interface void printk_red(int linenum){
    printk_red("user debug at line %d == 0x%x == '%c'\n", 
	       linenum, linenum, linenum >= 60 && linenum < 128 ? : ' ');
  }

}
