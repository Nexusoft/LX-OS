syscall Debug {

  decls __callee__ {
    includefiles { 
	"<nexus/defs.h>",
	"<nexus/ipd.h>",
	"<nexus/ipc.h>",
	"<nexus/mem.h>",
	"<nexus/machineprimitives.h>",
	"<nexus/thread-inline.h>",
	"<nexus/thread-private.h>",
	"<nexus/guard.h>",
	}
  }

  /** A minimal call for testing and benchmarking. 
      NO access control checks are performed */
  interface int
  Null(int foo) 
  {
    return foo;
  }

  /** Like Null(), but passes through access control
      Default access control policy in absence of goal is BLOCK 
      (while others are still ALLOW) */
  interface int
  Null2(int foo) 
  {
    return foo;
  }

  /** Like Null2(), but uses default access control policy */
  interface int
  Null3(int foo) 
  {
    return foo;
  }

  interface void
  Abort(unsigned long ebp)
  {
    printk_red("[abort] %d (%s) in %d (%s)\n", 
	       curt->ipd->id, curt->ipd->name ? curt->ipd->name : "",
	       curt->id, curt->name ? curt->name : ""); 
    dump_user_stack(curt, ebp);
    curt->ipd->exit_status = -99;
    ipd_kill(curt->ipd);
  }

  /** Record the latest Linux system call executed by the current thread
      (Linux calls are intercepted and forwarded to userspace libraries)
      @param enter is 1 on entry, 0 on exit from the call */
  interface void
  LinuxCall(int call, int enter)
  {
	  curt->linuxcall = enter ? call : 0;
  }

  /** Emulate an IRQ by sending the corresponding software interrupt */
  interface int
  SoftInt(int irq)
  {
	  // 'int' instruction only takes immediates: cannot use variable directly
	  switch (irq) {
		case 0x23 /* IRQ 3 */ :	asm("int $0x23"); break;
		default:		printk("[debug] irq out of range\n"); 
					return -1;
	  }

	  return 0;
  }

  interface int
  printk_msg(const char *msg, int num) 
  {
	int intlevel;
       
	intlevel = disable_intr();
	printk_red("[debug] pid=%d t=%d [%s] num=%d\n", 
		   curt->ipd->id, curt->id, msg, num);
	restore_intr(intlevel);
	return 0;
  }

  /** Generate a thread trace */
  interface void
  Trace(unsigned long ebp)
  {
  	dump_user_stack(curt, ebp);
  }

  /** Execute a kernel command, such as 'ps' 
      A leftover from the in-kernel shell 
   
      NB argv must be a char**. The IDL cannot handle those */
  interface int
  KCommand(int argc, void *argv)
  {
	return nxshell_execute(argc, (char **) argv);
  }
}

