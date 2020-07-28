#include <stdarg.h>
#include <nexus/defs.h>

#include <nexus/log.h>
#include <asm/hw_irq.h> // for _stext
#include <nexus/util.h>
#include <nexus/queue.h>
#include <nexus/machineprimitives.h>
#include <nexus/ksymbols.h>
#include<nexus/thread.h>
#include<nexus/thread-inline.h>
#include <nexus/stringbuffer.h>

#include <nexus/tftp.h>

//#define LOGSIZE 8192
#define LOGSIZE 65536
//#define LOGSIZE 256

struct NexusLog{
  char *log;
  int  istart;
  int istop;
  int  displaylog;
  int size; 
};

char nlog[LOGSIZE];
NexusLog syslog = {nlog, 0, 1, 0};

NexusLog *klog_syslog(void){
  return &syslog;
}

NexusLog *klog_new(int size){
  assert(size > 0);
  NexusLog *newlog = (NexusLog *)galloc(sizeof(NexusLog));
  newlog->log = (char *)galloc(size);
  (newlog->log)[0] = '\n';
  newlog->istart = 0;
  newlog->istop = 1;
  newlog->displaylog = 0;
  newlog->size = size;
  return newlog;
}

void klog_destroy(NexusLog *log){
  gfree(log->log);
  gfree(log);
}

void klog_display(NexusLog *log, int val){
  log->displaylog = val;
}

int klog_size(NexusLog *log){
  if(log->istart > log->istop) /* wrapped around */
    return log->size - log->istart + log->istop;

  return log->istop - log->istart;
}

void klog_memcpy(NexusLog *log, char *dst){
  if(log->istart > log->istop){ /* wrapped around */
    int size = log->size - log->istart;
    memcpy(dst, log->log + log->istart, size);
    memcpy(dst + size, log->log, log->istop);
    return;
  }
  
  memcpy(dst, log->log + log->istart, klog_size(log));
}

void klog_dump(NexusLog *log) {
  int i;

  for(i=0; i < LOGSIZE; ++i) {
    int index = ((log->istart + i) < LOGSIZE) ? (log->istart+i) : ((log->istart+i) % LOGSIZE);
    if((log->log)[index] == '\0')
      return;
    printk_current("%c", (log->log)[index]);
    //printk("%c", (log->log)[index]);
  }
}

void klog_send(NexusLog *log, const char *filename) {
  StringBuffer *sb = StringBuffer_new(1024);
  int i;
  for(i=0; i < LOGSIZE; ++i) {
    int index = ((log->istart + i) < LOGSIZE) ? (log->istart+i) : ((log->istart+i) % LOGSIZE);
    if((log->log)[index] == '\0') {
      break;
    }
    //printk_current("%c", (log->log)[index]);
    char str[2];
    sprintf(str, "%c", (log->log)[index]);
    SB_cat(sb, str);
  }
  char *data = (char *)SB_c_str(sb);
  send_file((char *)filename, data, strlen(data));
  StringBuffer_destroy(sb);
}

char *klog_get(NexusLog *log){
  return (log->log);
}

void klog(NexusLog *log, char *fmt, ...) {
  va_list args;
  char linebuf[200];
  int i, n, movedpaststart = 0;

  va_start(args, fmt);
  n = vsprintf(linebuf,fmt,args);
  va_end(args);
  for(i = 0; i < n; ++i) {
    int index = ((log->istop + i) < LOGSIZE) ? (log->istop+i) : ((log->istop+i) % LOGSIZE);

    if(index == log->istart)
      movedpaststart = 1;
    (log->log)[index] = linebuf[i];
  }
  log->istop = ((log->istop + n) < LOGSIZE) ? (log->istop+n) : ((log->istop+n) % LOGSIZE);
  (log->log)[log->istop] = '\0';
  if(log->istop == log->istart)
    movedpaststart = 1;
  if(movedpaststart) {
    log->istart = ((log->istop + 1) < LOGSIZE) ? (log->istop+1) : ((log->istop+1) % LOGSIZE);
  }
  if(log->displaylog)
    printk("%s", linebuf);
}

void nexuslog_init(void) {
  syslog.log[0] = 'L';
  syslog.log[1] = 'O';
  syslog.log[2] = 'G';
  syslog.log[3] = '\n';
  syslog.log[4] = '\0';
  syslog.istop = 4;
}

void klog_clear(NexusLog *log) {
  log->istart = 0;
  log->istop = 1;
}

/* Code for dumping the stack on errors */

static inline int kernel_text_address(unsigned long addr)
{
	return (addr >= (unsigned long) &_stext &&
		addr <= (unsigned long) &_etext);
}

// ubreak is just a convenient place to put a gdb breakpoint
int gdb_mode;
volatile int go;

void enable_gdb_mode(char *opt)
{
	gdb_mode = 1;
	printk_red(
		"GDB mode enabled: Connect with gdb, set breakpoints if you like, set go = 1, then continue. E.g.\n"
		"    gdb nexus/kernel/vmnexus\n"
		"    gdb> break ubreak\n"
		"    gdb> set go = 1\n"
		"    gdb> continue\n"
		"Note: the script 'tools/qemu/debug' will do this all for you\n");
	while (!go);
	go = 0;
}


void ubreak(void) {
	if (gdb_mode)
		printk("<ubreak>\n");
}

static int trace_pause0(int in_show_trace) {
	int done, intlevel, do_quit;
	char keypress;

	intlevel = disable_intr();

	printk("[ints were %s] ", (intlevel ? "enabled" : "disabled"));
	if (in_show_trace)
		printk("Hit <SPACE> to continue, 'q' for quit, or <ESC> to reboot...");
	else
		printk("Hit <SPACE> to continue, 't' for stack trace, 'q' for quit, or <ESC> to reboot...");

	done = 0;
	do_quit = 0;
	while (!done) {
	
		keypress = nexusthread_panicmode();

		switch (keypress) {
			case 0x39: // <SPACE>
				done = 1;
				break;
			case 0x01: // <ESC>
				machine_restart();
				break;
			case 0x10: // 'q'
				done = 1;
				do_quit = 1;
				break;
			case 0x14: // 't'
				if (!in_show_trace)
					dump_stack();
				break;
			break;
		}
	}
	printk("\n");
	restore_intr(intlevel);
	return do_quit;
}
int trace_pause(void) { return trace_pause0(0); }

/* extern void *last_preempt[];
extern int last_pnum;
extern int switchnest; */

// #undef CONFIG_FRAME_POINTER
static inline int peek_kernel_int(Map *map, void *addr, int *error) {
	if((unsigned int)addr < KERNELVADDR ||
	   fast_virtToPhys(map, ((unsigned int) addr) & PAGE_MASK, 0, 0) == 0) {
		*error = 1;
		return 0;
	}
	*error = 0;
	return *(int*)addr;
}

static unsigned long next_address(BasicThread *thread, unsigned long **stack, unsigned long *context, int *done) {
#ifndef CONFIG_FRAME_POINTER
#error "config frame pointer should always be defined!"
	*done = 0;
	return (unsigned long)*(*stack)++;
#else
	int err;
	if(*context == -1) {
		if(thread == nexusthread_self()) {
			__asm__ ("movl %%ebp, %0" : "=g" (*context));
		} else {
			*context = thread_getKTS(thread)->ebp;
		}
	} else {
		*context =
			peek_kernel_int(nexusthread_get_map(thread),
				 (unsigned long *)*context, &err);
		if(err != 0) {
			printk_red("next address (0) not mapped!\n");
			*done = 1;
			return 0;
		}
	}
	if(*context == 0) {
		*done = 1;
		return 0;
	}

	unsigned long val =
		peek_kernel_int(nexusthread_get_map(thread),
			 ((unsigned long *) *context) + 1, &err);
	if(err != 0) {
		// printk_red("next address (1) not mapped!\n");
		*done = 1;
		return 0;
	}
	return val;
#endif
}

#define GEN_STACK_TRACE(PFUNC, KSYMFUNC, FNAME, VADDR, DO_PAUSE) \
  unsigned long context = -1;					\
  int done = 0, stopped = 0;					\
  PFUNC("Call Trace (at 0x%p):\n", stack);			\
  if (use_ksym) {						\
    int ready = (FNAME == NULL);				\
    int skipped = 0;						\
    i = 0;							\
    unsigned long *top = stack + 4 * PAGESIZE;			\
    unsigned long *realstack = stack;				\
    do {							\
      stack = realstack;					\
      context = -1;						\
      done = 0;							\
      while(stack < top){					\
	addr = next_address(thread, &stack, &context, &done);	\
	if(done) break;						\
	if (!kernel_text_address(addr)) continue;		\
	if (!ready) {						\
	  KSymbol *ks = ksym_find_by_addr((void *)addr);	\
	  if (ks && !strcmp(ks->name, FNAME)) {			\
	    PFUNC("(stack: 0x%x ... 0x%x) Skipped %d frames\n", \
		realstack, stack, skipped);			\
	    ready = 1;						\
	    i++;						\
	    PFUNC("(stack: 0x%x) ", stack);			\
	    KSYMFUNC((void *)addr);				\
	    i++;						\
	    if (VADDR) {					\
	      PFUNC("(current eip value) ");			\
	      KSYMFUNC((void *)VADDR);				\
	      i++;						\
	    }\
	  } else {						\
	    skipped++;						\
	  }							\
	  continue;						\
	}							\
	if (DO_PAUSE && (++i % 16) == 0) {			\
	  stopped = trace_pause0(1);				\
	  if (stopped) break;					\
	}							\
	PFUNC("(stack: 0x%x) ", stack);				\
	KSYMFUNC((void *)addr);					\
      }								\
      if (!ready && skipped) {					\
	ready = 1;						\
	continue; /* try again without skipping any */		\
      }								\
      if (stopped) {						\
	PFUNC("(stack: 0x%x) => break from while\n", stack);	\
      } else {							\
	PFUNC("(stack: 0x%x) => done with while\n", stack);	\
	if(DO_PAUSE) trace_pause0(1);				\
      }								\
      break;							\
    } while (1);						\
  } else {							\
      i = 1;							\
      unsigned long *orig_stack = stack;			\
      int print_limit = 0;					\
      while (((long) stack & (PAGESIZE * 2 - 1)) != 0) {	\
	addr = next_address(thread, &stack, &context, &done);	\
	if(done) break;						\
	if (!kernel_text_address(addr)) continue;		\
	if ((i++ % 6) == 0) printk_current("\n");		\
	PFUNC("  [<0x%08lx>%4d]", addr,				\
	      stack - orig_stack);				\
	if(print_limit++ > 30) {				\
	  PFUNC("limit exceeded "); break;			\
	}							\
      }								\
      PFUNC("\n");						\
    }

void show_thread_trace(BasicThread *thread, unsigned long * stack, char *func_name, unsigned long vaddr)
{
	int i;
	unsigned long addr;
	int use_ksym;
#if PRETTY_STACK_TRACES > 0
	ksym_table(&use_ksym); // see if we have any symbols
#else
	use_ksym = 0;
#endif
	//printk("switch count = %d\n", switchnest);
	/* printk("last preempt: 0x%p ", last_preempt[(last_pnum+0)%20]);
	for (i = 1; i < 20; i++)
		printk("0x%p ", last_preempt[(last_pnum+i)%20]);
	trace_pause0(1); */

	if (!stack)
		stack = (unsigned long*)&stack;
	GEN_STACK_TRACE(printk_current, ksym_print_by_addr, func_name, vaddr, 1);
}

// try to devine where the thread is
char *guess_thread_place(BasicThread *thread, unsigned long * stack)
{
#if PRETTY_STACK_TRACES > 0
    int use_ksym;
    ksym_table(&use_ksym); // see if we have any symbols
    if (!use_ksym) return NULL;
#else
    return NULL;
#endif

    if(stack==NULL) {
	    if(thread == nexusthread_self()) {
		    stack=(unsigned long*)&stack;
	    } else {
		    stack = (unsigned long *)thread_getKTS(thread)->esp;
	    }
    }

    int intlevel = disable_intr();
    unsigned long vaddr[10];
    KSymbol *syms[10];
    int i, n = 0;
    unsigned long *top = stack + 4 * PAGESIZE;
    unsigned long context = -1;
    while (stack < top && n < 10) {
      int done = 0;
      unsigned long addr = next_address(thread, &stack, &context, &done);
      if (done) break;
      if (!kernel_text_address(addr)) continue;
      vaddr[n] = addr;
      syms[n++] = ksym_find_by_addr((void *)addr);
    }
    if (n == 0) {
      restore_intr(intlevel);
      return NULL;
    }
    if (n >= 2 && syms[0] && !strcmp(syms[0]->name, "nexusthread_stop")) {
      for (i = 1; i < n; i++) {
	KSymbol *s = syms[i];
	if (!s) continue;
	if (!strcmp(&s->name[strlen(s->name)-strlen("_Handler")], "_Handler")) {
	  char *buf = galloc(100);
	  sprintf(buf, "blocked via %s", s->name);
	  restore_intr(intlevel);
	  return buf;
	}
      }
    }
    restore_intr(intlevel);
    return NULL;
}

void show_trace(unsigned long * stack) {
	show_thread_trace(nexusthread_self(), stack, NULL, 0);
}


int dupaddr(unsigned long *tmpaddrs, int numaddrs, unsigned long addr){
  int i = 0;
  int found = -1;
  int zero = 0;

  for(i = 0; i < numaddrs; i++){
    if(tmpaddrs[i] == addr)
      found = i;
    if(tmpaddrs[i] == 0)
      zero = i;
  }

  if(found == -1){
    tmpaddrs[zero] = addr;
    return 0;
  }

  return 1;
}
/* put the trace into an array */
int show_trace_array(unsigned long *addrs, int numaddrs){
  unsigned long *stack = (unsigned long *)&stack;
  int i = 0;
  unsigned long *tmpaddrs = (unsigned long *)galloc(numaddrs * sizeof(unsigned long));
  unsigned long context = -1;
  int done = 0;
  BasicThread *thread = nexusthread_self();

  while (i < numaddrs) {
    unsigned long addr = next_address(thread, &stack, &context, &done);
    if(done) break;
    addrs[i++] = addr;
  }

  gfree(tmpaddrs);
  return i;
}


#define STACKPRINTDEPTH 24
// #define STACKPRINTDEPTH 48
void show_thread_stack(BasicThread *thread, unsigned long * esp, char *func_name, unsigned long vaddr)
{
	unsigned long *stack;
	int i;

	if (!thread) {
		// XXX update trace code to not require a BasicThread*
		printk("too early for stack trace ..\n");
		return;
	}

	// debugging aid: "show_stack(NULL);" prints the trace for this cpu.
	if (!esp) {
		if (thread == nexusthread_self())
			esp = (unsigned long*)&esp;
		else
			esp = (unsigned long *)thread_getKTS(thread)->esp;
	}

	printk_current("Stack @ %p: ", esp);
	stack = esp;
	for(i=0; i < STACKPRINTDEPTH; i++) {
	  if (((long) stack & (PAGESIZE * 2 - 1)) == 0)
	    break;
	  if (i && ((i % 8) == 0))
	    printk_current("\n       ");
	  printk_current("%08lx ", *stack++);
	}
	printk_current("\n");
	show_thread_trace(thread, esp, func_name, vaddr);
}

void show_stack(unsigned long * esp)
{
	show_thread_stack(nexusthread_self(), esp, NULL, 0);
}

/* same except logs the trace and stack */
void log_trace(unsigned long * stack)
{
	int i;
	unsigned long addr;

	if (!stack)
		stack = (unsigned long*)&stack;
#if 0
	nexuslog("Call Trace:   ");
	i = 1;
	while (((long) stack & (PAGESIZE * 2 - 1)) != 0) {
	  //while (((long) stack) != 0) {
	  addr = *stack++;
		if (kernel_text_address(addr)) {
		  if (i && ((i % 6) == 0))
			  nexuslog("\n ");
			nexuslog(" [<%08lx>]", addr);
			i++;
		}
	}
	nexuslog("\n");
#else
	int use_ksym;
#if PRETTY_STACK_TRACES > 0
	ksym_table(&use_ksym); // see if we have any symbols
#else
	use_ksym = 0;
#endif
	BasicThread *thread = nexusthread_self();
	GEN_STACK_TRACE(nexuslog, ksym_log_by_addr, NULL, 0, 0);
#endif
}
void log_stack(void)
{
  unsigned long * esp;
  unsigned long *stack;
	int i;

	// debugging aid: "show_stack(NULL);" prints the
	// back trace for this cpu.

	esp=(unsigned long*)&esp;

	stack = esp;
	for(i=0; i < STACKPRINTDEPTH; i++) {
	  if (((long) stack & (PAGESIZE * 2 - 1)) == 0)
	    break;
	  //if (((long) stack) == 0)
	  //break;
	  if (i && ((i % 8) == 0))
	    nexuslog("\n       ");
	  nexuslog("%08lx ", *stack++);
	}
	nexuslog("\n");
	log_trace(esp);
}
/*
 * The architecture-independent backtrace generator
 */

void dump_stack(void)
{
	show_stack(0);
}

void dump_stack_at(void *esp) {
	show_stack(esp);
}

void dump_stack_below(void *esp, char *func_name, unsigned long vaddr) {
	show_thread_stack(nexusthread_self(), esp, func_name, vaddr);
}
