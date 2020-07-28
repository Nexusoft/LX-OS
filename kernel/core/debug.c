#include <nexus/defs.h>
#include <nexus/machineprimitives.h>
#include <nexus/ipd.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

int breakpoint_do_print = 1;

#define LOG_LEN (1024)
typedef struct BreakpointInfo {
  int enable;
  int index;

  int type;
  int size;
  unsigned long address;
} BreakpointInfo;

typedef struct BreakpointLog {
  BreakpointInfo data[LOG_LEN];
  int pos;
} BreakpointLog;

static BreakpointInfo shadow[NUM_HW_BREAKPOINTS];
static BreakpointLog enable_disable_log;
int disable_log_pos;

static void log_append(BreakpointLog *log, int enable, int index, int type, int size, unsigned long address) {
  log->data[log->pos] = 
    ((BreakpointInfo) {.enable = enable, .index = index,
	 .type = type, .size = size, .address = address});
  log->pos = (log->pos + 1) % LOG_LEN;
}

static void BreakpointInfo_dump(BreakpointInfo *info) {
  printk_current("{[%d] %s %d %d %p}", info->index, 
		 info->enable ? "enable" : "disable", 
		 info->type, info->size, info->address);
}

static void log_dump(BreakpointLog *log) {
  int i;
  for(i = 0; i < LOG_LEN; i++) {
    BreakpointInfo *info = &log->data[(log->pos + i) % LOG_LEN];
    BreakpointInfo_dump(info);
  }
}

static void log_dump_match(BreakpointLog *log, unsigned long address) {
  int i;
  for(i = 0; i < LOG_LEN; i++) {
    BreakpointInfo *info = &log->data[(log->pos + i) % LOG_LEN];
    if(address == info->address) {
      printk_green("M@[%d]", i); BreakpointInfo_dump(info);
    }
  }
}

static unsigned long breakpoint_read_address(int index) {
  unsigned long address = -1;
  if(0) {
    switch(index) {
#define GET_ADDR(X)							\
      case X:								\
	__asm__ __volatile__ ("movl %%dr"# X ", %0" : : "r" (address) ); \
      return address
      GET_ADDR(0);
      GET_ADDR(1);
      GET_ADDR(2);
      GET_ADDR(3);
#undef GET_ADDR
    default:
      assert(0);
    }
    return -1; // suppress warnings
  } else {
    return shadow[index].address;
  }
}

static void breakpoint_disable(int index, DR7 *dr7) {
  // printk_green("b_dis(%d)", index);
  assert(index >= 0 && index < NUM_HW_BREAKPOINTS);
  *(__u32 *)dr7 &= ~(0x3 << (index * 2));
  log_append(&enable_disable_log, 0, index, 0, 0, breakpoint_read_address(index));
}

static void breakpoint_set_and_enable(int index, DR7 *dr7, int type, int size, unsigned long address) {
  log_append(&enable_disable_log, 1, index, type, size, address);
  shadow[index].type = type;
  shadow[index].size = size;
  shadow[index].address = address;

  assert(index >= 0 && index < NUM_HW_BREAKPOINTS);
  int len = -1;
  switch(size) {
  case 1:
    len = DR_LEN_1;
    break;
  case 2:
    len = DR_LEN_2;
    break;
  case 4:
    len = DR_LEN_4;
    break;
  default:
    printk_red("unsupported breakpoint length!\n");
    assert(0);
  }
  assert(len > 0);
  *(__u32 *)dr7 |= (((len << 2) |type) << (index * 4 + 16));
  // enable bits
  *(__u32 *)dr7 |= (0x3 << (index * 2));
  switch(index) {
#define SET_ADDR(X)				\
    case X:								\
      __asm__ __volatile__ ("movl %0, %%dr" # X : : "r" (address) );	\
    break
    SET_ADDR(0);
    SET_ADDR(1);
    SET_ADDR(2);
    SET_ADDR(3);
#undef SET_ADDR
  default:
    assert(0);
  }
}

static int breakpoint_is_enabled(int index, DR7 *dr7) {
  assert(index >= 0 && index < NUM_HW_BREAKPOINTS);
  return (*(__u32 *)dr7) & (0x3 << (index * 2));
}

static void breakpoint_clearstatus(void) {
  DR6 dr6;
  memset(&dr6, 0, sizeof(dr6));
  dr6.reserved0 = 0xff;
  dr6.reserved1 = 0xffff;
  __asm__ __volatile__ ("movl %0, %%dr6" : : "r" (*(__u32*)&dr6) );
}

void debug_init(void) {
  DR7 dr7;
  memset(&dr7, 0, sizeof(dr7));

  dr7.le = 1;
  dr7.ge = 1;
  dr7.reserved0 = 0x1;
  dr7.gd = 0;
  dr7.reserved1 = 0x0;
  int i;
  for(i=0; i < NUM_HW_BREAKPOINTS; i++) {
    breakpoint_disable(i, &dr7);
  }
  __asm__ __volatile__ ( "movl %0, %%dr7 " : : "r" (*(__u32*)&dr7));

  breakpoint_clearstatus();
}

int /* breakpoint index */ breakpoint_add(int type, int size, unsigned long address) {
  switch(size) {
  case 1:
  case 2:
  case 4:
    break;
  default:
    printk_red("Unsupported breakpoint size %d!\n", size);
    return -1;
  }

  int rval = -1;
  int intlevel = disable_intr();
  int bnum;
  int found = 0;
  DR7 dr7;
  __asm__ __volatile__ ("movl %%dr7, %0" : "=r" (*(__u32*)&dr7));
  for(bnum = 0; bnum < NUM_HW_BREAKPOINTS; bnum++) {
    if(!breakpoint_is_enabled(bnum, &dr7)) {
      found = 1;
      break;
    }
  }
  if(!found) {
    printk_green("No slot for breakpoint found!\n");
    rval = -1;
    goto out;
  }
  breakpoint_set_and_enable(bnum, &dr7, type, size, address);
  __asm__ __volatile__ ("movl %0, %%dr7" : : "r" (*(__u32*)&dr7));
  rval = bnum;
  // printk_green("b_en(%d@%p)", rval, address);
  
 out:
  restore_intr(intlevel);
  return rval;
}

void /* breakpoint index */ breakpoint_del(int index) {
  DR7 dr7;
  __asm__ __volatile__ ("movl %%dr7, %0" : "=r" (*(__u32*)&dr7));
  breakpoint_disable(index, &dr7);
  __asm__ __volatile__ ("movl %0, %%dr7" : : "r" (*(__u32*)&dr7));
}

int trap_bounce_to_user(InterruptState *is, int idx, unsigned int vaddr);
void breakpoint_handle_DB(InterruptState *is) {
  if (breakpoint_do_print) {
      int intlevel = disable_intr();
      IPD *ipd = nexusthread_current_ipd();
      if (ipd && trap_bounce_to_user(is, 3 /* BRAKPOINT */, 0)) {
	  breakpoint_clearstatus();
	  is->eflags &=  0xfffffeff; // clear the trace bit -- in ipd's eflags
      } else {
	  printk_current("NEXUS: debug_intr: ipd = %d eip = %p\n", (ipd ? ipd->id : -1), is->eip);
	  dump_regs_is(is);
	  printk_red("eip[-2 .. +2] = ");
	  int i;
	  for(i = -2; i <= 2; i++) {
		printk_red("%02x ", ((unsigned char *)is->eip)[i]);
	  }
	  printk_red(" continuing with breakpoint in place...\n");
	  breakpoint_clearstatus();
      }
      restore_intr(intlevel);
  }
}

void breakpoint_dump_matches(unsigned long address) {
  printk_green("matches"); log_dump_match(&enable_disable_log, address); printk_green("\n");
}
void breakpoint_dump_debug_info(void) {
  return;
  printk_green("general log"); log_dump(&enable_disable_log); printk_green("\n");
}
