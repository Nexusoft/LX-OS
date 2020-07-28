#include <nexus/defs.h>
#include <nexus/mem-private.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>
#include <nexus/synch-inline.h>
#include <nexus/x86_emulate.h>
#include <nexus/tftp.h>

#define MAX_LR_SIZE (32762)  /* log size */
//#define MAX_LR_SIZE (65524)  /* log size */
#define MAX_LOG_COUNT (MAX_LR_SIZE / 60)  /* how many entries between dumps */

typedef enum LogType{
  LOG_TYPE_REGION = 1,
  LOG_TYPE_IOPORT,
}LogType;

typedef struct LogGeneral LogGeneral;
struct LogGeneral{
  LogGeneral *next;
  LogGeneral *prev;
  int lognum; /* number of times this log has been dumped to disk */
  int logcount; /* numer of log entries so far in this dump cycle */
  char *logname;
  Sema *dumpsema;
  NexusLog *log;
  LogType type;
  unsigned int vaddr;
  int size;
};

typedef struct LogRegion LogRegion;
struct LogRegion{
  LogRegion *next;
  LogRegion *prev;
  int lognum; /* number of times this log has been dumped to disk */
  int logcount; /* numer of log entries so far in this dump cycle */
  char *logname;
  Sema *dumpsema;
  NexusLog *log;
  LogType type;
  unsigned int vaddr;
  int size;

  unsigned int rwaddr;
  unsigned int paddr;
};

typedef struct LogIO LogIO;
struct LogIO{
  LogIO *next;
  LogIO *prev;
  int lognum; /* number of times this log has been dumped to disk */
  int logcount; /* numer of log entries so far in this dump cycle */
  char *logname;
  Sema *dumpsema;
  NexusLog *log;
  LogType type;
  unsigned int vaddr;
  int size;
};


LogGeneral *lrlist = NULL;
LogGeneral *lilist = NULL;

int lrlock = 0;
int lilock = 0;

#define LR_WRITE 1
#define LR_READ  0

#define LOGGING_ENABLED 1
#define PRINTING_ENABLED 0
#define NO_TRAP_ON_READS 0

static int dbg = 0;

#define DBG_PRINT(x...) do{				\
    if(dbg){						\
      printk_red("%s:%d: ", __FILE__, __LINE__);	\
      printk_red(x);					\
    }							\
  }while(0)



#define PRINT_AND_LOG(l,x...) do{		\
    if(PRINTING_ENABLED)			\
      printk_red(x);				\
    if(LOGGING_ENABLED)				\
      klog(l,x);				\
  }while(0)


#define LOG_TYPE_STRING(t) ((t == LOG_TYPE_REGION)?"LOGREGION":"LOGIOPORT")
#define LOG_TYPE_LIST(t) ((t == LOG_TYPE_REGION)?&lrlist:&lilist)
#define LOG_TYPE_LOCK(t) ((t == LOG_TYPE_REGION)?lrlock:lilock)

int lr_dumpthread(void *arg){
  LogGeneral *todump = (LogGeneral *)arg;
  printk_red("dumpthread started for 0x%p\n", todump);
  while(1){
    P(todump->dumpsema);

    int lvl = disable_intr();

    int dumpsize = klog_size(todump->log);
    char *dumpcopy = (char *)galloc(dumpsize);
    klog_memcpy(todump->log, dumpcopy);
    klog_clear(todump->log);
    todump->logcount = 0;

    restore_intr(lvl);

    sprintf(todump->logname, "%s_0x%08x_0x%08x.%03d", LOG_TYPE_STRING(todump->type), todump->vaddr, todump->vaddr + todump->size, todump->lognum++);
    send_file(todump->logname, dumpcopy, dumpsize);
  };
}

static void lr_dumplist(LogType type){
  LogGeneral *cand; 
  for(cand = *LOG_TYPE_LIST(type); cand != NULL; cand = cand->next)
    printk_red("  vaddr=0x%x, size=%d\n", cand->vaddr, cand->size);
}

void lr_dumplists(void){
  printk_red("lrlist(0x%p==0x%p):\n", lrlist, LOG_TYPE_LIST(LOG_TYPE_REGION));
  lr_dumplist(LOG_TYPE_REGION);
  printk_red("lilist(0x%p==0x%p):\n", lilist, LOG_TYPE_LIST(LOG_TYPE_IOPORT));
  lr_dumplist(LOG_TYPE_IOPORT);
}

/* add to the front of the list */
static void lr_add(LogGeneral *lr){
  int lock = LOG_TYPE_LOCK(lr->type);
  while(atomic_test_and_set(&lock) != 0)
    nexusthread_yield(); /* should never happen; critical section is short */

  LogGeneral **list = LOG_TYPE_LIST(lr->type);

  DBG_PRINT("adding 0x%x to list starting with 0x%x\n", lr, list);
  
  lr->next = *list;
  if(*list)
    (*list)->prev = lr;
  *list = lr;

  atomic_clear(&lock);
}


static LogGeneral *lr_find(unsigned int vaddr, LogType type){
  LogGeneral *cand; 
  
  for(cand = *LOG_TYPE_LIST(type); cand != NULL; cand = cand->next)
    if((vaddr >= cand->vaddr) && (vaddr < cand->vaddr + cand->size))
      break;

  return cand;
}

static void lr_fill_general(LogGeneral *lr, unsigned int vaddr, int size, char *logname){
  lr->vaddr = vaddr;
  lr->size = size;

  lr->logname = galloc(strlen(logname + 1));
  lr->lognum = 0;
  lr->logcount = 0;
  lr->log = klog_new(MAX_LR_SIZE);

  lr->dumpsema = sema_new();
  nexusthread_fork(lr_dumpthread, lr);
}

static void lr_dump(LogGeneral *lr){
  V(lr->dumpsema);
}

static void lr_log(LogGeneral *lr, int rw, unsigned int vaddr, 
		   unsigned long val, int bytes){
  DBG_PRINT("lr=0x%p rw=%d vaddr=0x%x, val=0x%x, bytes=%d\n", lr, rw, vaddr, val, bytes);

  int lvl = disable_intr();
  PRINT_AND_LOG(lr->log, "%d 0x%x 0x%x 0x%x %d\n", rw, lr->vaddr, vaddr, 
		vaddr - lr->vaddr, vaddr - lr->vaddr);
  PRINT_AND_LOG(lr->log, "   ");

  switch(bytes){
  case 1:
    PRINT_AND_LOG(lr->log, "%d: 0x%02X\n", bytes, val);
    break;
  case 2:
    PRINT_AND_LOG(lr->log, "%d: 0x%04X\n", bytes, val);
    break;
  case 4:
    PRINT_AND_LOG(lr->log, "%d: 0x%08X\n", bytes, val);
    break;
  }
  lr->logcount++;
  restore_intr(lvl);

  if(lr->logcount >= MAX_LOG_COUNT){
    lr_dump(lr);
  }
}


static int protect_rw_one(Map *m, unsigned int vaddr){
  DirectoryEntry *dirent;
  PageTableEntry *pte;
  int diroffset  = (vaddr>>22) & 0x3ff;
  int pageoffset = (vaddr>>12) & 0x3ff;

  // printk("1:vaddr %x diroffset %x pageoffset %x\n", vaddr, diroffset, pageoffset);
  if(m->pdbr == NULL) {
    return -1;
  }

  dirent = (DirectoryEntry *) (VADDR(m->pdbr) + diroffset * sizeof(DirectoryEntry));

  if(!dirent->present) {
    return -1;
  } else {
    pte = (PageTableEntry *)(PHYS_TO_VIRT(dirent->physaddr << 12) + pageoffset * sizeof(PageTableEntry));
  }

  if(NO_TRAP_ON_READS)
    pte->rw = 0;  /* just write protect */
  else
    PageTableEntry_makeUnpresentButProtected(pte); /* read/write protect */


  return 0;
}


static void protect_rw(Map *m, unsigned int vaddr, int size){
  /* mark as not present in memmap, but leave allocated */
  int npages = (size + PAGESIZE - 1)/PAGESIZE;
  unsigned int startvaddr = vaddr & PAGE_MASK;
  int i;
  for(i = 0; i < npages; i++){
    int ret = protect_rw_one(kernelMap, startvaddr + i * PAGESIZE);
    printk("unmapped 0x%x %d\n", startvaddr + i * PAGESIZE, ret);
  }
}

void kernel_log_general_dump_logs(LogType type){
  LogGeneral *cand;
  for(cand = *LOG_TYPE_LIST(type); cand != NULL; cand = cand->next)
    lr_dump(cand);
}

void kernel_log_region_dump_logs(void){
  kernel_log_general_dump_logs(LOG_TYPE_REGION);
}
void kernel_log_io_dump_logs(void){
  kernel_log_general_dump_logs(LOG_TYPE_IOPORT);
}


#if 0
int kernel_log_region_dump_logs_shell(int ac, char **av){
  kernel_log_region_dump_logs();
  kernel_log_io_dump_logs();
  return 0;
}
DECLARE_SHELL_COMMAND(lr_dumplogs, kernel_log_region_dump_logs_shell, "-- dump kernel log regions to disk");
#endif

void kernel_log_io_add(unsigned int vaddr, int size){
  char *logname = "LOGIOPORT_0xdeadbeef_0xdeadbeef.123";
  LogIO *lr = (LogIO *)galloc(sizeof(LogIO));
  lr_fill_general((LogGeneral *)lr, vaddr, size, logname);
  lr->type = LOG_TYPE_IOPORT;

  lr_add((LogGeneral *)lr);
}

void kernel_log_region_add(unsigned int vaddr, int size){
  DBG_PRINT("adding lr 0x%x %d\n", vaddr, size);

  char *logname = "LOGREGION_0xdeadbeef_0xdeadbeef.123";

  int off = vaddr % PAGESIZE;
  unsigned int phys_addr = fast_virtToPhys_nocheck(kernelMap, vaddr - off) + off;
  printk("phys_addr = 0x%x, vaddr = 0x%x\n", phys_addr, vaddr);

  /* map a read/write copy */
  unsigned int rwaddr = remap_physical_pages(kernelMap, phys_addr, size, 1, 0);
  printk("rwaddr = 0x%x\n", rwaddr);

  LogRegion *lr = (LogRegion *)galloc(sizeof(LogRegion));
  lr_fill_general((LogGeneral *)lr, vaddr, size, logname);
  lr->type = LOG_TYPE_REGION;
  lr->rwaddr = rwaddr;
  lr->paddr = phys_addr;
    
  /* read-protect vaddr */
  protect_rw(kernelMap, vaddr, size);

  flushglobalTLB();

  lr_add((LogGeneral *)lr);
}

/* interface with the xen dissasembler */
int kernel_log_region_write(enum x86_segment seg,
			    unsigned long vaddr,
			    unsigned long val,
			    unsigned int bytes,
			    struct x86_emulate_ctxt *ctxt){

  LogRegion *lr = (LogRegion *)lr_find(vaddr, LOG_TYPE_REGION);

  DBG_PRINT("lr write 0x%lx to 0x%lx size %d lr=0x%p\n", val, vaddr, bytes, lr);

  if(!lr)
    return X86EMUL_UNHANDLEABLE;

  lr_log((LogGeneral *)lr, LR_WRITE, vaddr, val, bytes);

  /* do the write */
  int off = vaddr - lr->vaddr;
  unsigned char *target = (unsigned char *)lr->rwaddr + off;

  switch(bytes){
  case 1:
    __asm__ __volatile__("movb %b1, %b0": "=m" (*(char *)target): "q" (val));
    break;
  case 2:
    __asm__ __volatile__("movw %w1, %w0": "=m" (*(short *)target): "r" (val));
    break;
  case 4:
    __asm__ __volatile__("movl %1, %0": "=m" (*(int *)target): "r" (val));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  return X86EMUL_CONTINUE;
}


/* interface with the xen dissasembler */
int kernel_log_region_read(enum x86_segment seg,
			   unsigned long vaddr,
			   unsigned long *val,
			   unsigned int bytes,
			   struct x86_emulate_ctxt *ctxt){


  LogRegion *lr = (LogRegion *)lr_find(vaddr, LOG_TYPE_REGION);

  DBG_PRINT("lr read of 0x%lx size %d lr=0x%p\n", vaddr, bytes, lr);

  if(!lr)
    return X86EMUL_UNHANDLEABLE;

  /* do the read */
  int off = vaddr - lr->vaddr;
  unsigned char *target = (unsigned char *)lr->rwaddr + off;

  int targetoff = (unsigned int)target % PAGESIZE;
  unsigned int phys_addr = fast_virtToPhys_nocheck(kernelMap, (unsigned int)target);

  if(phys_addr + targetoff != lr->paddr + off)
     printk_red("0x%x == 0x%x\n", phys_addr + targetoff, lr->paddr + off);
  assert(phys_addr + targetoff == lr->paddr + off);

  switch(bytes){
  case 1:
    __asm__ __volatile__("movzbl %b1, %0": "=q" (*val): "m" (*(char *)target));
    break;
  case 2:
    __asm__ __volatile__("movzwl %w1, %0": "=r" (*val): "m" (*(short *)target));
    //*val = readw(target);
    break;
  case 4:
    __asm__ __volatile__("movl %1, %0": "=r" (*val): "m" (*(int *)target));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  lr_log((LogGeneral *)lr, LR_READ, vaddr, *val, bytes);

  return X86EMUL_CONTINUE;
}

void kernel_log_io_read(unsigned short port,
			unsigned char *val,
			unsigned int bytes){
  LogIO *lr = (LogIO *)lr_find((unsigned int) port, LOG_TYPE_IOPORT);

  if(!lr){
    printk_red("lr io read not logged port=0x%04x size=%d\n", port, bytes);
    return;
  }

  unsigned long realval = 0;

  switch(bytes){
  case 1:
    realval = *(unsigned char *)val;
    break;
  case 2:
    realval = *(unsigned short *)val;
    break;
  case 4:
    realval = *(unsigned long *)val;
    break;
  };

  lr_log((LogGeneral *)lr, LR_READ, (unsigned int)port, realval, bytes);
}

void kernel_log_io_write(unsigned short port,
			 unsigned char *val,
			 unsigned int bytes){
  LogIO *lr = (LogIO *)lr_find((unsigned int) port, LOG_TYPE_IOPORT);

  if(!lr){
    printk_red("lr io write not logged port=0x%04x size=%d\n", port, bytes);
    return;
  }

  unsigned long realval = 0xdeadbeef;

  switch(bytes){
  case 1:
    realval = *(unsigned char *)val;
    break;
  case 2:
    realval = *(unsigned short *)val;
    break;
  case 4:
    realval = *(unsigned long *)val;
    break;
  };

  lr_log((LogGeneral *)lr, LR_WRITE, (unsigned int)port, realval, bytes);
}



#if 0
//XXX this doesn't work but is a good idea...
int kernel_log_region_test(int argc, char **argv){
  unsigned short *testpage = (unsigned short *)galloc(PAGESIZE + PAGESIZE);

  printk("adding test region at 0x%p\n", testpage);
  kernel_log_region_add((unsigned int)testpage, PAGESIZE + PAGESIZE);

  int i;
  for(i = 0; i < PAGESIZE; i++)
    *(testpage + i) = i + 1;

  for(i = 0; i < PAGESIZE; i++){
    unsigned short val = *(testpage + i);
    if(val != i + 1){
      printk_red("read 0x%04x, should be 0x%04x\n", val, i+1);
      return -1;
    }
  }

  return 0;
}

DECLARE_SHELL_COMMAND(lr_test, kernel_log_region_test, "-- test kernel log regions");
#endif
