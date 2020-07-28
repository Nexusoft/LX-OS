#include <nexus/ddrm.h>

#include <nexus/ipd.h>
#include <nexus/thread-inline.h>
#include <nexus/synch-inline.h>
#include <nexus/devicelog.h>
#include <nexus/djwilldbg.h>
#include <nexus/hashtable.h>

int ddrm_debug_ioport_logging = 0;
#define FIRST_DMAABLE_NAME (20)

static inline int next_dmaable_name(void){
  static int dmaable_name = FIRST_DMAABLE_NAME;
  return dmaable_name++;
}



/* this macro only works for single instructions */
/* if ddrm->dying != 0, skip the op */
#define ddrm_test_and_do(s)						\
  "1:test %2, %2\n" /* intr before 1 is ok; test will do the right thing */ \
  "2:jnz 4f\n"								\
  "3:"s"\n"								\
  "4:\n"								\
  									\
  ".section __ddrm_ex_table,\"a\"\n"					\
  									\
  "	.int 2b\n"							\
  "	.int 4b\n"							\
  									\
  "	.int 3b\n"							\
  "	.int 4b\n"							\
  ".previous\n"								

static int x86_emulate_do_ddrm_write(DDRM *ddrm, unsigned long addr, 
				     unsigned long val, int bytes){
  switch(bytes){
  case 1:
    __asm__ __volatile__(ddrm_test_and_do("movb %b1, %b0")		
			 : "=m" (*(char *)addr)
			 : "q" (val), 
			   "r" (ddrm->dying));
    break;
  case 2:
    __asm__ __volatile__(ddrm_test_and_do("movw %w1, %w0")
			 : "=m" (*(short *)addr): "r" (val), "r" (ddrm->dying));
    break;
  case 4:
    __asm__ __volatile__(ddrm_test_and_do("movl %1, %0")
			 : "=m" (*(int *)addr): "r" (val), "r" (ddrm->dying));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  return X86EMUL_CONTINUE;
}
static int x86_emulate_do_ddrm_read(DDRM *ddrm, unsigned long addr, 
				    unsigned long *val, int bytes){
  switch(bytes){
  case 1:
    __asm__ __volatile__(ddrm_test_and_do("movzbl %b1, %0")
			 : "=q" (*val): "m" (*(char *)addr), "r" (ddrm->dying));
    break;
  case 2:
    __asm__ __volatile__(ddrm_test_and_do("movzwl %w1, %0")
			 : "=r" (*val): "m" (*(short *)addr), "r" (ddrm->dying));
    break;
  case 4:
    __asm__ __volatile__(ddrm_test_and_do("movl %1, %0")
			 : "=r" (*val): "m" (*(int *)addr), "r" (ddrm->dying));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  return X86EMUL_CONTINUE;
}

static int x86_emulate_do_ddrm_out(DDRM *ddrm, unsigned long addr, 
				   unsigned long val, int bytes){
  unsigned short port = (unsigned short)(addr & 0xffff);
  switch(bytes){
  case 1:
    __asm__ __volatile__ (ddrm_test_and_do("outb %b0,%w1") 
			  : : "a" (val), "Nd" (port), "r" (ddrm->dying));
    break;
  case 2:
    __asm__ __volatile__ (ddrm_test_and_do("outw %w0,%w1")
			  : : "a" (val), "Nd" (port), "r" (ddrm->dying));
    break;
  case 4:
    __asm__ __volatile__ (ddrm_test_and_do("outl %0,%w1")
			  : : "a" (val), "Nd" (port), "r" (ddrm->dying));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  if(ddrm_debug_ioport_logging)
    kernel_log_io_write(port, (unsigned char *)&val, bytes);

  return X86EMUL_CONTINUE;
}


static int x86_emulate_do_ddrm_in(DDRM *ddrm, unsigned long addr, 
				  unsigned long *val, int bytes){
  unsigned short port = (unsigned short)(addr & 0xffff);
  int dbg = 0;
  printk_djwill("port = 0x%x, *val=0x%lx, bytes=%d\n", port, *val, bytes);

  switch(bytes){
  case 1:
    __asm__ __volatile__ (ddrm_test_and_do("inb %w1,%b0")
			  : "=a" (*val) : "Nd" (port) , "r" (ddrm->dying));
    *val &= 0xff;
    break;
  case 2:
    __asm__ __volatile__ (ddrm_test_and_do("inw %w1,%w0")
			  : "=a" (*val) : "Nd" (port) , "r" (ddrm->dying));
    *val &= 0xffff;
    break;
  case 4:
    __asm__ __volatile__ (ddrm_test_and_do("inl %w1,%0") 
			  : "=a" (*val) : "Nd" (port) , "r" (ddrm->dying));
    break;
  default:
    return X86EMUL_UNHANDLEABLE;
  };

  if(ddrm_debug_ioport_logging)
    kernel_log_io_read(port, (unsigned char *)val, bytes);

  if(port == 0x18f0)
    printk_djwill("port = 0x%x, *val=0x%lx, bytes=%d\n", port, *val, bytes);

  return X86EMUL_CONTINUE;
}

/* the following four functions manage the remapping and reuse of
   memory mapped I/O regions.  They only get mapped into the kernel
   once; from then on they are reused.*/
static Sema ddrm_mmio_mutex = SEMA_MUTEX_INIT;
static struct HashTable *ddrm_mmio_table;
typedef struct MappedMMIO{
  unsigned int rwaddr;
  int len;
  int used;
}MappedMMIO;
#define NUM_MMIO_BUCKETS (32)

void ddrm_sys_region_init(void){
  ddrm_mmio_table = hash_new(NUM_MMIO_BUCKETS, sizeof(unsigned int));
}

static void ddrm_mmio_release_remapped(unsigned int paddr, int len){
  MappedMMIO *mmio;

  P(&ddrm_mmio_mutex);
  mmio = hash_findItem(ddrm_mmio_table, &paddr);
  V(&ddrm_mmio_mutex);

  assert(mmio != NULL);
  assert(mmio->used == 1);
  assert(mmio->len == len);
  
  mmio->used = 0;
}
static unsigned int ddrm_mmio_obtain_remapped(unsigned int paddr, int len){
  MappedMMIO *mmio;

  P(&ddrm_mmio_mutex);
  mmio = hash_findItem(ddrm_mmio_table, &paddr);
  V(&ddrm_mmio_mutex);

  if(mmio == NULL)
    return 0;

  assert(mmio->used == 0);
  assert(mmio->len == len);
  
  mmio->used = 1;

  return mmio->rwaddr;
}
static unsigned int ddrm_mmio_insert_remapped(unsigned int paddr, int len){
  /* map physical region into *all* addr spaces as r/w in supervisor mode */
  /* this is just so we can do the reset from any context.  */
  MappedMMIO *mmio = (MappedMMIO *)galloc(sizeof(MappedMMIO));
  mmio->rwaddr = remap_physical_pages(kernelMap, paddr, len, 1, 0);
  mmio->len = len;
  mmio->used = 1;

  P(&ddrm_mmio_mutex);
  hash_insert(ddrm_mmio_table, &paddr, mmio);
  V(&ddrm_mmio_mutex);

  return mmio->rwaddr;
}

static inline int is_vaddr_in_region(DDRMRegion *region, unsigned int vaddr){
  if(region == NULL)
    return 0;
  return ((vaddr >= region->rwaddr) && (vaddr < region->rwaddr + region->len));
}

static void ddrm_region_print(DDRMRegion *reg){
  int dbg = 0;
  printk_djwill("uaddr = 0x%x, rwaddr = 0x%x, paddr = 0x%x len = %d\n",
		reg->uaddr, reg->rwaddr, reg->paddr, reg->len);
}

/* Return the index where the item is stored (>= 0) or -1 on error. */
static int ddrm_add_region(DDRM *ddrm, DDRMRegion *region){	
  int dbg = 0;					
  int index;						
    							
  if(ddrm->numregions >= MAX_DDRM_REGIONS){				
    printk_red("DDRM only supports %d %ss (%d)\n", MAX_DDRM_REGIONS, region, ddrm->numregions); 
    return -1;							
  }									
    									
    printk_djwill("adding ddrm 0x%p number %d name %d\n", region, ddrm->numregions, region->name);	
    ddrm_region_print(region);						
									
  index = atomic_get_and_addto(&ddrm->numregions, 1);
  ddrm->regions[index] = region;
    									
  return index;							
}

/* warning: this erases the pointer (security reasons) but does not
   reclaim the space */
static void ddrm_remove_region(DDRM *ddrm, DDRMRegion *region){		
  ddrm->regions[region->index] = NULL;				
}				


/* find a region or ioport based on vaddr.  If we implement the
   optimization of disassembling instructions in the kernel and
   directly calling across to the ddrm, this will be callable from
   interrupt context. */
static DDRMRegion *ddrm_find_region(DDRM *ddrm, unsigned int vaddr){	
  DDRMRegion *found = NULL;						
									
  /* get the number of regions that it could possibly be in */
  int total = atomic_get(&ddrm->numregions);

  int i;				
  for(i = 0; i < total; i++) {
    if(is_vaddr_in_region(ddrm->regions[i], vaddr)){			
      found = ddrm->regions[i];						
      break;								
    }									
  }									
									
  return found;							
}

DDRMRegion *ddrm_find_region_by_name(DDRM *ddrm, int name){	
  assert(ddrm_initted);
  assert(check_intr() == 0); /* called from interrupt context */	
  int dbg = 0;							
									
  DDRMRegion *found = NULL;						
									
  /* get the number of regions that it could possibly be in */
  int total = atomic_get(&ddrm->numregions);
									
  int i;								
  for(i = 0; i < total; i++){				
    if(ddrm->regions[i] == NULL)
      continue;
    printk_djwill("region %i, checking if %d == %d\n", i, ddrm->regions[i]->name, name);		
    if(ddrm->regions[i]->name == name){			
      found = ddrm->regions[i];						
      break;								
    }									
  }									
									
  printk_djwill("found 0x%p as number %d\n", found, i);		
									
  return found;							
}

void ddrm_destroy_region(DDRM *ddrm, DDRMRegion *region){
  assert(ddrm_initted);
  assert(!nexusthread_in_interrupt(nexusthread_self()));

  Map *map = ddrm->ipd->map;

  switch(region->type){
  case DDRM_REGION_TYPE_DMAABLE:
    unmap_pages(map, region->rwaddr, NPAGES_FROM_BYTES(region->len));
    break;
  case DDRM_REGION_TYPE_MMIO:
    ddrm_mmio_release_remapped(region->paddr, region->len);
    break;
  case DDRM_REGION_TYPE_PORTIO:
    break;
  }

  gfree(region);
}

DDRMRegion *ddrm_create_region_dmaable(DDRM *ddrm, int len, int contract){
  assert(ddrm_initted);
  Map *map = nexusthread_current_map();
  DDRMRegion *newreg = (DDRMRegion *)galloc(sizeof(DDRMRegion));

  newreg->type = DDRM_REGION_TYPE_DMAABLE;

  // Get contiguous physical pages and map them into the user's
  // context as supervisor rw. Do NOT mix user and supervisor
  // (4MB PDE) regions, as all accesses to the PTE will trap.

  //newreg->rwaddr = USERSUPERVISORBEGIN;
  newreg->rwaddr = USERMMAPBEGIN;
  newreg->paddr = map_physical_pages(map, NPAGES_FROM_BYTES(len), 1, 0, 
				     &newreg->rwaddr);
  newreg->uaddr = newreg->rwaddr;
  newreg->len = len;
  newreg->name = next_dmaable_name();

  newreg->emulate_read = x86_emulate_do_ddrm_read;
  newreg->emulate_write = x86_emulate_do_ddrm_write;

  newreg->index = ddrm_add_region(ddrm, newreg);
  if(newreg->index < 0)
    goto err;

  int sr = ddrm->spec->register_dmaable(newreg->name, newreg->paddr, len, contract);
  if(sr != DDRMSPEC_ALLOW)
    goto err2;

  return newreg;

 err2:
  ddrm_remove_region(ddrm, newreg);
 err:
  gfree(newreg);
  return NULL;
}

/* a region is created inside a DDRM. */
DDRMRegion *ddrm_create_region_mmio(DDRM *ddrm, int name, 
				    unsigned int paddr, int len){
  assert(ddrm_initted);
  int dbg = 0;

  DDRMRegion *newreg = (DDRMRegion *)galloc(sizeof(DDRMRegion));
  assert(newreg != NULL);

  newreg->type = DDRM_REGION_TYPE_MMIO;

  newreg->paddr = paddr;
  newreg->len = len;
  newreg->name = name;

  printk_djwill("name = %d\n", name);

  assert(name < FIRST_DMAABLE_NAME);

  printk_djwill("paddr = 0x%x, len=%d\n", paddr, len);

  newreg->rwaddr = ddrm_mmio_obtain_remapped(paddr, len);
  if(newreg->rwaddr == 0)
    newreg->rwaddr = ddrm_mmio_insert_remapped(paddr, len);

  /* reads and writes from userspace will trap via a gpf */
  newreg->uaddr = newreg->rwaddr; 

  newreg->emulate_read = x86_emulate_do_ddrm_read;
  newreg->emulate_write = x86_emulate_do_ddrm_write;

  printk_djwill("creating mmio ddrm vaddr 0x%x paddr 0x%x len %d\n", newreg->rwaddr, newreg->paddr, newreg->len);

  newreg->index = ddrm_add_region(ddrm, newreg);
  if(newreg->index < 0)
    goto err;

  /* let the spec know we are granting some physical pages */
  int specresult = ddrm->spec->register_mmio(name, paddr, len);
  if(specresult != DDRMSPEC_ALLOW)
    goto err2;

  return newreg;

 err2:
  ddrm_remove_region(ddrm, newreg);
 err:
  gfree(newreg);

  return NULL;
}

/* a region is created inside a DDRM. */
DDRMRegion *ddrm_create_region_portio(DDRM *ddrm, int name, 
				      unsigned int paddr, int len){
  assert(ddrm_initted);
  int dbg = 0;

  DDRMRegion *newreg = (DDRMRegion *)galloc(sizeof(DDRMRegion));

  newreg->type = DDRM_REGION_TYPE_PORTIO;

  newreg->paddr = paddr;
  newreg->len = len;
  newreg->rwaddr = paddr;
  newreg->uaddr = paddr; 
  
  /* for debugging */
  if(ddrm_debug_ioport_logging)
    kernel_log_io_add(paddr, len);

  newreg->name = name;
  assert(name < FIRST_DMAABLE_NAME);

  newreg->emulate_read = x86_emulate_do_ddrm_in;
  newreg->emulate_write = x86_emulate_do_ddrm_out;

  printk_djwill("creating portio ddrm vaddr 0x%x paddr 0x%x len %d\n", newreg->rwaddr, newreg->paddr, newreg->len);

  newreg->index = ddrm_add_region(ddrm, newreg);
  if(newreg->index < 0)
    goto err;

  /* let the spec know we are granting some physical pages */
  int specresult = ddrm->spec->register_portio(name, paddr, len);
  if(specresult != DDRMSPEC_ALLOW)
    goto err2;

  return newreg;

 err2:
  ddrm_remove_region(ddrm, newreg);
 err:
  gfree(newreg);

  return NULL;
}

/** preamble shared between ddrm_read and ddrm_write */
static DDRMRegion *
__ddrm_preamble(unsigned long vaddr, DDRM **ddrmp)
{
  DDRMRegion *region;
  IPD *ipd;
  int offset;

  assert(check_intr() == 1); /* called from syscall context */
  ipd = nexusthread_current_ipd();

  *ddrmp = ipd_get_ddrm(ipd);
  if (!*ddrmp)
	  return NULL;

  region = ddrm_find_region(*ddrmp, vaddr);
  if (!region)
	return NULL;

  assert(region->rwaddr == region->uaddr);
  return region;
}


/* Note: If we implement the optimization of disassembling
   instructions in the kernel and directly calling across to the ddrm,
   read and write will be callable from interrupt context. */
int ddrm_read(enum x86_segment seg,
	      unsigned long vaddr,
	      unsigned long *val,
	      unsigned int bytes,
	      struct x86_emulate_ctxt *ctxt)
{
  DDRMRegion *region;
  DDRM* ddrm;
  int offset;
  int sr, ret;

  region = __ddrm_preamble(vaddr, &ddrm);
  if (!region)
	  return X86EMUL_UNHANDLEABLE;
  offset = vaddr - region->uaddr;

  // check conformance to device spec
  sr = ddrm->spec->request_read(region->name, region->paddr + offset, bytes);
  if (sr != DDRMSPEC_ALLOW)
    return X86EMUL_UNHANDLEABLE;
  
  ret = region->emulate_read(ddrm, region->rwaddr + offset, val, bytes);

  sr = ddrm->spec->report_read(region->name, region->paddr + offset, *val, bytes);
  if (sr != DDRMSPEC_ALLOW)
    return X86EMUL_UNHANDLEABLE;

  return ret;
}


int ddrm_write(enum x86_segment seg,
	       unsigned long vaddr,
	       unsigned long val,
	       unsigned int bytes,
	       struct x86_emulate_ctxt *ctxt){
  DDRMRegion *region;
  DDRM* ddrm;
  int offset;
  int sr, ret;

  region = __ddrm_preamble(vaddr, &ddrm);
  if (!region)
	  return X86EMUL_UNHANDLEABLE;
  offset = vaddr - region->uaddr;

  // check conformance to device spec
  sr = ddrm->spec->request_write(region->name, region->paddr + offset, val, bytes);
  if (sr != DDRMSPEC_ALLOW)
    return X86EMUL_UNHANDLEABLE;

  ret = region->emulate_write(ddrm, region->rwaddr + offset, val, bytes);

  return ret;
}

