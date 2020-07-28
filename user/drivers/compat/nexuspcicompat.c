#include <asm/bitops.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nexus/segments.h>
#include <nexus/device.h>
#include <nexus/interrupts.h>
#include <nexus/interrupt_thread.h>
#include <nexus/djwilldbg.h>
#include <nexus/ipc.h>
#include <nexus/pci.h>
#include <nexus/util.h>

#include <nexus/pci.interface.h>
#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/ddrm.interface.h>

#include <nexus/devicecompat.h>

struct resource ioport_resource = { "PCI IO", 0x0000, IO_SPACE_LIMIT, IORESOURCE_IO };
struct resource iomem_resource = { "PCI mem", 0x00000000, 0xffffffff, IORESOURCE_MEM };

#define NEXUSPCIDBG 1 /* a bunch of printks */
static int dbg = 0;

extern PCI_ProbeFunc pci_probe_func;

int default_pci_dev_oid = 0;
int default_irq = -1;
char *default_pci_dev_name;

static void pci_dev_reload(struct pci_dev *pdev, int pci_dev_oid);
int pci_read_config_byte(struct pci_dev *pdev, int where, u8 *val);
int pci_read_config_word(struct pci_dev *pdev, int where, u16 *val);
int pci_read_config_dword(struct pci_dev *pdev, int where, u32 *val);

int pci_write_config_byte(struct pci_dev *pdev, int where, u8 val);
int pci_write_config_word(struct pci_dev *pdev, int where, u16 val);
int pci_write_config_dword(struct pci_dev *pdev, int where, u32 val);


int
pcibios_present(void)
{
  return 1;
}


#include <nexus/interrupts.h>

void enable_irq(unsigned int irq) {
  nexus_sti();
}

void disable_irq_nosync(unsigned int irq) {
  nexus_cli();
}

struct pci_dev *driverdev = NULL;

static void resource_nexus_to_linux(struct resource *res, NexusResource *nres){
  assert(nres != NULL);
  assert(res != NULL);
  res->name = nres->name;
  res->start = nres->start;
  res->end = nres->end;
  res->flags = nres->flags;
  
  res->parent = NULL;
  res->sibling = NULL;
  res->child = NULL;
}

static struct pci_dev *pci_dev_create(UNexusPCIDev *dev, struct pci_driver *driver){
  struct pci_dev *pdev = (struct pci_dev *)malloc(sizeof(struct pci_dev));

  int i;

  /* These fields are faked in user space.  They should be removed if
     no drivers use them. */
  pdev->global_list = (struct list_head){NULL, NULL};
  pdev->bus_list = (struct list_head){NULL, NULL};
  pdev->bus = NULL;
  pdev->subordinate = NULL;

  pdev->sysdata = NULL;
  pdev->procent = NULL;

  /* These fields come from Nexus structure */
  pdev->devfn = dev->devfn;
  pdev->vendor = dev->vendor;
  pdev->device = dev->device;
  pdev->subsystem_device = dev->subsystem_device;
  pdev->class = dev->class;
  pdev->hdr_type = dev->hdr_type;
  pdev->rom_base_reg = dev->rom_base_reg;

  /* This field is passed in by the driver */
  pdev->driver = driver;

  /* These fields come from Nexus structure */
  pdev->dma_mask = dev->dma_mask;
  pdev->current_state = dev->current_state;;

  memset(pdev->vendor_compatible, 0, sizeof(short) * DEVICE_COUNT_COMPATIBLE);
  memset(pdev->device_compatible, 0, sizeof(short) * DEVICE_COUNT_COMPATIBLE);

  for(i = 0; i < min(DEVICE_COUNT_COMPATIBLE, NEXUS_DEVICE_COUNT_COMPATIBLE); i++){
    pdev->vendor_compatible[i] = dev->vendor_compatible[i];
    pdev->device_compatible[i] = dev->device_compatible[i];
  }

  pdev->irq = dev->irq;

  memset(&pdev->resource, 0, NEXUS_DEVICE_COUNT_RESOURCE * sizeof(NexusResource));
  memset(&pdev->dma_resource, 0, NEXUS_DEVICE_COUNT_DMA * sizeof(NexusResource));
  memset(&pdev->irq_resource, 0, NEXUS_DEVICE_COUNT_IRQ * sizeof(NexusResource));

  for(i = 0; i < min(DEVICE_COUNT_RESOURCE, NEXUS_DEVICE_COUNT_RESOURCE); i++)
    resource_nexus_to_linux(&pdev->resource[i], &dev->resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_DMA, NEXUS_DEVICE_COUNT_DMA); i++)
    resource_nexus_to_linux(&pdev->dma_resource[i], &dev->dma_resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_IRQ, NEXUS_DEVICE_COUNT_IRQ); i++)
    resource_nexus_to_linux(&pdev->irq_resource[i], &dev->irq_resource[i]);

  memset(pdev->name, 0, 90);
  memset(pdev->slot_name, 0, 8);

  memcpy(pdev->name, dev->name, min(90, NEXUS_PCI_DEV_NAME_LEN));
  memcpy(pdev->slot_name, dev->slot_name, min(8, NEXUS_PCI_SLOT_NAME_LEN));

  pdev->active = dev->active;
  pdev->ro = dev->ro;
  pdev->regs = dev->regs;

  pdev->transparent = dev->transparent;

  /* These fields are faked in user space.  They should be removed if
     no drivers use them. */
  pdev->prepare = NULL;
  pdev->activate = NULL;
  pdev->deactivate = NULL;

  /* These fields contain information used by the compat layer that
     weren't in the original Linux struct. */
  pdev->pci_dev_oid = dev->index;

  memset(pdev->map_info, 0, DEVICE_COUNT_RESOURCE * sizeof(struct pci_map_info));
  memcpy(pdev->map_info, dev->map_info, sizeof(struct pci_map_info) * 
	 min(DEVICE_COUNT_RESOURCE, NEXUS_DEVICE_COUNT_RESOURCE));

  return pdev;
}

/* returns 0 on failure, 1 on success */
int pci_register_driver(struct pci_driver *drv, int unused) { 
  int dbg = 1;
  UNexusPCIDev *npci_dev;
  struct pci_dev *pci_dev;

  DeviceType type = DEVICE_NONE;

  if (!strcmp("intel810_audio", drv->name))
    type = DEVICE_AUDIO;
  else if (!strcmp("e1000", drv->name))
    type = DEVICE_NETWORK;
  else {
    printf("[pci] Unknown device type\n");
    return 0;
  }
  assert(type > 0 && type < NUM_DEVICE_TYPES);

  npci_dev = calloc(1, sizeof(UNexusPCIDev));  

  int i;
  int num_ids = 0;
  /* this loop gets the number of id's in the table */
  for(i=0; drv->id_table[i].vendor || 
	drv->id_table[i].subvendor || 
	drv->id_table[i].class_mask; i++) {
    num_ids++;
  }

  int pci_hdl = pci_Probe((NexusPCIDevID *)drv->id_table, num_ids, 
			  type,
			  (unsigned int)&cli_holder, 
			  (unsigned int)&pending_intr,
			  npci_dev);

  if (pci_hdl <= 0) {
    printf("No driver found for device %s\n", drv->name);
    return 0;
  }

  /* find which id was selected */
  for(i = 0; i < num_ids; i++){
    NexusPCIDevID *id = (NexusPCIDevID *)&drv->id_table[i];
    
    if ((id->vendor == PCI_ANY_ID || id->vendor == npci_dev->vendor) &&
	(id->device == PCI_ANY_ID || id->device == npci_dev->device) &&
	(id->subvendor == PCI_ANY_ID || id->subvendor == npci_dev->subsystem_vendor) &&
	(id->subdevice == PCI_ANY_ID || id->subdevice == npci_dev->subsystem_device) &&
	!((id->class ^ npci_dev->class) & id->class_mask))
      break;
  }

  /* create the fake Linux struct pci_dev */
  //pci_dev = pci_dev_create(npci_dev, drv);
  pci_dev = (struct pci_dev *)malloc(sizeof(struct pci_dev));
  pci_dev_reload(pci_dev, pci_hdl);  
  driverdev = pci_dev; /* XXX get rid of this stupid old hack */

  if(drv->probe((struct pci_dev *)pci_dev, &drv->id_table[i]) < 0)
    return 0;

  printf("[pci] registered device %s of type %d\n", drv->name, type);
  return 1; 
}

struct dma_addr_t;
void *pci_alloc_consistent(struct pci_dev *hwdev, 
			   size_t size,
			   dma_addr_t *dma_handle) { 
  unsigned int paddr, vaddr;

  if (ddrm_sys_allocate_memory(size, 0, &vaddr, &paddr))
	  return NULL;

  *dma_handle = paddr;
  return (void *) vaddr; 
}

dma_addr_t pci_map_single_nexuscompat(struct pci_dev *hwdev, void *ptr, 
				      size_t size, int direction){
  return Mem_GetPhysicalAddress(ptr, size);
}

/* -------------------------------------------------------------*/


void * __ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags){
  unsigned int mappedpaddr, mappedvaddr;
  int mappedsize, offset;
  int i;

  assert(driverdev != NULL);
  assert(driverdev->map_info != NULL);

  for(i = 0; i < 6; i++){
    mappedpaddr = driverdev->map_info[i].paddr;
    mappedvaddr = driverdev->map_info[i].vaddr;
    mappedsize  = driverdev->map_info[i].size;
    if ((phys_addr >= mappedpaddr) && (phys_addr + size <= mappedpaddr + mappedsize)) {
      offset = phys_addr - mappedpaddr;
      return (void*) mappedvaddr + offset;
    }
  }
  assert(0);
  return NULL;
}

/*  
 *  from pci-i386.c:
 *  If we set up a device for bus mastering, we need to check the latency
 *  timer as certain crappy BIOSes forget to set it properly.
 */
unsigned int pcibios_max_latency = 255;

void pcibios_set_master(struct pci_dev *dev)
{
	u8 lat;
	pci_read_config_byte(dev, PCI_LATENCY_TIMER, &lat);
	
	if (lat < 16)
		lat = (64 <= pcibios_max_latency) ? 64 : pcibios_max_latency;
	else if (lat > pcibios_max_latency)
		lat = pcibios_max_latency;
	else
		return;
	pci_write_config_byte(dev, PCI_LATENCY_TIMER, lat);
}


// from pci.c
void pci_set_master(struct pci_dev *dev) { 
  u16 cmd;

  pci_read_config_word(dev, PCI_COMMAND, &cmd);

  if (! (cmd & PCI_COMMAND_MASTER)) {
    cmd |= PCI_COMMAND_MASTER;
    pci_write_config_word(dev, PCI_COMMAND, cmd);
  }
  pcibios_set_master(dev);
}

//unsigned int dmaregcnt = 0;

static void pci_dev_reload(struct pci_dev *pdev, int pci_dev_oid) {
  if(pci_CopyFromHandle(pci_dev_oid, pdev, sizeof(*pdev)) < 0) {
    printk("Error reloading pci dev!\n");
  }
  pdev->pci_dev_oid = pci_dev_oid;
}

#define PCI_ENTER()							\
  int pci_dev_oid = pdev->pci_dev_oid; /* Save */			\
  {									\
    struct pci_dev check_pdev;						\
    pci_dev_reload(&check_pdev, pci_dev_oid);				\
    if(memcmp(&check_pdev, pdev, sizeof(check_pdev)) != 0) {		\
      printk("check pdev mismatch! check_pdev size = %d, %s:%d\n", sizeof(check_pdev), __FILE__,__LINE__); \
      int i;								\
      exit(1);							\
    }									\
  }

#define PCI_EXIT()						\
  printk_djwill("exiting %s\n", __FUNCTION__);				\
  pci_dev_reload(pdev, pci_dev_oid)

int pci_set_dma_mask(struct pci_dev *pdev, u64 mask) { 
  PCI_ENTER();

   if(mask < 0x00ffffff)
    return -EIO;
  
   pci_set_dma_mask_internal(pci_dev_oid, mask);

   PCI_EXIT();  
   return 0; 
}

void pcicompat_set_drvdata (struct pci_dev *pdev, void *data){
  PCI_ENTER();
  pci_set_drvdata_internal(pci_dev_oid, data);
  PCI_EXIT();
}

void pci_disable_device(struct pci_dev *pdev) {
  PCI_ENTER();
  pci_disable_device_internal(pci_dev_oid);
  PCI_EXIT();
}

struct pci_dev *pci_find_device (unsigned int vendor, unsigned int device, 
				 const struct pci_dev *from) {
  printk("%s: not implemented\n", __FUNCTION__);
  return NULL;
}

struct pci_dev *pci_find_slot (unsigned int bus, unsigned int devfn) {
  printk("%s: not implemented\n", __FUNCTION__);
  return NULL;
}

int pci_enable_device(struct pci_dev *pdev) {
  PCI_ENTER();
  int rv = pci_enable_device_internal(pci_dev_oid);
  PCI_EXIT();
  return rv;
}

int pci_request_regions(struct pci_dev *pdev, char *resname) {
  PCI_ENTER();
  int rv = pci_request_regions_internal(pci_dev_oid, resname);
  PCI_EXIT();
  return rv;
}

void pci_release_regions(struct pci_dev *pdev) {
  PCI_ENTER();
  pci_release_regions_internal(pci_dev_oid);
  PCI_EXIT();
}


#define DO_CONFIG(DIR,SIZE) \
  PCI_ENTER();								\
  int err = pci_##DIR##_config_##SIZE##_internal(pci_dev_oid, where, val); \
  PCI_EXIT();								\
  return err;

int pci_read_config_byte(struct pci_dev *pdev, int where, u8 *val) {
  DO_CONFIG(read,byte);
}

int pci_read_config_word(struct pci_dev *pdev, int where, u16 *val) {
  DO_CONFIG(read,word);
}
int pci_read_config_dword(struct pci_dev *pdev, int where, u32 *val) {
  DO_CONFIG(read,dword);
}

int pci_write_config_byte(struct pci_dev *pdev, int where, u8 val) {
  DO_CONFIG(write,byte);
}
int pci_write_config_word(struct pci_dev *pdev, int where, u16 val) {
  DO_CONFIG(write,word);
}
int pci_write_config_dword(struct pci_dev *pdev, int where, u32 val) {
  DO_CONFIG(write,dword);
}

struct resource * __request_region(struct resource *parent, unsigned long start, unsigned long n, const char *name)
{
  printk("__request_region (currently a noop, returns 1 for ne2k-pci success)\n");
  return (struct resource *)1;
}

void __release_region(struct resource *parent, unsigned long start, unsigned long n)
{
  printk("__release_region!\n");
}





