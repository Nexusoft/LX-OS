
#include <asm/bitops.h>

//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>

#include <nexus/defs.h>
#include <nexus/devicecompat.h>
#include <nexus/segments.h>
#include <nexus/device.h>
#include <nexus/interrupt_thread.h>
#include <nexus/ipc.h>
#include <nexus/pci.h>
#include <nexus/util.h>
#include <linux/types.h>		// NB: must come after some (which?) others

#include <nexus/Mem.interface.h>
#include <nexus/Thread.interface.h>
#include <nexus/Device.interface.h>
#include <nexus/Pci.interface.h>

#define PAGESHIFT 	(12)
#define PAGE_SHIFT	PAGESHIFT
#define PAGE_SIZE	PAGESIZE

#define PCI_SLOT(devfn)	(((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)	((devfn) & 0x07)


struct resource ioport_resource = { "PCI IO", 0x0000, IO_SPACE_LIMIT, IORESOURCE_IO };
struct resource iomem_resource = { "PCI mem", 0x00000000, 0xffffffff, IORESOURCE_MEM };

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
  return 1; ///< pcibios is not really supported. shouldn't this be 0?
}

void 
enable_irq(unsigned int irq) 
{
	assert(0);
}

/** Map a PCI resource onto a linux pci_dev struct resource */
static void 
nxpci_map_bar(struct pci_location loc, int bar, uint32_t bar_data, struct resource *resource)
{
  uint32_t bar_length;

  // get the length (obscure pci protocol) 
  bar_length = Pci_ConfigSpace_BarLength_ext(default_pci_port, loc, bar);
  if (!bar_length)
	return;

  // ioport or memory ?
  if (bar_data & 0x1) {
    resource->name = "ioport";
    resource->start = bar_data & 0xfffffffc;
    resource->end   = resource->start + bar_length - 1;
    resource->flags = IORESOURCE_IO;
  }
  else {
    resource->name = "mem";
    resource->start = bar_data & 0xfffffff0;
    resource->end   = resource->start + bar_length - 1;
    resource->flags = IORESOURCE_MEM;
    if (bar_data & 0x8)
      resource->flags |= IORESOURCE_PREFETCH;
  }

}

int
nxpci_configspace(struct pci_location loc, char *configspace)
{
	uint32_t dword;
	uint16_t vendor, device;
	int i;

	vendor = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, 0), 2);
	device = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, 2), 2);
	if (vendor == 0xffff)
		return -1;

	for (i = 0; i < 256; i++)
		configspace[i] = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, i), 1);

	return 0;
}

struct pci_configspace {
  uint16_t vendor;
  uint16_t device;
  uint16_t command_reg; 
  uint16_t status_reg;
  uint8_t  revision;
  uint8_t  classcode[3];
  uint8_t  cacheline;
  uint8_t  latency_tmr;
  uint8_t  header_type;
  uint8_t  bist;
  uint32_t bar[6];
  uint32_t cardbus_id;
  uint16_t sub_vendor;
  uint16_t sub_device;
  uint32_t rom_base_reg;
  uint8_t  reserved[8];
  uint8_t  irqline;
  uint8_t  irqpin;
  uint8_t  min_gnt;
  uint8_t  max_lat;  

  // not defined by base standard
  uint8_t  other[192];
} __attribute__((__packed__)); 


/** returns 0 on failure, pci_dev_oid handle on success */
int pci_register_driver(struct pci_driver *drv, int _type) { 
  struct pci_dev *pci_dev;
  int num_ids = 0, i, j, pci_hdl;

  struct pci_location loc;
  struct pci_configspace configspace;
  int *pci_ids, ilen;
  uint16_t vendor, device;

  // calculate pci (device, vendor) pairs to probe for
  for (i = 0; drv->id_table[i].vendor && 
	      drv->id_table[i].device; i++)
	i++;
  ilen = sizeof(int) * i;

  // copy pairs from linux-specific structure
  pci_ids = malloc(ilen);
  for (i = 0; drv->id_table[i].vendor && 
	      drv->id_table[i].device; i++)
	pci_ids[i] = (drv->id_table[i].vendor << 16) | drv->id_table[i].device;

  // call pci.drv to probe
  loc = Pci_Probe_ext(default_pci_port, VARLEN(pci_ids, ilen));
  if (loc.bus == 0xff) {
    fprintf(stderr, "[pci] no device found for driver %s\n", drv->name);
    return 0;
  }

  if (nxpci_configspace(loc, (void *) &configspace)) {
    fprintf(stderr, "[pci] error at configspace copy\n");
    return 0;
  }

  // build linux device struct 
  // fragile: has to use some default values
  pci_dev = calloc(1, sizeof(struct pci_dev));
  pci_dev->bus			= (void *) loc.bus;
  pci_dev->devfn 		= (loc.dev << 3) | (loc.fn & 0x7);
  pci_dev->vendor 		= configspace.vendor;
  pci_dev->device 		= configspace.device;
  pci_dev->subsystem_device 	= configspace.sub_device;
  pci_dev->class		= 0;//configspace.classcode;
  pci_dev->hdr_type		= 0;//configspace.header_type;
  pci_dev->rom_base_reg		= 0x30; // hardcoded offset from start according to pci spec 
  pci_dev->current_state 	= 0x4;  // ACPI: asleep
  pci_dev->active		= 0;    // ISAPnP: asleep
  pci_dev->ro			= 0;
  pci_dev->transparent		= 0;
  pci_dev->dma_mask		= 0xffffffff;
  pci_dev->regs			= 0; // ISAPnP:  not supported
  pci_dev->irq 			= configspace.irqline;
  memcpy(pci_dev->name, "unknown", 8);
  memcpy(pci_dev->slot_name, "unknown", 8);

  // copy over supported device PCIIDs
  for (i = 0; i < DEVICE_COUNT_COMPATIBLE && 
	      drv->id_table[i].vendor && 
	      drv->id_table[i].device; i++) {
	  pci_dev->vendor_compatible[i]	= drv->id_table[i].vendor;
	  pci_dev->device_compatible[i]	= drv->id_table[i].device;
  }

  // set memory regions
  for (i = 0; i < 6; i++)
  	nxpci_map_bar(loc, i, configspace.bar[i], &pci_dev->resource[i]);

  /* call userspace driver ->probe() function with new PCI id */
  if (drv->probe(pci_dev, &drv->id_table[i]) < 0) {
    fprintf(stderr, "[pci] probe: no supported devices found\n");
    return 0;
  }
  
  return 1; 
}

struct dma_addr_t;
void *
pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
		     dma_addr_t *dma_handle) 
{
  void *vaddr;

  vaddr = (void *) Mem_GetPages(PAGECOUNT(size), 0);
  *dma_handle = Mem_GetPhysicalAddress(vaddr, size);

  return vaddr; 
}

dma_addr_t pci_map_single_nexuscompat(struct pci_dev *hwdev, void *ptr, 
				      size_t size, int direction){
  return Mem_GetPhysicalAddress(ptr, size);
}

/* -------------------------------------------------------------*/


/** noop: have already replaced physical with virtual address 
  	  at initial device registration using nxpci_map_bar */
void * 
__ioremap(unsigned long phys_addr, unsigned long size, unsigned long flags)
{
  return Device_mem_map(phys_addr, size);
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

int pci_set_dma_mask(struct pci_dev *pdev, u64 mask) { 
  if(mask < 0x00ffffff)
   return -EIO;
  
  // skip: only support standard 32-bit mask
  return 0; 
}

void pcicompat_set_drvdata (struct pci_dev *pdev, void *data) {
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

int pci_request_regions(struct pci_dev *pdev, char *resname) {
  return 0;
}

void pci_release_regions(struct pci_dev *pdev) {
}

/** Calculate the correct configuration space address and 
    issue a pci read through the kernel */
static int
nxpci_read(struct pci_dev *pdev, int offset, int len)
{
  unsigned long address;

  address = PCI_ADDRESS((unsigned long) pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn), offset);
  return Device_pciconfig_read(address, len);
}

static int
nxpci_write(struct pci_dev *pdev, int offset, int len, unsigned long value)
{
  unsigned long address;

  address = PCI_ADDRESS((unsigned long) pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn), offset);
  Device_pciconfig_write(address, len, value);
  return 0;
}

int pci_read_config_byte(struct pci_dev *pdev, int where, u8 *val) {
  *val = (u8) nxpci_read(pdev, where, 1);
  return 0;
}

int pci_read_config_word(struct pci_dev *pdev, int where, u16 *val) {
  *val = (u16) nxpci_read(pdev, where, 2);
  return 0;
}
int pci_read_config_dword(struct pci_dev *pdev, int where, u32 *val) {
  *val = (u32) nxpci_read(pdev, where, 4);
  return 0;
}

int pci_write_config_byte(struct pci_dev *pdev, int where, u8 val) {
  return nxpci_write(pdev, where, 1, val);
}
int pci_write_config_word(struct pci_dev *pdev, int where, u16 val) {
  return nxpci_write(pdev, where, 2, val);
}
int pci_write_config_dword(struct pci_dev *pdev, int where, u32 val) {
  return nxpci_write(pdev, where, 4, val);
}

int 
pci_enable_device(struct pci_dev *pdev) 
{
  uint16_t cmd;

  pci_read_config_word(pdev, 4, &cmd);
  if ((cmd & 0x3) != 0x3) {
	  cmd |= 0x3 /* memory BARs | ioport BARS */;
	  pci_write_config_word(pdev, 4, cmd);
  }

  return 0;
}

void 
pci_disable_device(struct pci_dev *pdev) 
{
  uint16_t cmd;

  pci_read_config_word(pdev, 4, &cmd);
  if (cmd & 0x3) {
	  cmd &= ~(0x3 /* memory BARs | ioport BARS */);
	  pci_write_config_word(pdev, 4, cmd);
  }
}

struct resource * __request_region(struct resource *parent, unsigned long start, unsigned long n, const char *name)
{
}

void __release_region(struct resource *parent, unsigned long start, unsigned long n)
{
}

