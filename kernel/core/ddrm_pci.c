/** NexusOS: translation from DDRM resource calls to Linux pci calls */

#include <nexus/ddrm.h>
#include <linux/pci.h>
#include <nexus/djwilldbg.h>
#include <nexus/pci.h>
#include <nexus/synch-inline.h>

#define MAX_NEXUS_PCI_DEVS 50 /* This can be as big as we like but probably won't go over 20 */
NexusPCIDev nexus_pci_devices[MAX_NEXUS_PCI_DEVS]; 
int num_nexus_pci_devices = 0;  /*XXX  if these really need to be global move them*/
Sema pci_assignment_mutex = SEMA_MUTEX_INIT;

HashTable *resource_mapping_table;

static void resource_nexus_fixup(NexusResource *nres, struct resource *res){

  /* lookup the other resources in the resource mapping table */
  if(res->parent)
    nres->parent = (NexusResource *)hash_findItem(resource_mapping_table, 
						  res->parent);

  if(res->sibling)
    nres->sibling = (NexusResource *)hash_findItem(resource_mapping_table, 
						   res->sibling);

  if(res->child)
    nres->child = (NexusResource *)hash_findItem(resource_mapping_table, 
						 res->child);
}

static void resource_linux_to_nexus(NexusResource *nres, struct resource *res){
  assert(nres != NULL);
  assert(res != NULL);
  memset(nres->name, 0, NEXUS_RESOURCE_NAME_LEN);
  if(res->name){
    assert(strlen(res->name) < NEXUS_RESOURCE_NAME_LEN);
    strcpy(nres->name, res->name);
  }else{
    strcpy(nres->name, "No Name");
  }
  nres->start = res->start;
  nres->end = res->end;
  nres->flags = res->flags;
  nres->flags = res->flags;

  /* don't do parent/sibling/child yet */
  hash_insert(resource_mapping_table, res, nres);
}

static void pci_dev_linux_to_nexus(NexusPCIDev *ndev, struct pci_dev *dev){
  int i;

  ndev->devfn = dev->devfn;
  ndev->vendor = dev->vendor;
  ndev->device = dev->device;
  ndev->subsystem_device = dev->subsystem_device;
  ndev->class = dev->class;
  ndev->hdr_type = dev->hdr_type;
  ndev->rom_base_reg = dev->rom_base_reg;
  ndev->dma_mask = dev->dma_mask;
  ndev->current_state = dev->current_state;;

  memset(ndev->vendor_compatible, 0, sizeof(short) * NEXUS_DEVICE_COUNT_COMPATIBLE);
  memset(ndev->device_compatible, 0, sizeof(short) * NEXUS_DEVICE_COUNT_COMPATIBLE);

  for(i = 0; i < min(DEVICE_COUNT_COMPATIBLE, NEXUS_DEVICE_COUNT_COMPATIBLE); i++){
    ndev->vendor_compatible[i] = dev->vendor_compatible[i];
    ndev->device_compatible[i] = dev->device_compatible[i];
  }

  ndev->irq = dev->irq;

  /* save a mapping so we can do parent/sibling/child relationships later */
  resource_mapping_table = hash_new(128, sizeof(unsigned int));

  memset(&ndev->resource, 0, NEXUS_DEVICE_COUNT_RESOURCE * sizeof(NexusResource));
  memset(&ndev->dma_resource, 0, NEXUS_DEVICE_COUNT_DMA * sizeof(NexusResource));
  memset(&ndev->irq_resource, 0, NEXUS_DEVICE_COUNT_IRQ * sizeof(NexusResource));

  for(i = 0; i < min(DEVICE_COUNT_RESOURCE, NEXUS_DEVICE_COUNT_RESOURCE); i++)
    resource_linux_to_nexus(&ndev->resource[i], &dev->resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_DMA, NEXUS_DEVICE_COUNT_DMA); i++)
    resource_linux_to_nexus(&ndev->dma_resource[i], &dev->dma_resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_IRQ, NEXUS_DEVICE_COUNT_IRQ); i++)
    resource_linux_to_nexus(&ndev->irq_resource[i], &dev->irq_resource[i]);

  /* fix up all of the parent/sibling/child relationships */
  for(i = 0; i < min(DEVICE_COUNT_RESOURCE, NEXUS_DEVICE_COUNT_RESOURCE); i++)
    resource_nexus_fixup(&ndev->resource[i], &dev->resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_DMA, NEXUS_DEVICE_COUNT_DMA); i++)
    resource_nexus_fixup(&ndev->dma_resource[i], &dev->dma_resource[i]);
  for(i = 0; i < min(DEVICE_COUNT_IRQ, NEXUS_DEVICE_COUNT_IRQ); i++)
    resource_nexus_fixup(&ndev->irq_resource[i], &dev->irq_resource[i]);


  memset(ndev->name, 0, NEXUS_PCI_DEV_NAME_LEN);
  memset(ndev->slot_name, 0, NEXUS_PCI_SLOT_NAME_LEN);

  memcpy(ndev->name, dev->name, min(90, NEXUS_PCI_DEV_NAME_LEN));
  memcpy(ndev->slot_name, dev->slot_name, min(8, NEXUS_PCI_SLOT_NAME_LEN));

  ndev->active = dev->active;
  ndev->ro = dev->ro;
  ndev->regs = dev->regs;

  ndev->transparent = dev->transparent;

  ndev->linux_pci_dev = dev;
}

/** Initialize a list of all registered PCI devices */
void ddrm_sys_pci_init(void) {
  struct pci_dev *dev;

  pci_for_each_dev(dev) {
    NexusPCIDev *ndev = &nexus_pci_devices[num_nexus_pci_devices];
    pci_dev_linux_to_nexus(ndev, dev);
    ndev->index = num_nexus_pci_devices++;
    assert(dev->index <= MAX_NEXUS_PCI_DEVS);
  }

  printk("[pci] found %d devices\n", num_nexus_pci_devices);
}

static inline int is_pio_addr(unsigned int addr) {
	return addr < 0x10000;
}

static int ddrm_pci_add_resource(DDRM *ddrm,
				 NexusResource *entry, 
				 struct pci_map_info *map_info,
				 int barnum){
  assert(check_intr() == 1);
  int dbg = 1;
  DDRMRegion *newreg = NULL;
  unsigned long from, to;
  int size;

  from = entry->start;
  to = entry->end;

  if (to < from) {
    printkx(PK_DRIVER, PK_WARN, "[ddrm] negative size resource\n", to, from);
    return -1;
  }

  if(to == from)
    return 0;
  
  size = to - from;
  // Round up size to word boundary
  size = (size + 0x3) & ~0x3;

  if(!is_pio_addr(to)) {
    newreg = ddrm_create_region_mmio(ddrm, barnum, from, size);
  } else {
    newreg = ddrm_create_region_portio(ddrm, barnum, from, size);
  }

  if(newreg == NULL)
    return -1;

  /* to let user lvl pci layer know where things have been ioremapped */
  map_info->paddr = newreg->paddr;
  map_info->vaddr = newreg->uaddr;
  map_info->size = newreg->len;

  printkx(PK_DRIVER, PK_DEBUG, "[udev] mmap paddr %x vaddr %x size %u\n", 
	  map_info->paddr, map_info->vaddr, map_info->size);

  return 0;
}

static void ddrm_pci_init_resources(NexusPCIDev *dev){
  assert(check_intr() == 1);
  int i;

  for(i = 0; i < 6; i++){
    NexusResource *res = &dev->resource[i];
    int off = 0;
    while(res != NULL){
      int ret = ddrm_pci_add_resource(dev->ddrm, res, 
				      &dev->linux_pci_dev->map_info[i], 
				      i + off);
      assert(ret == 0);
      res = res->child;
      off += 10;
    }
  }  
}

static NexusPCIDev *nexus_pci_match(const NexusPCIDevID *ids, int numids){
  int i,j;

  for(j = 0; j < num_nexus_pci_devices; j++){
    NexusPCIDev *dev = &nexus_pci_devices[j];

    for(i = 0; i < numids; i++){
      const NexusPCIDevID *id = &ids[i];
      if ((id->vendor == PCI_ANY_ID || id->vendor == dev->vendor) &&
	  (id->device == PCI_ANY_ID || id->device == dev->device) &&
	  (id->subvendor == PCI_ANY_ID || id->subvendor == dev->subsystem_vendor) &&
	  (id->subdevice == PCI_ANY_ID || id->subdevice == dev->subsystem_device) &&
	  !((id->class ^ dev->class) & id->class_mask))
	return dev;
    }
  }
  return NULL;
}

/** Search for a device that matches the list of devices and set it
    up for userlevel driver control by creating a DDRM.  */
NexusPCIDev *ddrm_pci_init(NexusPCIDevID *match_ids, int numids,
			   DeviceType type,
			   unsigned int cli_addr, 
			   unsigned pending_intr_addr) {
  assert(check_intr() == 1);

  NexusPCIDev *ndev = nexus_pci_match(match_ids, numids);
  if (!ndev)
    return NULL;

  int have_pci_dev = 1;

  P(&pci_assignment_mutex);
  if(ndev->assigned == 0)
    ndev->assigned = 1;
  else
    have_pci_dev = 0;
  V(&pci_assignment_mutex);
  
  if(!have_pci_dev)
    return NULL;

  assert(ndev->ddrm == NULL);

  /* XXX hardcoded sample spec */
  extern DDRMSpec sample_spec;
  void i810_reset(DDRM *ddrm);
  sample_spec.reset_card = i810_reset;

  /* create ddrm */
  ndev->ddrm = ddrm_create(&sample_spec, cli_addr, pending_intr_addr, 
			   type, ndev->name, 
			   (void (*)(void *))ddrm_pci_reclaim,
			   (void *)ndev);

  if (ndev->ddrm == NULL){
    printkx(PK_DRIVER, PK_WARN, "[ddrm] error at create\n");
    ndev->assigned = 0;
    return NULL;
  }

  ddrm_pci_init_resources(ndev);

  return ndev;
}

void ddrm_pci_reclaim(NexusPCIDev *dev){
  assert(check_intr() == 1);
  dev->assigned = 0;
  dev->ddrm = NULL;
}

