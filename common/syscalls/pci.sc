syscall pci {
  decls {
    struct pci_dev;
    struct pci_device_id;
    includefiles { "<nexus/udevice.h>" }
    includefiles { "<nexus/pci.h>" }
  }

  decls __callee__ {
    includefiles { "<linux/pci.h>" }
    includefiles { "<nexus/defs.h>" }
    includefiles { "<nexus/mem.h>" }
    includefiles { "<nexus/ipd.h>" }
    includefiles { "<nexus/util.h>" }
    includefiles { "<nexus/hashtable.h>" }

    includefiles { "Thread.interface.h" }

    includefiles { "<linux/pci.h>" }
    includefiles { "<asm/hw_irq.h>" }
    includefiles { "<nexus/net.h>" }
    includefiles { "<nexus/device.h>" }
    includefiles { "<nexus/unet.h>" }
    includefiles { "<asm/system.h>" }
    includefiles { "nexus/synch-inline.h" }

    /** Return the device structure if the handle is 
        valid and owned by this process. */
    static inline struct pci_dev * 
    pcidev_get(int pci_dev_oid) {
      extern int num_nexus_pci_devices;					
      extern NexusPCIDev nexus_pci_devices[];
      NexusPCIDev *ndev;

      if (pci_dev_oid < 0 || pci_dev_oid > num_nexus_pci_devices)	
	return NULL;							

      ndev = &nexus_pci_devices[pci_dev_oid];		
      if (!ndev->assigned || !ndev->ddrm)			
	return NULL;							
									
      if (ndev->ddrm->ipd != nexusthread_current_ipd())
	return NULL;							
									
      return ndev->linux_pci_dev;					
    }
    
  }

  interface int 
  enable_device_internal(int pci_dev_oid) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    if (!pdev)
      return -1;
    return pci_enable_device(pdev);
  }

  interface int 
  disable_device_internal(int pci_dev_oid) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    if (!pdev)
      return -1;

    pci_disable_device(pdev);
    return 0;
  }

  /* XXX this is probably bad */
  interface int  
  set_dma_mask_internal(int pci_dev_oid, unsigned long long mask) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    if (!pdev)
      return -1;

    pdev->dma_mask = mask;
    return 0;
  }

  interface int 
  set_drvdata_internal(int pci_dev_oid, void *data) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    if (!pdev)
      return -1;

    pdev->driver_data = data;
    return 0;
  }

  /** Request PCI ioport and memory regions */
  interface int 
  request_regions_internal(int pci_dev_oid, char *user_resname) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    char *res_name;
    int ret, err = 0;

    if (!pdev)
      return -1;

    res_name = peek_strdup(nexusthread_current_map(), (unsigned)user_resname, &err);
    if(!res_name)
      return -SC_ACCESSERROR;
    
    printkx(PK_PCI, PK_DEBUG, "[pci] request region %s\n", (char *)res_name);
    ret = pci_request_regions(pdev, res_name);
    gfree(res_name);
    return ret;
  }

  interface int 
  release_regions_internal(int pci_dev_oid) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    if (!pdev)
      return -1;

    pci_release_regions(pdev);
    return 0;
  }

  // config word stuff goes here
  interface int 
  write_config_dword_internal(int pci_dev_oid, int where, unsigned int value) {
#define DO_CONFIG_WRITE(SIZE)						\
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);			\
    if (!pdev)								\
      return -1;							\
									\
    if (where < 0 || where > 255)					\
      return -SC_INVALID;						\
    return pci_write_config_##SIZE (pdev, where, value);

    DO_CONFIG_WRITE(dword);
  }

  interface int 
  write_config_word_internal(int pci_dev_oid, int where, unsigned short value) {
    DO_CONFIG_WRITE(word);
  }

  interface int 
  write_config_byte_internal(int pci_dev_oid, int where, unsigned char value) {
    DO_CONFIG_WRITE(byte);
  }

  interface int 
  read_config_dword_internal(int pci_dev_oid, int where, unsigned int *value_p) {
#define DO_CONFIG_READ(SIZE,CTYPE)					\
      struct pci_dev *pdev = pcidev_get(pci_dev_oid);			\
      if (!pdev)							\
        return -1;							\
									\
      CTYPE value;							\
      if(where < 0 || where > 255)					\
	return -SC_INVALID;						\
      int ret = pci_read_config_##SIZE (pdev, where, &value);		\
      if (poke_user(nexusthread_current_map(), 				\
		    (unsigned int)value_p, &value, sizeof(value)) != 0) \
	return -SC_ACCESSERROR;						\
      return ret;

    DO_CONFIG_READ(dword, u32);
  }

  interface int 
  read_config_word_internal(int pci_dev_oid, int where, unsigned short *value_p) {
    DO_CONFIG_READ(word, u16);
  }
  
  interface int 
  read_config_byte_internal(int pci_dev_oid, int where, unsigned char *value_p) {
    DO_CONFIG_READ(byte, u8);
  }

  /** Try to take control of a device that matches the list of pci devices 
      that this driver supports.

      This function creates a DDRM and links it to the caller process.
      The ipd->ddrm and ipd->isdevice fields act as capabilities for the
      other pci.sc and ddrm.sc calls.
   
      @return on success, a nexus device handle
              on failure, a negative error code */
  interface int Probe(struct NexusPCIDevID *user_match_ids, int match_count, 
		      DeviceType type,
		      unsigned int cli_addr, 
		      unsigned pending_intr_addr,
		      struct UNexusPCIDev *result) {
    NexusPCIDevID *match_ids;
    NexusPCIDev *ndev;
    Map *map;
    int peeklen, ret;
    
    // sanity check input
    if (!user_match_ids  || !result ||
        match_count <= 0 || match_count > NEXUS_PCI_MAX_MATCH_NUM ||
	type < 0 || type >= NUM_DEVICE_TYPES)
      return -SC_INVALID;

    if (nexusthread_current_ipd()->ddrm)
      return -SC_INVALID;

    map = nexusthread_current_map();
    if (!map_contains_addr(map, cli_addr) ||
        !map_contains_addr(map, pending_intr_addr) ||
	!map_contains_addr(map, (unsigned int)result))
      return -SC_INVALID;

    // copy all device IDs that this driver supports
    peeklen = sizeof(NexusPCIDevID) * match_count;
    match_ids = galloc(peeklen);
    if (!match_ids)
      return -SC_NOMEM;

    ret = peek_user(map, (unsigned int) user_match_ids, match_ids, peeklen);
    if (ret) {
      gfree(match_ids);
      return -SC_ACCESSERROR;
    }

    // try to initialize a DDRM for a device that matches this driver
    ndev = ddrm_pci_init(match_ids, match_count, type, cli_addr, 
		         pending_intr_addr);
    gfree(match_ids);
    if (!ndev) 
      return -SC_NOTFOUND;

    // return the nexus-specific device structure
    ret = poke_user(map, (unsigned int) result, 
		    (UNexusPCIDev *)ndev, sizeof(UNexusPCIDev));
    if (ret)
      return -SC_ACCESSERROR;

    nexusthread_current_ipd()->isdevice = 1;
    printkx(PK_PCI, PK_DEBUG, "[pci] probe returns device %d\n", ndev->index);
    return ndev->index;
  }

  /** Copy the pdev structure from the kernel by pci_dev_oid;
      A pdev is a PCI device as found through pci probe function.
      
      @param pci_dev_oid is a capability acquired by calling to Probe */
  interface int CopyFromHandle(int pci_dev_oid, struct pci_dev *user_pdev, int max_len) {
    struct pci_dev *pdev = pcidev_get(pci_dev_oid);
    int len;

    if (!pdev)
      return -1;

    len = sizeof(*pdev);
    if (max_len < len)
      return -SC_NORESULTMEM;

    if (poke_user(nexusthread_current_map(), (unsigned) user_pdev, pdev, len))
      return -SC_ACCESSERROR;

    return len;
  }

}

