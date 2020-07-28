#ifndef __NEXUS_PCI_H__
#define __NEXUS_PCI_H__

typedef struct NexusResource NexusResource;
typedef struct UNexusPCIDev UNexusPCIDev;
typedef struct NexusPCIDevID NexusPCIDevID;

//XXX still here because pci cleanup isn't finished
typedef struct NexusPCIMapInfo NexusPCIMapInfo;

#define NEXUS_PCI_DEV_NAME_LEN     (90)
#define NEXUS_PCI_SLOT_NAME_LEN     (8)
#define NEXUS_RESOURCE_NAME_LEN   (256)

#define NEXUS_DEVICE_COUNT_COMPATIBLE   (4)
#define NEXUS_DEVICE_COUNT_IRQ          (2)
#define NEXUS_DEVICE_COUNT_DMA	        (2)
#define NEXUS_DEVICE_COUNT_RESOURCE    (12)

#define NEXUS_PCI_MAX_MATCH_NUM   (20)

/*
 * Resources are tree-like, allowing
 * nesting etc..
 */
struct NexusResource {
  char name[NEXUS_RESOURCE_NAME_LEN];
  unsigned long start, end;
  unsigned long flags;
  /* XXX pointers may be just needed in kernel (and child at that) */
  NexusResource *parent, *sibling, *child;
};

struct NexusPCIDevID{
  unsigned int vendor, device;            /* Vendor and device ID or PCI_ANY_ID */
  unsigned int subvendor, subdevice;      /* Subsystem ID's or PCI_ANY_ID */
  unsigned int class, class_mask;         /* (class,subclass,prog-if) triplet */
  unsigned long driver_data;              /* Data private to the driver */
};

/* DAN: added pci_map_info for nexus */
/* XXX still here because pci cleanup isn't finished */
struct NexusPCIMapInfo{
  unsigned int paddr;
  unsigned int vaddr;
  int size;
};

/* This is the Nexus structure equivalent to pci_dev in Linux.  If
   can't fake the rest in userspace for driver compatibility, we'll
   have to add back fields. On the other hand, if these fields aren't
   all needed in Nexus, get rid of them. */


#define USER_NEXUS_SHARED_FIELDS					\
  int index; /* the index in nexus_pci_devices array.  This is also	\
		the handle to the user. */				\
  									\
  									\
  NexusPCIMapInfo map_info[NEXUS_DEVICE_COUNT_RESOURCE];/* XXX This is	\
							   here		\
							   because the	\
							   pci cleanup	\
							   is not	\
							   finished	\
							   yet */	\
  									\
  									\
  /*-------------------------------------------------------------*/	\
  /* below this line are fields inherited from Linux */			\
									\
  unsigned int	devfn;		/* encoded device & function index */	\
  unsigned short	vendor;						\
  unsigned short	device;						\
  unsigned short	subsystem_vendor;				\
  unsigned short	subsystem_device;				\
  unsigned int	class;		/* 3 bytes: (base,sub,prog-if) */	\
  unsigned char	hdr_type;	/* PCI header type (`multi' flag masked out) */	\
  unsigned char	rom_base_reg;	/* which config register controls the ROM */ \
									\
  unsigned long long dma_mask;	/* Mask of the bits of bus address this	\
				   device implements.  Normally this is	\
				   0xffffffff.  You only need to change	\
				   this if your device has broken DMA	\
				   or supports 64-bit transfers.  */	\
									\
  unsigned int current_state;  /* Current operating state. In ACPI-speak, \
				     this is D0-D3, D0 being fully functional, \
				     and D3 being off. */		\
									\
  /* device is compatible with these IDs */				\
  unsigned short vendor_compatible[NEXUS_DEVICE_COUNT_COMPATIBLE];	\
  unsigned short device_compatible[NEXUS_DEVICE_COUNT_COMPATIBLE];	\
									\
  /*									\
   * Instead of touching interrupt line and base address registers	\
   * directly, use the values stored here. They might be different!	\
   */									\
  unsigned int	irq;							\
  NexusResource resource[NEXUS_DEVICE_COUNT_RESOURCE]; /* I/O and memory regions + expansion ROMs */ \
  NexusResource dma_resource[NEXUS_DEVICE_COUNT_DMA];			\
  NexusResource irq_resource[NEXUS_DEVICE_COUNT_IRQ];			\
									\
  char		name[NEXUS_PCI_DEV_NAME_LEN];	/* device name */	\
  char		slot_name[NEXUS_PCI_SLOT_NAME_LEN];	/* slot name */	\
  int		active;		/* ISAPnP: device is active */		\
  int		ro;		/* ISAPnP: read only */			\
  unsigned short	regs;		/* ISAPnP: supported registers */ \
									\
  /* These fields are used by common fixups */				\
  unsigned short	transparent:1;	/* Transparent PCI bridge */	


struct UNexusPCIDev {
  USER_NEXUS_SHARED_FIELDS;
};

#ifdef __NEXUSKERNEL__
typedef struct NexusPCIDev NexusPCIDev;

struct pci_dev; /*XXX*/

struct NexusPCIDev {
  USER_NEXUS_SHARED_FIELDS;
  
  /* these are fields private to the Nexus */

  int assigned; /* 0 if assigned to a DDRM, 1 otherwise */
  DDRM *ddrm; /* the DDRM associated with this pci dev */

  // Only here because pci cleanup is not done.  This offends me greatly. */
  struct pci_dev *linux_pci_dev;
};
#endif

#endif
