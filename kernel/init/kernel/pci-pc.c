/*
 *	Low-Level PCI Support for PC
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 */

#include <linux/config.h>
#include <asm/types.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>

#include <asm/segment.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/smpboot.h>

#include "pci-i386.h"
#include <nexus/defs.h>

#define __init
#define __initdata
#define __devinit

unsigned int pci_probe = PCI_PROBE_BIOS | PCI_PROBE_CONF1 | PCI_PROBE_CONF2;

int pcibios_last_bus = -1;
struct pci_bus *pci_root_bus = NULL;
struct pci_ops *pci_root_ops = NULL;

static int pci_using_acpi_prt = 0;

#define BUS2QUAD(global) (0)
#define BUS2LOCAL(global) (global)
#define QUADLOCAL2BUS(quad,local) (local)

/*
 * This interrupt-safe spinlock protects all accesses to PCI
 * configuration space.
 */
static spinlock_t pci_config_lock = SPIN_LOCK_UNLOCKED;


/*
 * Functions for accessing PCI configuration space with type 1 accesses
 */

#ifdef CONFIG_PCI_DIRECT

#define PCI_CONF1_ADDRESS(bus, dev, fn, reg) \
	(0x80000000 | (bus << 16) | (dev << 11) | (fn << 8) | (reg & ~3))

static int pci_conf1_read (int seg, int bus, int dev, int fn, int reg, int len, u32 *value) /* !CONFIG_MULTIQUAD */
{
	unsigned long flags;
	//printk("DAN: pci_conf1_read\n");

	if (bus > 255 || dev > 31 || fn > 7 || reg > 255)
		return -EINVAL;

	spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, dev, fn, reg), 0xCF8);

	switch (len) {
	case 1: *value = inb(0xCFC + (reg & 3));
		break;
	case 2: *value = inw(0xCFC + (reg & 2));
		break;
	case 4:
		*value = inl(0xCFC);
		break;
	}

	spin_unlock_irqrestore(&pci_config_lock, flags);
	return 0;
}

static int pci_conf1_write (int seg, int bus, int dev, int fn, int reg, int len, u32 value) /* !CONFIG_MULTIQUAD */
{
	unsigned long flags;
	//printk("DAN: pci_conf1_write\n");
	if ((bus > 255 || dev > 31 || fn > 7 || reg > 255)) 
		return -EINVAL;

	spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, dev, fn, reg), 0xCF8);

	switch (len) {
	case 1:
		outb((u8)value, 0xCFC + (reg & 3));
		break;
	case 2:
		outw((u16)value, 0xCFC + (reg & 2));
		break;
	case 4:
		outl((u32)value, 0xCFC);
		break;
	}

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

#undef PCI_CONF1_ADDRESS

extern int pci_conf1_read_config_byte(struct pci_dev *dev, int where, u8 *value)
{
	int result; 
	u32 data;
	result = pci_conf1_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		PCI_FUNC(dev->devfn), where, 1, &data);

	*value = (u8)data;

	return result;
}

extern int pci_conf1_read_config_word(struct pci_dev *dev, int where, u16 *value)
{
	int result; 
	u32 data;

	result = pci_conf1_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		PCI_FUNC(dev->devfn), where, 2, &data);

	*value = (u16)data;

	return result;
}

extern int pci_conf1_read_config_dword(struct pci_dev *dev, int where, u32 *value)
{
	return pci_conf1_read(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		 PCI_FUNC(dev->devfn), where, 4, value);
}

extern int pci_conf1_write_config_byte(struct pci_dev *dev, int where, u8 value)
{
	return pci_conf1_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		PCI_FUNC(dev->devfn), where, 1, value);
}

extern int pci_conf1_write_config_word(struct pci_dev *dev, int where, u16 value)
{
	return pci_conf1_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		PCI_FUNC(dev->devfn), where, 2, value);
}

extern int pci_conf1_write_config_dword(struct pci_dev *dev, int where, u32 value)
{
	return pci_conf1_write(0, dev->bus->number, PCI_SLOT(dev->devfn), 
		PCI_FUNC(dev->devfn), where, 4, value);
}

static struct pci_ops pci_direct_conf1 = {
	pci_conf1_read_config_byte,
	pci_conf1_read_config_word,
	pci_conf1_read_config_dword,
	pci_conf1_write_config_byte,
	pci_conf1_write_config_word,
	pci_conf1_write_config_dword
};

/*
 * Before we decide to use direct hardware access mechanisms, we try to do some
 * trivial checks to ensure it at least _seems_ to be working -- we just test
 * whether bus 00 contains a host bridge (this is similar to checking
 * techniques used in XFree86, but ours should be more reliable since we
 * attempt to make use of direct access hints provided by the PCI BIOS).
 *
 * This should be close to trivial, but it isn't, because there are buggy
 * chipsets (yes, you guessed it, by Intel and Compaq) that have no class ID.
 */
static int __devinit pci_sanity_check(struct pci_ops *o)
{
	u16 x;
	struct pci_bus bus;		/* Fake bus and device */
	struct pci_dev dev;
	//	printk("DAN: pci_sanity_check\n");
	if (pci_probe & PCI_NO_CHECKS)
		return 1;
	bus.number = 0;
	dev.bus = &bus;
	for(dev.devfn=0; dev.devfn < 0x100; dev.devfn++)
		if ((!o->read_word(&dev, PCI_CLASS_DEVICE, &x) &&
		     (x == PCI_CLASS_BRIDGE_HOST || x == PCI_CLASS_DISPLAY_VGA)) ||
		    (!o->read_word(&dev, PCI_VENDOR_ID, &x) &&
		     (x == PCI_VENDOR_ID_INTEL || x == PCI_VENDOR_ID_COMPAQ)))
			return 1;
	DBG("PCI: Sanity check failed\n");
	return 0;
}

static struct pci_ops * __devinit pci_check_direct(void)
{
	unsigned int tmp;
	unsigned long flags;

	__save_flags(flags); __cli();

	/*
	 * Check if configuration type 1 works.
	 */
	if (pci_probe & PCI_PROBE_CONF1) {
		outb (0x01, 0xCFB);
		tmp = inl (0xCF8);
		outl (0x80000000, 0xCF8);
		if (inl (0xCF8) == 0x80000000 &&
		    pci_sanity_check(&pci_direct_conf1)) {
			outl (tmp, 0xCF8);
			__restore_flags(flags);
			printk(KERN_INFO "PCI: Using configuration type 1\n");
			request_region(0xCF8, 8, "PCI conf1");

			return &pci_direct_conf1;
		}
		outl (tmp, 0xCF8);
	}

	/*
	 * Check if configuration type 2 works.
	 */
	if (pci_probe & PCI_PROBE_CONF2) {
		outb (0x00, 0xCFB);
		outb (0x00, 0xCF8);
		outb (0x00, 0xCFA);
		if (inb (0xCF8) == 0x00 && inb (0xCFA) == 0x00) {
			__restore_flags(flags);
			printk("[pci] possible type 2: not supported\n");
		}
	}

	__restore_flags(flags);
	return NULL;
}

#endif

/*
 * Several buggy motherboards address only 16 devices and mirror
 * them to next 16 IDs. We try to detect this `feature' on all
 * primary buses (those containing host bridges as they are
 * expected to be unique) and remove the ghost devices.
 */

static void __devinit pcibios_fixup_ghosts(struct pci_bus *b)
{
	struct list_head *ln, *mn;
	struct pci_dev *d, *e;
	int mirror = PCI_DEVFN(16,0);
	int seen_host_bridge = 0;
	int i;

	DBG("PCI: Scanning for ghost devices on bus %d\n", b->number);
	for (ln=b->devices.next; ln != &b->devices; ln=ln->next) {
		d = pci_dev_b(ln);
		if ((d->class >> 8) == PCI_CLASS_BRIDGE_HOST)
			seen_host_bridge++;
		for (mn=ln->next; mn != &b->devices; mn=mn->next) {
			e = pci_dev_b(mn);
			if (e->devfn != d->devfn + mirror ||
			    e->vendor != d->vendor ||
			    e->device != d->device ||
			    e->class != d->class)
				continue;
			for(i=0; i<PCI_NUM_RESOURCES; i++)
				if (e->resource[i].start != d->resource[i].start ||
				    e->resource[i].end != d->resource[i].end ||
				    e->resource[i].flags != d->resource[i].flags)
					continue;
			break;
		}
		if (mn == &b->devices)
			return;
	}
	if (!seen_host_bridge)
		return;
	printk(KERN_WARNING "PCI: Ignoring ghost devices on bus %02x\n", b->number);

	ln = &b->devices;
	while (ln->next != &b->devices) {
		d = pci_dev_b(ln->next);
		if (d->devfn >= mirror) {
			list_del(&d->global_list);
			list_del(&d->bus_list);
			gfree(d);
		} else
			ln = ln->next;
	}
}

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void __devinit pcibios_fixup_peer_bridges(void)
{
	int n;
	struct pci_bus bus;
	struct pci_dev dev;
	u16 l;

	if (pcibios_last_bus <= 0 || pcibios_last_bus >= 0xff)
		return;
	DBG("PCI: Peer bridge fixup\n");
	for (n=0; n <= pcibios_last_bus; n++) {
		if (pci_bus_exists(&pci_root_buses, n))
			continue;
		bus.number = n;
		bus.ops = pci_root_ops;
		dev.bus = &bus;
		for(dev.devfn=0; dev.devfn<256; dev.devfn += 8)
			if (!pci_read_config_word(&dev, PCI_VENDOR_ID, &l) &&
			    l != 0x0000 && l != 0xffff) {
				DBG("Found device at %02x:%02x [%04x]\n", n, dev.devfn, l);
				printk(KERN_INFO "PCI: Discovered peer bus %02x\n", n);
				pci_scan_bus(n, pci_root_ops, NULL);
				break;
			}
	}
}

/*
 * Exceptions for specific devices. Usually work-arounds for fatal design flaws.
 */

static void __devinit pci_fixup_i450nx(struct pci_dev *d)
{
	/*
	 * i450NX -- Find and scan all secondary buses on all PXB's.
	 */
	int pxb, reg;
	u8 busno, suba, subb;
#ifdef CONFIG_MULTIQUAD
	int quad = BUS2QUAD(d->bus->number);
#endif
	printk("PCI: Searching for i450NX host bridges on %s\n", d->slot_name);
	reg = 0xd0;
	for(pxb=0; pxb<2; pxb++) {
		pci_read_config_byte(d, reg++, &busno);
		pci_read_config_byte(d, reg++, &suba);
		pci_read_config_byte(d, reg++, &subb);
		DBG("i450NX PXB %d: %02x/%02x/%02x\n", pxb, busno, suba, subb);
		if (busno)
			pci_scan_bus(QUADLOCAL2BUS(quad,busno), pci_root_ops, NULL);	/* Bus A */
		if (suba < subb)
			pci_scan_bus(QUADLOCAL2BUS(quad,suba+1), pci_root_ops, NULL);	/* Bus B */
	}
	pcibios_last_bus = -1;
}

static void __devinit pci_fixup_i450gx(struct pci_dev *d)
{
	/*
	 * i450GX and i450KX -- Find and scan all secondary buses.
	 * (called separately for each PCI bridge found)
	 */
	u8 busno;
	pci_read_config_byte(d, 0x4a, &busno);
	printk(KERN_INFO "PCI: i440KX/GX host bridge %s: secondary bus %02x\n", d->slot_name, busno);
	pci_scan_bus(busno, pci_root_ops, NULL);
	pcibios_last_bus = -1;
}

static void __devinit  pci_fixup_umc_ide(struct pci_dev *d)
{
	/*
	 * UM8886BF IDE controller sets region type bits incorrectly,
	 * therefore they look like memory despite of them being I/O.
	 */
	int i;

	printk(KERN_WARNING "PCI: Fixing base address flags for device %s\n", d->slot_name);
	for(i=0; i<4; i++)
		d->resource[i].flags |= PCI_BASE_ADDRESS_SPACE_IO;
}

static void __devinit  pci_fixup_ncr53c810(struct pci_dev *d)
{
	/*
	 * NCR 53C810 returns class code 0 (at least on some systems).
	 * Fix class to be PCI_CLASS_STORAGE_SCSI
	 */
	if (!d->class) {
		printk("PCI: fixing NCR 53C810 class code for %s\n", d->slot_name);
		d->class = PCI_CLASS_STORAGE_SCSI << 8;
	}
}

static void __devinit pci_fixup_ide_bases(struct pci_dev *d)
{
	int i;

	/*
	 * PCI IDE controllers use non-standard I/O port decoding, respect it.
	 */
	if ((d->class >> 8) != PCI_CLASS_STORAGE_IDE)
		return;
	DBG("PCI: IDE base address fixup for %s\n", d->slot_name);
	for(i=0; i<4; i++) {
		struct resource *r = &d->resource[i];
		if ((r->start & ~0x80) == 0x374) {
			r->start |= 2;
			r->end = r->start;
		}
	}
}

static void __devinit  pci_fixup_ide_trash(struct pci_dev *d)
{
	int i;

	/*
	 * There exist PCI IDE controllers which have utter garbage
	 * in first four base registers. Ignore that.
	 */
	DBG("PCI: IDE base address trash cleared for %s\n", d->slot_name);
	for(i=0; i<4; i++)
		d->resource[i].start = d->resource[i].end = d->resource[i].flags = 0;
}

static void __devinit  pci_fixup_latency(struct pci_dev *d)
{
	/*
	 *  SiS 5597 and 5598 chipsets require latency timer set to
	 *  at most 32 to avoid lockups.
	 */
	DBG("PCI: Setting max latency to 32\n");
	pcibios_max_latency = 32;
}

static void __devinit pci_fixup_piix4_acpi(struct pci_dev *d)
{
	/*
	 * PIIX4 ACPI device: hardwired IRQ9
	 */
	d->irq = 9;
}

/*
 * Addresses issues with problems in the memory write queue timer in
 * certain VIA Northbridges.  This bugfix is per VIA's specifications,
 * except for the KL133/KM133: clearing bit 5 on those Northbridges seems
 * to trigger a bug in its integrated ProSavage video card, which
 * causes screen corruption.  We only clear bits 6 and 7 for that chipset,
 * until VIA can provide us with definitive information on why screen
 * corruption occurs, and what exactly those bits do.
 * 
 * VIA 8363,8622,8361 Northbridges:
 *  - bits  5, 6, 7 at offset 0x55 need to be turned off
 * VIA 8367 (KT266x) Northbridges:
 *  - bits  5, 6, 7 at offset 0x95 need to be turned off
 * VIA 8363 rev 0x81/0x84 (KL133/KM133) Northbridges:
 *  - bits     6, 7 at offset 0x55 need to be turned off
 */

#define VIA_8363_KL133_REVISION_ID 0x81
#define VIA_8363_KM133_REVISION_ID 0x84

static void __init pci_fixup_via_northbridge_bug(struct pci_dev *d)
{
	u8 v;
	u8 revision;
	int where = 0x55;
	int mask = 0x1f; /* clear bits 5, 6, 7 by default */

	pci_read_config_byte(d, PCI_REVISION_ID, &revision);
	
	if (d->device == PCI_DEVICE_ID_VIA_8367_0) {
		/* fix pci bus latency issues resulted by NB bios error
		   it appears on bug free^Wreduced kt266x's bios forces
		   NB latency to zero */
		pci_write_config_byte(d, PCI_LATENCY_TIMER, 0);

		where = 0x95; /* the memory write queue timer register is 
				 different for the KT266x's: 0x95 not 0x55 */
	} else if (d->device == PCI_DEVICE_ID_VIA_8363_0 &&
	           (revision == VIA_8363_KL133_REVISION_ID || 
		    revision == VIA_8363_KM133_REVISION_ID)) {
		mask = 0x3f; /* clear only bits 6 and 7; clearing bit 5
				causes screen corruption on the KL133/KM133 */
	}

	pci_read_config_byte(d, where, &v);
	if (v & ~mask) {
		printk("Disabling VIA memory write queue (PCI ID %04x, rev %02x): [%02x] %02x & %02x -> %02x\n", \
			d->device, revision, where, v, mask, v & mask);
		v &= mask;
		pci_write_config_byte(d, where, v);
	}
}

/*
 * For some reasons Intel decided that certain parts of their
 * 815, 845 and some other chipsets must look like PCI-to-PCI bridges
 * while they are obviously not. The 82801 family (AA, AB, BAM/CAM,
 * BA/CA/DB and E) PCI bridges are actually HUB-to-PCI ones, according
 * to Intel terminology. These devices do forward all addresses from
 * system to PCI bus no matter what are their window settings, so they are
 * "transparent" (or subtractive decoding) from programmers point of view.
 */
static void __init pci_fixup_transparent_bridge(struct pci_dev *dev)
{
  // printk("DAN: pci_fixup_transparent_bridge\n");
	if ((dev->class >> 8) == PCI_CLASS_BRIDGE_PCI &&
	    (dev->device & 0xff00) == 0x2400)
		dev->transparent = 1;
}

struct pci_fixup pcibios_fixups[] = {
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82451NX,	pci_fixup_i450nx },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82454GX,	pci_fixup_i450gx },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_UMC,	PCI_DEVICE_ID_UMC_UM8886BF,	pci_fixup_umc_ide },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_5513,		pci_fixup_ide_trash },
	{ PCI_FIXUP_HEADER,	PCI_ANY_ID,		PCI_ANY_ID,			pci_fixup_ide_bases },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_5597,		pci_fixup_latency },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_5598,		pci_fixup_latency },
 	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82371AB_3,	pci_fixup_piix4_acpi },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8363_0,	pci_fixup_via_northbridge_bug },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8622,	        pci_fixup_via_northbridge_bug },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8361,	        pci_fixup_via_northbridge_bug },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8367_0,	pci_fixup_via_northbridge_bug },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_NCR,	PCI_DEVICE_ID_NCR_53C810,	pci_fixup_ncr53c810 },
	{ PCI_FIXUP_HEADER,	PCI_VENDOR_ID_INTEL,	PCI_ANY_ID,			pci_fixup_transparent_bridge },
	{ 0 }
};

/*
 *  Called after each bus is probed, but before its children
 *  are examined.
 */

void __devinit  pcibios_fixup_bus(struct pci_bus *b)
{
  //  printk("DAN: pcibios_fixup_bus\n");
	pcibios_fixup_ghosts(b);
	pci_read_bridge_bases(b);
}

struct pci_bus * __devinit pcibios_scan_root(int busnum)
{
	struct list_head *list;
	struct pci_bus *bus;

	list_for_each(list, &pci_root_buses) {
		bus = pci_bus_b(list);
		if (bus->number == busnum) {
			/* Already scanned */
			return bus;
		}
	}

	printk("PCI: Probing PCI hardware (bus %02x)\n", busnum);

	return pci_scan_bus(busnum, pci_root_ops, NULL);
}

void __devinit pcibios_config_init(void)
{
	pci_root_ops = &pci_direct_conf1;
}

int use_acpi_pci __initdata = 1;

void __init pcibios_init(void)
{
	int quad;

	if (!pci_root_ops)
		pcibios_config_init();
	if (!pci_root_ops) {
		printk(KERN_WARNING "PCI: System does not support PCI\n");
		return;
	}

#ifdef CONFIG_ACPI_PCI
	if (use_acpi_pci && !acpi_pci_irq_init()) {
		pci_using_acpi_prt = 1;
		printk(KERN_INFO "PCI: Using ACPI for IRQ routing\n");
		printk(KERN_INFO "PCI: if you experience problems, try using option 'pci=noacpi' or even 'acpi=off'\n");
	}
#endif
	if (!pci_using_acpi_prt) {
		pci_root_bus = pcibios_scan_root(0);
		pcibios_irq_init();
		pcibios_fixup_peer_bridges();
		pcibios_fixup_irqs();
	}
	extern int numnodes;
	if (clustered_apic_mode && (numnodes > 1)) {
		for (quad = 1; quad < numnodes; ++quad) {
			pci_scan_bus(QUADLOCAL2BUS(quad,0), 
				pci_root_ops, NULL);
		}
	}

	pcibios_resource_survey();
}

unsigned int pcibios_assign_all_busses(void)
{
	return (pci_probe & PCI_ASSIGN_ALL_BUSSES) ? 1 : 0;
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	int err;
	if ((err = pcibios_enable_resources(dev, mask)) < 0)
		return err;

#ifdef CONFIG_ACPI_PCI
	if (pci_using_acpi_prt) {
		acpi_pci_irq_enable(dev);
		return 0;
	}
#endif

	pcibios_enable_irq(dev);

	return 0;
}

