/** NexusOS: userspace IDE driver */

#include <linux/pci.h>

#include <nexus/device.h>
#include <nexus/udevice.h>
#include <nexus/ioport.h>
#include <nexus/sema.h>
#include <nexus/block.h>
#include <nexus/pci.h>

#define SECTORSIZE	512
static const char *ide_driver_name = "ide storage";
static int blockdev_ipcport;

#define PCI_DMA_32BIT	0x00000000ffffffffULL
#define PCI_DMA_64BIT	0xffffffffffffffffULL

static struct 
pci_device_id ide_pci_table[] = 
{
	/* common Intel 82371sb PIIX3 IDE Controller. Emulated by Qemu */
	{PCI_VENDOR_ID_INTEL, 0x7010, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	/* other PIIX4/4E/4M IDE Controller */
	{PCI_VENDOR_ID_INTEL, 0x7111, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_INTEL, 0x2828, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_INTEL, 0x2828, 0x106b, 0x00a0, 0, 0, 0},
	{PCI_VENDOR_ID_INTEL, 0x2828, 0x106b, 0x00a1, 0, 0, 0},
	{PCI_VENDOR_ID_INTEL, 0x2828, 0x106b, 0x00a3, 0, 0, 0},
	{0}
};

static void ide_remove(struct pci_dev *pdev);
static int ide_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id);

static struct pci_driver ide_pci_driver = {
	name:		"ide storage",
	id_table:	ide_pci_table,
	probe:		ide_probe,
	remove:		ide_remove,
};

#ifdef DO_DEBUG

/** Debug routine: probe PCI config space */
void print_IOports(struct pci_dev *pdev)
{
    int i;
    {
        uint16_t word;
        uint32_t dword;
        uint8_t byte;

        pci_read_config_word(pdev, 0x0, &word);
        printk("vendor : %hx\n", word);
        pci_read_config_word(pdev, 0x2, &word);
        printk("device : %hx\n", word);
        pci_read_config_word(pdev, 0x4, &word);
        printk("command : %hx\n", word);
        pci_read_config_word(pdev, 0x6, &word);
        printk("status : %hx\n", word);
        pci_read_config_dword(pdev, 0x20, &dword);
        printk("bmiba : %x\n", dword);
        pci_read_config_byte(pdev, 0x20, &byte);
        printk("bmiba[0] : %x\n", byte);
        pci_read_config_byte(pdev, 0x21, &byte);
        printk("bmiba[1] : %x\n", byte);
        pci_read_config_byte(pdev, 0x22, &byte);
        printk("bmiba[2] : %x\n", byte);
        pci_read_config_byte(pdev, 0x23, &byte);
        printk("bmiba[3] : %x\n", byte);
    }
        for (i = 0x1f0; i <= 0x1f7; i++)
            printk("ioport %d %x\n", i, inb(i));

        for (i = 0x170; i <= 0x177; i++)
            printk("ioport %d %x\n", i, inb(i));
}

#endif

// IDE interrupt handler
static void 
ide_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    // Top half should ACK the device
    //printf("Disk interrupt received\n");
    hd_intr(NULL);
    //printf("Disk interrupt done\n");
}

static int 
ide_probe(struct pci_dev *pdev, const struct pci_device_id *pci_id)
{
    int i;
    int pci_dev_oid;
    pci_enable_pfault_handler();

    if (pci_enable_device(pdev)) {
        printf( "ide: no device found\n");
        return -EIO;
    }
    pci_dev_oid = pdev->pci_dev_oid;

#if 0
    // ask device driver reference monitor to grant access to IDE regions
    if (pci_request_regions_ide(pci_dev_oid)) {
	printf("[ide] access to IDE regions denied\n");
        return -ENODEV;
    }
    // resync pci device struct with kernel
    if (pci_CopyFromHandle(pci_dev_oid, pdev)) {
	printf("[ide] pci kernel sync failed\n");
        return -ENODEV;
    }
    pdev->pci_dev_oid = pci_dev_oid;
#endif

    // WARNING: we hardcode the IRQ of the primary IDE controller
    if (request_irq(14 /* pdev->irq */, &ide_interrupt, SA_SHIRQ, 
                "Intel PIIX IDE controller", NULL /* XXX put card struct here */)) {
        printf("ide: unable to allocate irq %d\n", pdev->irq);
        return -ENODEV;
    }
    
    if((i = pci_set_dma_mask(pdev, PCI_DMA_64BIT)) &&
       ((i = pci_set_dma_mask(pdev, PCI_DMA_32BIT)))) {
        printf("No usable DMA configuration, aborting\n");
        return i;
    }

    if (pci_request_regions(pdev, ide_driver_name)) {
	printf("[ide] access to PCI regions denied\n");
        return -ENODEV;
    }

    pci_set_master(pdev);

#ifdef DO_DEBUG
    print_IOports(pdev);
#endif

    init_hd(pdev->devfn);
    printf("[ide] registered device at IRQ 14\n");
    return 0;
}

static void ide_remove(struct pci_dev *pdev)
{
	// not implemented
}

/// boilerplate: translate blockdev read() into low-level driver read()
static int ide_read(unsigned long addr, unsigned long off, unsigned long len)
{
        int ret = dev_read(0, addr, len*SECTORSIZE, off, 0);
	return ret;
}

/// boilerplate: translate blockdev write() into low-level driver write()
static int ide_write(unsigned long addr, unsigned long off, unsigned long len)
{
        int ret = dev_write(0, addr, len*SECTORSIZE, off, 0);
	return ret;
}

/// calls to give to the blockdevice interface, so that the right one is 
//  called for each incoming blockdevice request (arriving over IPC)
struct nxblock_device_ops ide_ops = {
	.read = ide_read,
	.write = ide_write,
};

int main(int argc, char **argv)
{
	int pci_id;

	// discover pci
	if (!pci_present()) {
		printf("[ide] no PCI subsystem found\n");
		return -ENODEV;
	}
	
	// discover ide driver
	pci_id = pci_register_driver(&ide_pci_driver, 
				     DEVICE_STORAGE /* deprecated */ );
	if (!pci_id) {
                printf("[ide] no IDE device found\n");
		return -ENODEV;
	}
	
	// run quick selftest 
	// XXX reserve a region (partition) on disk just for this
	if (nxblock_selftest()) {
		printf("[ide] Abort\n");
		return -ENODEV;
	}
#if 0
	// XXX: This may destroy disk content
        if (nxblock_evaluate_io())
            printf("[ide] evaluation tests on IDE block device failed\n");
#endif

	// register as /dev/block0
	blockdev_ipcport = nxblock_server_register("block0");
	if (blockdev_ipcport < 0)
		return -EBADF;

	// listen for requests
	printf("[ide] up\n");
        while (!nxblock_server_serve(blockdev_ipcport, &ide_ops));

	// cleanup
	printf("[ide] closing\n");
	nxblock_server_unregister(blockdev_ipcport);
	pci_unregister_driver(&ide_pci_driver);
	return 0;
}

