/** NexusOS: pci driver: 
    scans bus and responds to probe requests from other drivers */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <nexus/hashtable.h>
#include <nexus/Device.interface.h>
#include <nexus/Pci.interface.h>

#define PCI_NUM_BUS	255
#define PCI_NUM_DEV	32
#define PCI_NUM_FN	8

#define PCI_ADDRESS(bus, dev, fn, off) \
      (0x80000000 | (bus << 16) | (dev << 11) | (fn << 8) | (off))

/** Lookup device location (bus.dev.fn) by vendor.device */
static struct HashTable *devicetable;


//////// support

static unsigned long
probe(uint16_t vendor, uint16_t device)
{
	uint32_t index;

	index = (vendor << 16) | device;
	return (unsigned long) hash_findItem(devicetable, &index);
}

static inline void
scan_test(int bus, int dev, int fn)
{
	uint32_t index;
	uint16_t vendor, device;
	int len;

	// test whether this function holds a device
	vendor = Device_pciconfig_read(PCI_ADDRESS(bus, dev, fn, 0), 2);
	device = Device_pciconfig_read(PCI_ADDRESS(bus, dev, fn, 2), 2);
	if (vendor == 0xffff)
		return;

	// insert into lookup table
	index = (vendor << 16) | device;
	hash_insert(devicetable, &index, (void *) ((bus << 16) | (dev << 8) | fn));

	fprintf(stderr, "[pci] at %d.%d.%d device %02hx.%02hx\n", 
			bus, dev, fn, vendor, device);
}

/** Scan the entire PCI space for attached devices */
static void
scan(void)
{
	int bus, dev, fn;

	for (bus = 0; bus < PCI_NUM_BUS; bus++) {
		for (dev = 0; dev < PCI_NUM_DEV; dev++) {
			// XXX speed up: if fn0 says that this is a single dev
			//               then don't bother testing fn 1..7
			for (fn = 0; fn < PCI_NUM_FN; fn++) {
				scan_test(bus, dev, fn);
			}
		}
	}
}


//////// Pci.svc callbacks

/** For a given set of PCIIDs, return the first matching device.

    @param ilen is the length if the ID array in BYTES
    @return a device location, or location ffh.ffh.ffh
     
    XXX support lookup of the 2nd .. nth device */
struct pci_location
pci_probe(int *_ids, int ilen)
{
	struct pci_location loc;
	unsigned long _loc;
	uint16_t vendor, device;
	int i;

	for (i = 0; i < (ilen / sizeof(int)); i++) {
		vendor = _ids[i] >> 16 & 0xffff;
		device = _ids[i] & 0xffff;
		_loc = probe(vendor, device);
		if (_loc) {
			loc.bus = (_loc >> 16) & 0xff;
			loc.dev = (_loc >> 8) & 0xff;
			loc.fn  = (_loc) & 0xff;
			fprintf(stderr, "[pci] %hx.%hx -> %hu.%hu.%hu\n", 
				vendor, device, loc.bus, loc.dev, loc.fn);
			return loc;
		}
	}

	return (struct pci_location) { .bus = 0xff, .dev = 0xff, .fn = 0xff };
}

char *
pci_configspace(struct pci_location loc)
{
	unsigned long *configspace;
	uint16_t vendor, device;
	int i;

	vendor = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, 0), 2);
	device = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, 2), 2);
	if (vendor == 0xffff)
		return;

	configspace = malloc(256);
	for (i = 0; i < 256; i += 4)
		configspace[i / 4] = Device_pciconfig_read(PCI_ADDRESS(loc.bus, loc.dev, loc.fn, i), 4);

	return (char *) configspace;
}

int
main(int argc, char **argv)
{
	// scan pci space
	devicetable = hash_new(32, 4);
	scan();

	// initialize service
	Pci_serverInit();
 	
	// override dynamically assigned port
    	Pci_port_handle = IPC_CreatePort(default_pci_port);
	printf("[pci] driver up\n");
	
	// handle requests from device drivers
	while (1)
		Pci_processNextCommand();
	
	return 0;
}

