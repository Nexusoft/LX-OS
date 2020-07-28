#ifndef _NEXUS_DRIVER_COMPAT_H_
#define _NEXUS_DRIVER_COMPAT_H_
#include <nexus/defs.h>
#include <nexus/device.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <asm/types.h>

struct pt_regs;
typedef void (*linux_interrupt_t)(int irq, void *dev_id, struct pt_regs *regs);
int nexus_register_netdev(struct net_device *dev, char *name, linux_interrupt_t intr);

static inline int nexus_unimplemented(void) {
	nexuspanic();
	return 0;
}

static inline unsigned long copy_to_user (void * to, const void * from, unsigned long n) {
	return nexus_unimplemented();
}

static inline unsigned long copy_from_user (void * to, const void * from, unsigned long n) {
	return nexus_unimplemented();
}

static inline int verify_area(int type, const void * addr, unsigned long size) {
	return nexus_unimplemented();
}


#define put_user(x, ptr) nexus_unimplemented()
#define get_user(x, ptr) nexus_unimplemented()
#define access_ok(type,addr,size) nexus_unimplemented()

struct pci_dev;
static inline void pci_unmap_page(struct pci_dev *hwdev, dma_addr_t dma_address,
				  size_t size, int direction) {
	nexus_unimplemented();
}

#endif
