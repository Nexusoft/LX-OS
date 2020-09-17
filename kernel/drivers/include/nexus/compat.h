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
int nexus_register_netdev(struct net_device *dev, char *name, 
			  linux_interrupt_t intr, void *arg);

int nexus_open_netdev(void);

static inline int nexus_unimplemented(void) {
	nexuspanic();
	return 0;
}

static inline int verify_area(int type, const void * addr, unsigned long size) {
	return nexus_unimplemented();
}


#define put_user(x, ptr) nexus_unimplemented()
#define get_user(x, ptr) nexus_unimplemented()
#define access_ok(type,addr,size) nexus_unimplemented()

#endif
