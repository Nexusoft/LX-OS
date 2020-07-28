/*
 *	PCI Bus Services -- Function For Backward Compatibility
 *
 *	Copyright 1998--2000 Martin Mares <mj@ucw.cz>
 */

#include <nexus/defs.h>
#include <nexus/device.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <asm/hw_irq.h>

#include <nexus/compat.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#include <nexus/net.h>

int
pcibios_present(void)
{
	return !list_empty(&pci_devices);
}

int
pcibios_find_class(unsigned int class, unsigned short index, unsigned char *bus, unsigned char *devfn)
{
	const struct pci_dev *dev = NULL;
	int cnt = 0;

	while ((dev = pci_find_class(class, dev)))
		if (index == cnt++) {
			*bus = dev->bus->number;
			*devfn = dev->devfn;
			return PCIBIOS_SUCCESSFUL;
		}
	return PCIBIOS_DEVICE_NOT_FOUND;
}


int
pcibios_find_device(unsigned short vendor, unsigned short device, unsigned short index,
		    unsigned char *bus, unsigned char *devfn)
{
	const struct pci_dev *dev = NULL;
	int cnt = 0;

	while ((dev = pci_find_device(vendor, device, dev)))
		if (index == cnt++) {
			*bus = dev->bus->number;
			*devfn = dev->devfn;
			return PCIBIOS_SUCCESSFUL;
		}
	return PCIBIOS_DEVICE_NOT_FOUND;
}

#define PCI_OP(rw,size,type)							\
int pcibios_##rw##_config_##size (unsigned char bus, unsigned char dev_fn,	\
				  unsigned char where, unsigned type val)	\
{										\
	struct pci_dev *dev = pci_find_slot(bus, dev_fn);			\
	if (!dev) return PCIBIOS_DEVICE_NOT_FOUND;				\
	return pci_##rw##_config_##size(dev, where, val);			\
}

PCI_OP(read, byte, char *)
PCI_OP(read, word, short *)
PCI_OP(read, dword, int *)
PCI_OP(write, byte, char)
PCI_OP(write, word, short)
PCI_OP(write, dword, int)


// Make it easier to register linux net drivers as if they were nexus
// drivers. Note that nothing outside of this directory ever knows about
// (struct net_device).

static int set_rx_mode(struct net_device *dev, int new_flags) {
	if (new_flags & ~IFF_PROMISC) {
		printkx(PK_DRIVER, PK_WARN, "%s: unknown mode\n", __FUNCTION__);
		return -1;
	}

	dev->flags = new_flags;
	return 0;
}

/** forward IRQs from bounce_net_interrupt to the 
    low level interrupt handler */
struct llint_handler {
	linux_interrupt_t func;
	void *dev;
};

static int nxnet_dev_interrupt(int irq, NexusDevice *nd) {
	struct llint_handler * ll = nd->data;
	ll->func(irq, ll->dev, NULL);
	return 0;
}

int nexus_register_netdev(struct net_device *dev, char *name, 
			  linux_interrupt_t intr) {
	struct llint_handler *ll;
	int portnum;

	ll = galloc(sizeof(*ll));
	ll->func = intr;
	ll->dev = dev;

	portnum = nxnet_dev_init(dev->dev_addr, (void *) dev->hard_start_xmit, dev);
	if (portnum == -1)
		return -1;

	nexus_register_device(DEVICE_NETWORK, name, dev->irq, ll, 
			      nxnet_dev_interrupt, NULL, DRIVER_KERNEL);

	printk("NXDEBUG: Warning: opening device during registration\n");
	dev->open(dev);

	if (!default_ip_nic) {
		printkx(PK_NET, PK_INFO, "[net] default nic set\n");
		default_ip_nic = portnum;
	}

	return 0;
}

int request_irq(unsigned int irq, 
		void (*handler)(int, void *, struct pt_regs *),
		unsigned long irqflags, 
		const char * devname,
		void *dev_id)
{
	enable_8259A_irq(irq);
	return 0;
}

void free_irq(unsigned int irq, void *dev_id)
{
	disable_8259A_irq(irq);
}

#define ASSERTNOTCALLED() do { printk("%s (%s:%d) HAS NOT BEEN IMPLEMENTED! \n", __FUNCTION__, __FILE__, __LINE__); dump_stack(); nexuspanic(); } while(0)
#define PRINT_NOTIMPLEMENTED() printk("%s NOT IMPLEMENTED\n", __FUNCTION__)

void __kfree_skb(struct sk_buff *skb) { skb_destroy(skb); }
struct sk_buff *alloc_skb(unsigned int size, int priority) {ASSERTNOTCALLED(); return NULL;}
void cpu_raise_softirq(unsigned int cpu, unsigned int nr) {ASSERTNOTCALLED();}
extern int del_timer(struct timer_list * timer) {ASSERTNOTCALLED(); return 0;}
extern void add_timer(struct timer_list * timer) { printk("Oliver: Timers aren't implemented.  You'll get virtually identical semantics with Alarms in nexus/clock.h\n"); ASSERTNOTCALLED(); }

extern void __netdev_watchdog_up(struct net_device *dev) {ASSERTNOTCALLED();}
extern int		netif_receive_skb(struct sk_buff *skb) {ASSERTNOTCALLED(); return 0;}
extern int schedule_task(void /*struct tq_struct*/ *task) {ASSERTNOTCALLED(); return 0;}
struct sk_buff *skb_copy(const struct sk_buff *skb, int priority) {ASSERTNOTCALLED(); return NULL;}


unsigned short eth_type_trans(struct sk_buff *skb, struct net_device *dev) {
	
	skb_pull(skb, ETH_HLEN);
	skb->mac.raw = skb->data - ETH_HLEN;

	/*
	 *	This is a magic hack to spot IPX packets. Older Novell breaks
	 *	the protocol design and runs IPX over 802.3 without an 802.2 LLC
	 *	layer. We look for FFFF which isn't a used 802.2 SSAP/DSAP. This
	 *	won't work for fault tolerant netware but does for the rest.
	 */
	if (*(unsigned short *)skb->data == 0xFFFF)
		return htons(ETH_P_802_3);
	else	
		return htons(ETH_P_802_2);
}

