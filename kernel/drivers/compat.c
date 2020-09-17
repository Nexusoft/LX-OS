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
#include <nexus/synch.h>
#include <nexus/thread.h>
#include <nexus/thread-inline.h>

#include <nexus/net.h>

void msleep(unsigned int msecs)
{
	nexusthread_usleep(1000 * msecs);  
}

unsigned long msleep_interruptible(unsigned int msecs)
{
	msleep(msecs);
	return 0;
}

void * kmalloc(int len, int unused)
{
	return galloc(len);
}

void kfree(void *region)
{
	gfree(region);
}

struct sk_buff *dev_alloc_skb(unsigned int length)
{
	return __dev_alloc_skb(length, 0);
}

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

unsigned int nexuscompat_pci_map_single(void *arg1, void *arg2, int arg3, int arg4)
{
  return map_get_physical_address(kernelMap, (unsigned long) arg2);
}

struct dma_addr_t;
void *
nexuscompat_pci_alloc_consistent(struct pci_dev *hwdev, size_t size,
		     		 dma_addr_t *dma_handle) 
{
	void *data;

	data = getKernelPages(PAGECOUNT(size));
	*dma_handle = fast_virtToPhys(kernelMap, data, 0, 0);
	return data;
}

struct pci_dev;
dma_addr_t pci_map_page(struct pci_dev *hwdev, void *page, unsigned long offset,
		    size_t size, int direction) 
{
	nexuspanic();
}

void pci_unmap_page(struct pci_dev *hwdev, dma_addr_t dma_address,
		  size_t size, int direction) 
{
	// noop
}

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
	int irq;
	linux_interrupt_t func;
	void *dev;
};

static int nxnet_dev_interrupt(void *_ll) {
	struct llint_handler * ll = _ll;

	assert(ll && ll->func && ll->dev);
	ll->func(ll->irq, ll->dev, NULL);
	return 0;
}

// hack: be able to find device to open() after probe() ends
struct net_device *global_netdev;
static Sema global_netdev_mutex = SEMA_MUTEX_INIT;

/** Similar to Linux device registration.
    @param arg the argument to pass to the interrupt handler */
int nexus_register_netdev(struct net_device *dev, char *name, 
			  linux_interrupt_t intr, void *arg) {
	struct llint_handler *ll;
	int portnum;
	int calc_pseudo;

	P(&global_netdev_mutex);
	if (global_netdev) {
		printk_red("[net] cannot register device: registration in progress\n");
		V(&global_netdev_mutex);
		return -1;
	}

	ll = galloc(sizeof(*ll));
	ll->irq = dev->irq;
	ll->func = intr;
	ll->dev = arg;

	// UGLY HACK: only tell netstack to calculate pseudo header for E1000 
	calc_pseudo = memcmp("e1000", name, 5) ? 0 : 1;

	portnum = nxnet_dev_init(dev->dev_addr, 
			dev->features & (NETIF_F_IP_CSUM | NETIF_F_HW_CSUM) ? 1 : 0,
			calc_pseudo, (void *) dev->hard_start_xmit, dev);
	if (portnum == -1) {
		V(&global_netdev_mutex);
		return -1;
	}

	nxirq_get(dev->irq, nxnet_dev_interrupt, ll);
	global_netdev = dev;

	V(&global_netdev_mutex);
	return 0;
}

int nexus_open_netdev(void)
{
	int ret = 0;

	P(&global_netdev_mutex);
	if (global_netdev) {
		global_netdev->open(global_netdev);
		global_netdev = NULL;
	}
	else
		ret = 1;	
	V(&global_netdev_mutex);

	return ret;
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

#define assert_nc() \
	do { \
		printk("%s.%d: not implemented\n", __FUNCTION__, __LINE__); \
		dump_stack_current(NULL); \
		nexuspanic(); \
	} while(0)

void cpu_raise_softirq(unsigned int cpu, unsigned int nr) 
{
	printk("[kdev] softirq: not implemented\n");
}

int del_timer(struct timer_list * timer) {assert_nc(); return 0;}
void add_timer(struct timer_list * timer) { assert_nc(); }

int mod_timer(struct timer_list *timer, unsigned long expires) 
{
	if (check_intr() == 1)
		register_alarm(expires, (void *) timer->function, (void *) timer->data);
	else
		register_alarm_noint(expires, (void *) timer->function, (void *) timer->data);
}

void __netdev_watchdog_up(struct net_device *dev) {assert_nc();}
int		netif_receive_skb(struct sk_buff *skb) {assert_nc(); return 0;}
int schedule_task(void /*struct tq_struct*/ *task) {assert_nc(); return 0;}
struct sk_buff *skb_copy(const struct sk_buff *skb, int priority) {assert_nc(); return NULL;}


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

void skb_over_panic(struct sk_buff *skb, int len, void *here) {printk("DAN: skb_over_panic!!!\n");}
long schedule_timeout(long timeout) { return 0; }

int __generic_copy_from_user(void){assert_nc(); return -1;}
int __generic_copy_to_user(void){assert_nc(); return -1;}

int copy_from_user(void *to, void *from, int len) { memcpy(to, from, len); }
int copy_to_user(void *to, void *from, int len) { memcpy(to, from, len); }


int register_reboot_notifier(void *nb) { return 0; }


