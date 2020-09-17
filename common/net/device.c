/** NexusOS: interface to network devices 
 
    This file has one tricky implementation issue. It is compiled both
    in the kernel and userspace, and needs to know about sk_buff in both.
    This pulls in the entire linux headerfile set, which means we cannot
    use any stdio or many other headers. I've disabled some #includes as
    a result.
    */

#include <linux/skbuff.h>

#include <nexus/defs.h>
#include <nexus/syscall-defs.h>

// see explanation at top of file.
//#include <nexus/IPC.interface.h>
//#include <nexus/Net.interface.h>

#ifdef __NEXUSKERNEL__
#include <nexus/machineprimitives.h>
#include <nexus/user_compat.h>
#include <nexus/synch-inline.h>
#include <nexus/ipc.h>
#include <nexus/net.h>
#include <nexus/queue.h>
#include <nexus/thread.h>
#else
#include <nexus/syscalls.h>
#include <nexus/Thread.interface.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#define PktEther		ethhdr
#define malloc(x)		kmalloc(x, 0)
#define free(x)			kfree(x)
#define assert(x)		do {if (!(x)) {printk("assert in netdev at %d FAILED\n", __LINE__); while(1) {};} } while (0)
int pthread_create(int *thread, void *attr, void *(*start_routine)(void*), void *arg);
#endif

int nxnet_checksum_generate(char *frame);
int nxnet_checksum_verify(char *frame);
int nxnet_checksum_prepare(char *frame, int do_pseudo);

/** Avoid looping external data back out on the network:
    Never tx a packet whose source matches that of the last
    externally received 
 
    probably no longer needed, was used during switch debugging

    XXX: bit hackish. preemption could cause this field
    overwritten before a received packet is sent back out (unlikely) */
static char nxnet_lastrx_src[6];

struct nxnet_dev {
	int portnum;
	int hw_checksum;
	int hw_pseudo;

	// low-level (linux) device tx function
	int (*llfunc)(struct sk_buff *, void *);
	void *lldev;
};

/** Reply inline in the driver: benchmark upper bound on throughput */
//#define BENCH_QUICKREPLY
#if !NXCONFIG_DEVICE_BLIND
#ifdef BENCH_QUICKREPLY
struct nxnet_dev *HACKDEV;
#include "echo.c"

static int nxnet_quickreply(struct sk_buff *skb, char *page)
{
	// reverse and reply as soon as possible to calculate max rate
	if (nxnet_echoreply(page)) {
		nxnet_page_setlen(page, skb->len);
#ifdef __NEXUSKERNEL__
		skb = nxnet_init_skb(page, fast_virtToPhys(curr_map, (unsigned long) page, 0, 0));
#else
		skb = nxnet_init_skb(page, Mem_GetPhysicalAddress(page, PAGE_SIZE));
#endif
		skb->len = nxnet_page_getlen(page);
		skb->ip_summed = CHECKSUM_HW;
		nxnet_checksum_prepare(page, HACKDEV->hw_pseudo);
		HACKDEV->llfunc(skb, HACKDEV->lldev);
		return 0;
	}
}
#endif
#endif

/** Receive a packet FROM the NIC.
    Will deallocate the skbuff and its data
 
    @return 0 on success, -1 on failure */
int
nxnet_dev_rx(struct sk_buff *skb)
{
	char *page = skb->mac.raw;

	// only accept full pages that start with an ethernet header
	if (((unsigned long) page) & (PAGE_SIZE - 1)) {
		printk("[device] driver data is not page aligned\n");
		return 1;
	}

// disabled because NEXUS_E1000_BLIND cannot set skb->ip_summed
// NB: pcnet32 does not offload hardware: no rx checksum is calculated!
#if !NXCONFIG_DEVICE_BLIND
	// checksum
	if (skb->ip_summed != CHECKSUM_UNNECESSARY && 
	    skb->ip_summed != CHECKSUM_HW) {
		if (nxnet_checksum_verify(page)) {
			// NB: if off by 1 byte: 
			// probably a bug in carry-bit accounting
			printk_red("[net] NXDEBUG: rx checksum failed\n");
			return 1;
		}
	}
#endif

#ifdef BENCH_QUICKREPLY
	return nxnet_quickreply(skb, page);
#endif

// leave: useful for debugging network path
#if 0 && defined __NEXUSKERNEL__
	nxnet_pktinfo(page, 2);
#endif

	// send to vswitch
#if !NXCONFIG_DEVICE_BLIND
	nxnet_page_setlen(page, skb->len);
#endif
#ifdef __NEXUSKERNEL__
	nxnet_switch_tx(page, skb->len);
#else
	Net_vrouter_to((unsigned long) page, skb->len);
#endif

#if NXCONFIG_DEVICE_BLIND
	nxcompat_free(skb);
#endif
	return 0;
}

// interrupt context support has no use in userspace
#ifdef __NEXUSKERNEL__

// queue to allow asynchronous rx processing from interrupt context
#define NQ_MAX 64
Sema skb_queue_sema = SEMA_INIT_KILLABLE;
struct sk_buff *skb_queue[NQ_MAX];
int skb_queue_off;


/** As nxnet_dev_rx, but may be called from interrupt context

    This supports network devices that do not have a low-priority
    kernel thread themselves (e.g., pcnet32, 3c59x).
 */
int 
nxnet_dev_rx_int(struct sk_buff *skb)
{
	// overload? clean complete buffer
	if (skb_queue_off == NQ_MAX) {
		skb_queue_off = 1;
		printk("[net] overflow. dropped %d packets\n", NQ_MAX);
	}
	else {
		skb_queue[skb_queue_off++] = skb;
		V_nexus(&skb_queue_sema);
	}

	return 0;
}

/** Helper thread to listen on nxnet_dev_rx_int enqueues */
static int 
nxnet_dev_rxthread(void *unused)
{
	extern void prealloc_skb_int(void);
	struct sk_buff *skb;
	int intrlevel;

	nexusthread_setname("net.rx");

	while (1) {
		prealloc_skb_int();
    		P(&skb_queue_sema);
		
		intrlevel = disable_intr();
		// after ring clean (overflow), this can happen
		if (!skb_queue_off) {
			restore_intr(intrlevel);
			continue;
		}
		skb = skb_queue[--skb_queue_off];
		restore_intr(intrlevel);
	
		nxnet_dev_rx(skb);
	}

	/* not reached */
	return 0;
}

#endif

static inline void
nxnet_dev_tx(void *_dev, void *page, unsigned long paddr, int proto, int len)
{
	struct nxnet_dev *dev = _dev;
	struct sk_buff *skb;
	
#if !NXCONFIG_DEVICE_BLIND
	// do not forward packets that came from outside
	if (unlikely(!memcmp(page + 6, nxnet_lastrx_src, 6)))
		return;
#endif

	// page holds skb. update data pointers
	skb = nxnet_init_skb(page, paddr);
	skb->protocol = proto;
#if NXCONFIG_DEVICE_BLIND
	skb->len = len;
#endif

	// checksum
	if (!dev->hw_checksum) {
		skb->ip_summed = CHECKSUM_NONE;
		nxnet_checksum_generate(page);
	}
	else {
		skb->ip_summed = CHECKSUM_HW;
#if !NXCONFIG_DEVICE_BLIND
		// blind device have checksums prepared in kernel
		nxnet_checksum_prepare(page, dev->hw_pseudo);
#endif
	}

// leave: useful for debugging network path
#if 0 && defined __NEXUSKERNEL__
		nxnet_pktinfo(page, 1);
#endif
	// call device hard_start_xmit handler
	// linux drivers are responsible for freeing the skb
	dev->llfunc(skb, dev->lldev);
}

/** Helper thread to listen on tx requests over IPC */ 
#ifdef __NEXUSKERNEL__
static int 
#else
static void *
#endif
nxnet_dev_txthread(void *_dev)
{
	struct nxnet_dev *dev = _dev;
	unsigned long paddr;
	const int mtu = 1514;
	char buf[mtu], *page;
	int len, proto;

#ifdef __NEXUSKERNEL__
	nexusthread_setname("net.tx");
#else
	Thread_SetName("net.tx");
#endif

	while (1) {
#ifdef __NEXUSKERNEL__
		len = nxnet_vrouter_from(dev->portnum, &page, 
				         (char **) &paddr, &proto);
#else
		len = Net_vrouter_from_blind(dev->portnum, (unsigned long) &page, 
				            (unsigned long) &paddr, &proto, 
					    dev->hw_pseudo);
#endif
		if (len <= 0) {
			printk("[dev] tx failed\n");
			continue;
		}
		nxnet_dev_tx(dev, page, paddr, proto, len);
	}

	// XXX tell switch we've gone
	nxcompat_free(dev);

#ifdef __NEXUSKERNEL__
	return 0;
#else
	return NULL;
#endif
}

/** Initialize a network device 
    @param mac is a 6byte mac address
    @param hw_calc_pseudo decides whether the device driver will place the TCP/UDP
           pseudo header in the TCP/UDP checksum field of tx packets. Some drivers
	   require that (e1000), others do not (tg3).
    @return -1 on failure or 
            the portnum on which this device listens for tx requests */
int
nxnet_dev_init(const char *mac, 
	       int hw_checksum, int hw_calc_pseudo,
	       int (*llfunc)(struct sk_buff *, void *),
	       void *lldev)
{
#ifndef __NEXUSKERNEL__
	int txthread;
#endif
	struct nxnet_dev *dev;

	// create struct
	dev = nxcompat_alloc(sizeof(*dev));
	dev->hw_checksum = hw_checksum;
	dev->hw_pseudo = hw_calc_pseudo;
	dev->lldev = lldev;
	dev->llfunc = llfunc;

#ifdef BENCH_QUICKREPLY
HACKDEV = dev;
#endif

	// open ipc port to receive tx requests on
	dev->portnum = IPC_CreatePort(0);
	if (dev->portnum == -1)
		return -1;

	// tell switch we're here
#ifdef __NEXUSKERNEL__
	nxnet_switch_add(mac, dev->portnum);
#else
	Net_add_mac(mac, dev->portnum);
#endif

	// start listeners
#ifdef __NEXUSKERNEL__
	nexusthread_fork(nxnet_dev_rxthread, NULL);
	nexusthread_fork(nxnet_dev_txthread, dev);
#else
	pthread_create(&txthread, NULL, nxnet_dev_txthread, dev);
#endif
	nxcompat_printf("[netdrv] device listening on port %d\n"
			"checksum offload %sabled\n%s", 
			dev->portnum, 
			hw_checksum ? "en" : "dis",
			hw_checksum && hw_calc_pseudo ? "pseudoheader calculation enabled\n" : "");
	return dev->portnum;
}

