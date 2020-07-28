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
#else
#include <nexus/Thread.interface.h>
#include <linux/if_ether.h>
#define skb_allocate(len) 	alloc_skb(len, 0)
#define skb_destroy(skb)	__kfree_skb(skb)
#define PktEther		ethhdr
#define malloc(x)		kmalloc(x, 0)
#define free(x)			kfree(x)
#define assert(x)		do {if (!(x)) {printk("assert in netdev at %d FAILED\n", __LINE__); while(1) {};} } while (0)
int pthread_create(int *thread, void *attr, void *(*start_routine)(void*), void *arg);
#endif

/** Avoid looping external data back out on the network:
    Never tx a packet whose source matches that of the last
    externally received 
 
    XXX: bit hackish. preemption could cause this field
    overwritten before an rx'ed packet is sent back out (unlikely) */
static char nxnet_lastrx_src[6];

struct nxnet_dev {
	int portnum;

	// low-level (linux) device tx function
	void (*llfunc)(struct sk_buff *, void *);
	void *lldev;
};

/** Receive a packet FROM the NIC.
    Will deallocate the skbuff and its data
 
    @return 0 on success, -1 on failure */
int
nxnet_dev_rx(struct sk_buff *skb)
{
	char *pkt;
	int plen;

	// different devices return different skbuffs. ensure consistent view
	plen = skb->len + sizeof(struct PktEther);
	assert(skb->data - skb->mac.raw == sizeof(struct PktEther));

	// paranoid: copy out of skb and destroy that here
	// XXX skip and let skb->data be destroyed by last user in IPC
	pkt = nxcompat_alloc(plen);
	memcpy(pkt, skb->mac.raw, plen);
	skb_destroy(skb);

	memcpy(nxnet_lastrx_src, pkt + 6, 6);

	if (IPC_Send(default_switch_port, pkt, plen))
		printk("failed to send to switch\n");

	return 0;
}

// interrupt context support has no use in userspace
#ifdef __NEXUSKERNEL__

// queue to allow asynchronous rx processing from interrupt context
#define NQ_MAX 10
Sema skb_queue_sema = SEMA_INIT;
struct sk_buff *skb_queue[NQ_MAX];
int skb_queue_off;


/** As nxnet_dev_rx, but may be called from interrupt context

    This supports network devices that do not have a low-priority
    kernel thread themselves (e.g., 3c59x).
 */
int 
nxnet_dev_rx_int(struct sk_buff *skb)
{
	if (skb_queue_off == NQ_MAX) {
		printk("Out of room in %s\n", __FUNCTION__);
		return -1;
	}

	skb_queue[skb_queue_off++] = skb;
	nxnet_pktinfo(skb->mac.raw, 0);

	V_nexus(&skb_queue_sema);
	return 0;
}

/** Helper thread to listen on nxnet_dev_rx_int enqueues */
static int 
nxnet_dev_rxthread(void *unused)
{
	struct sk_buff *skb;
	int intrlevel;

	while (1) {
    		P(&skb_queue_sema);
		
		intrlevel = disable_intr();
		assert(skb_queue_off >= 1);
		skb = skb_queue[--skb_queue_off];
		restore_intr(intrlevel);
	
		nxnet_dev_rx(skb);
	}

	/* not reached */
	return 0;
}

#endif

/** Helper thread to listen on tx requests over IPC */ 
#ifdef __NEXUSKERNEL__
static int 
#else
static void *
#endif
nxnet_dev_txthread(void *_dev)
{
	struct nxnet_dev *dev = _dev;
	struct sk_buff *skb;
	const int mtu = 1514;
	char buf[mtu];
	int len;

	while (1) {
		// receive a packet
		len = IPC_Recv(dev->portnum, buf, mtu);
		if (len <= 0) {
			printk("nic tx failed (%dB)\n", len);
			continue;
		}

		// do not forward packets that came from outside
		if (!memcmp(buf + 6, nxnet_lastrx_src, 6))
			continue;

		// convert into skb (XXX slow, fix to use existing buf)
		skb = skb_allocate(len);
		if (!skb) {
			nxcompat_printf("[net] out of memory\n");
			break;
		}

		skb_put(skb, len);
		memcpy(skb->data, buf, len);

		// call device hard_start_xmit handler
		// linux drivers are responsible for freeing the skb
		dev->llfunc(skb, dev->lldev);
		assert(skb && skb->data);
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
    @return -1 on failure or 
            the portnum on which this device listens for tx requests */
int
nxnet_dev_init(const char *mac, 
	       void (*llfunc)(struct sk_buff *, void *),
	       void *lldev)
{
#ifndef __NEXUSKERNEL__
	int txthread;
#endif
	struct nxnet_dev *dev;

	// create struct
	dev = nxcompat_alloc(sizeof(*dev));
	dev->lldev = lldev;
	dev->llfunc = llfunc;

	// open ipc port to receive tx requests on
	dev->portnum = IPC_CreatePort(NULL);
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
	return dev->portnum;
}

