/** NexusOS: one of the Linux device wrapper files. 
    XXX all these drivers/.../compat files need to be cleaned out */
#include <asm/bitops.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <nexus/nexuseth.h>
#include <nexus/devicecompat.h>
#include <nexus/libc-protos.h>
#include <nexus/device.h>

#include <nexus/Mem.interface.h>

#define WARNING_QUEUE_LEN (10000)

// used to open network devices from udriver.c
// XXX remove these ugly global vars and create cleaner interface
struct net_device *_global_netdev = NULL;

extern PCI_InterruptHandlerFunc pci_intr_handler;

////////	standard functions expected by linux netdevice		////////

static int eth_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr=p;
	if (netif_running(dev))
		return -EBUSY;
	memcpy(dev->dev_addr, addr->sa_data,dev->addr_len);
	return 0;
}

static int eth_change_mtu(struct net_device *dev, int new_mtu)
{
        if ((new_mtu < 68) || (new_mtu > 1500))
                return -EINVAL;
        dev->mtu = new_mtu;
        return 0;
}

void ether_setup(struct net_device *dev)
{
	/* Fill in the fields of the device structure with ethernet-generic values.
	   This should be in a common file instead of per-driver.  */
	
	dev->change_mtu		= eth_change_mtu;
	dev->hard_header	= eth_header;
	dev->rebuild_header 	= eth_rebuild_header;
	dev->set_mac_address 	= eth_mac_addr;
	dev->hard_header_cache	= eth_header_cache;
	dev->header_cache_update= eth_header_cache_update;
	dev->hard_header_parse	= eth_header_parse;

	dev->type		= ARPHRD_ETHER;
	dev->hard_header_len 	= ETH_HLEN;
	dev->mtu		= 1500; /* eth_mtu */
	dev->addr_len		= ETH_ALEN;
	dev->tx_queue_len	= 100;	/* Ethernet wants good queues */	
	
	memset(dev->broadcast,0xFF, ETH_ALEN);

	/* New-style flags. */
	dev->flags		= IFF_BROADCAST|IFF_MULTICAST;
}

static struct net_device *alloc_netdev(int sizeof_priv, const char *mask,
				       void (*setup)(struct net_device *))
{
	struct net_device *dev;
	int alloc_size;

	alloc_size = sizeof (*dev) + sizeof_priv + 31;
	dev = (struct net_device *) calloc(1, alloc_size);

	/* ensure 32-byte alignment of the private area */
	if (sizeof_priv)
		dev->priv = (void *) (((unsigned long)(dev + 1) + 31) & ~31);

	setup(dev);
	_global_netdev = dev;
	return dev;
}

struct net_device *alloc_etherdev(const char *dev_name, int sizeof_priv)
{
	return alloc_netdev(sizeof_priv, dev_name, ether_setup);
}

struct tq_struct;
int schedule_task(struct tq_struct *task) {return -1;}
struct softnet_data softnet_data[NR_CPUS];

////////	registration 	////////

int 
register_netdev(struct net_device *dev)
{
	// UGLY HACK: tell netstack to calculate pseudo header, as expected by E1000 
	//            other devices, such as tg3, should have this set to 0
	int calc_pseudo = 1;

	if (nxnet_dev_init(dev->dev_addr, 
			   dev->features & (NETIF_F_IP_CSUM | NETIF_F_HW_CSUM) ? 1 : 0, 
			   calc_pseudo, dev->hard_start_xmit, dev) < 0) {
		printk("[udev] nxnet_dev_init failed\n");
		assert(0);
		return -1;
	}

	return 0;
}

void 
unregister_netdev(struct net_device *dev) 
{
	assert(0);
}

