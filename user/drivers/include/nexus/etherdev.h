// XXX remove at least the DO_DEPRECATED stuff, probably much more

#ifndef _ETHERDEV_H_
#define _ETHERDEV_H_

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

// Compatibility definitions for a backported 2.6 driver to 2.4.31
#include <nexus/device.h>

typedef void irqreturn_t;
#define IRQ_NONE
#define IRQ_HANDLED
#define IRQ_RETVAL(x)

#define netdev_priv(x)          (x)->priv

#define WARN_ON(condition)						\
  do {									\
    if (unlikely((condition)!=0)) {					\
      printk("Badness in %s at %s:%d\n", __FUNCTION__, __FILE__, __LINE__); \
      /* dump_stack(); */						\
    }									\
  } while (0)

#define SET_NETDEV_DEV(net, pdev) do { } while (0)
#define  PCI_CAP_ID_EXP         0x10    /* PCI-EXPRESS */

static inline void free_netdev(struct net_device *dev) {
        free(dev);
}

#define dev_kfree_skb(X) free_skb(X)

static inline void __netif_rx_complete(struct net_device *dev) {}
static inline void netif_poll_disable(struct net_device *dev) {}
static inline void netif_poll_enable(struct net_device *dev) {}
static inline void netif_tx_disable(struct net_device *dev) {}

#define pci_map_single(PDEV,ADDR,LEN,FLAG) nexuscompat_pci_map_single(PDEV,ADDR,LEN,FLAG)


#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(X)

#endif // _ETHERDEV_H_

