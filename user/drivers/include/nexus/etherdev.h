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

// struct net_dev *dev
#define netif_rx_schedule(DEV)			\
  do {						\
    int budget = 100000;			\
    (DEV)->quota = budget;			\
    int res;					\
    do {					\
      spin_unlock(&tp->lock);			\
      res = (DEV)->poll(DEV, &budget);		\
      spin_lock(&tp->lock);			\
    } while(res);				\
  } while(0)

#define pci_map_single(PDEV,ADDR,LEN,FLAG) nexuscompat_pci_map_single(PDEV,ADDR,LEN,FLAG)


#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(X)

// This must be defined _after_ io.h

#define inb inb_nexus
#define inw inw_nexus
#define inl inl_nexus
#define insb insb_nexus
#define insw insw_nexus
#define insl insl_nexus

#define outb outb_nexus
#define outw outw_nexus
#define outl outl_nexus
#define outsb outsb_nexus
#define outsw outsw_nexus
#define outsl outsl_nexus

#define inb_p inb_p_nexus
#define inw_p inw_p_nexus
#define inl_p inl_p_nexus

#define outb_p outb_p_nexus
#define outw_p outw_p_nexus
#define outl_p outl_p_nexus

// XXX I cannot find the IO.svc file, so I guess this is deprecated
#ifdef DO_DEPRECATED
#undef __KERNEL__
#include <nexus/IO.interface.h>
#define __KERNEL__

#define ALL_NAME_TYPE_SUFFIX(M)			\
    M(BYTE,unsigned char,b);				\
    M(WORD,unsigned short,w);				\
    M(LONG,unsigned int,l);

#define IN(NAME,TYPE,SUFFIX)				\
  static inline TYPE in##SUFFIX(unsigned short int port) {	\
    TYPE rv;							\
    IO_PIO(port, &rv, PIO_IN, PIO_##NAME, 0, 1);			\
    return rv;							\
  }								\
  static inline TYPE in##SUFFIX##_p(unsigned short int port) {	\
    TYPE rv;								\
    IO_PIO(port, &rv, PIO_IN, PIO_##NAME, 1, 1);			\
    return rv;							\
  }

ALL_NAME_TYPE_SUFFIX(IN);
#undef IN

#define OUT(NAME,TYPE,SUFFIX)				\
  static inline void out##SUFFIX(TYPE value, unsigned short int port) {	\
    IO_PIO(port, &value, PIO_OUT, PIO_##NAME, 0, 1);			\
  }									\
  static inline void out##SUFFIX##_p(TYPE value, unsigned short int port) { \
    IO_PIO(port, &value, PIO_OUT, PIO_##NAME, 1, 1);			\
  }


ALL_NAME_TYPE_SUFFIX(OUT);
#undef OUT

#define INS(NAME,TYPE,SUFFIX)						\
  static inline void ins##SUFFIX(unsigned short int port, void *addr, unsigned long int count) { \
    IO_PIO(port, addr, PIO_IN, PIO_##NAME, 0, count);			\
  }

#define OUTS(NAME,TYPE,SUFFIX)						\
  static inline void outs##SUFFIX(unsigned short int port, const void *addr, unsigned long int count) { \
    IO_PIO(port, (void *)addr, PIO_OUT, PIO_##NAME, 0, count);		\
  }

ALL_NAME_TYPE_SUFFIX(INS);
ALL_NAME_TYPE_SUFFIX(OUTS);
#undef INS
#undef OUTS
#endif /* DO_DEPRECATED */

#endif // _ETHERDEV_H_
