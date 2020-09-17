#ifndef _DEVICE_H_
#define _DEVICE_H_

struct pci_dev;
struct pci_device_id;
struct pt_regs;
struct sk_buff;
struct net_device;

// Definitions for device drivers
typedef int (*PCI_ProbeFunc)(struct pci_dev *pdev, const struct pci_device_id *ent);
typedef void (*PCI_InterruptHandlerFunc)(int irq, void *data, struct pt_regs *regs);
typedef int (*PCI_TransmitFunc)(struct sk_buff *skb, struct net_device *dev);

unsigned int nexuscompat_pci_map_single(void *arg1, void *arg2, int arg3, int arg4);
void outl_syscall(unsigned int value, unsigned int port);
void free_skb(struct sk_buff * skb);

#endif // _DEVICE_H_
