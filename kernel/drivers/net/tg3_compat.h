/* Copyright (C) 2008-2010 Broadcom Corporation. */

#include "tg3_flags.h"

#ifndef NONEXUS
#define OLD_NETIF
#define PCI_COMMAND_INTX_DISABLE 0x400	/* INTx Emulation Disable */
#endif

#if !defined(__maybe_unused)
#define __maybe_unused  /* unimplemented */
#endif

#if !defined(__iomem)
#define __iomem
#endif

#ifndef __acquires
#define __acquires(x)
#endif

#ifndef __releases
#define __releases(x)
#endif

#ifndef mmiowb
#define mmiowb()
#endif

#ifndef WARN_ON
#define WARN_ON(x)
#endif

#ifndef MODULE_VERSION
#define MODULE_VERSION(version)
#endif

#ifndef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev) do { } while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef BCM_HAS_BOOL
typedef int bool;
#define false 0
#define true  1
#endif

#ifndef BCM_HAS_LE32
typedef u32 __le32;
typedef u32 __be32;
#endif

#ifndef BCM_HAS_RESOURCE_SIZE_T
typedef unsigned long resource_size_t;
#endif

#ifndef IRQ_RETVAL
typedef void irqreturn_t;
#define IRQ_RETVAL(x)
#define IRQ_HANDLED
#define IRQ_NONE
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef IRQF_SAMPLE_RANDOM
#define IRQF_SAMPLE_RANDOM SA_SAMPLE_RANDOM
#endif

#if (LINUX_VERSION_CODE <= 0x020600)
#define schedule_work(x)	schedule_task(x)
#define work_struct		tq_struct
#define INIT_WORK(x, y, z)	INIT_TQUEUE(x, y, z)
#endif

#ifndef BCM_HAS_KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void * memptr = kmalloc(size, flags);
	if (memptr)
		memset(memptr, 0, size);

	return memptr;
}
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC			1000000
#endif

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC			1000
#endif

#ifndef MAX_JIFFY_OFFSET
#define MAX_JIFFY_OFFSET		((LONG_MAX >> 1)-1)
#endif

#ifndef BCM_HAS_JIFFIES_TO_USECS
static unsigned int inline jiffies_to_usecs(const unsigned long j)
{
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (USEC_PER_SEC / HZ) * j;
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return (j + (HZ / USEC_PER_SEC) - 1)/(HZ / USEC_PER_SEC);
#else
	return (j * USEC_PER_SEC) / HZ;
#endif
}
#endif /* BCM_HAS_JIFFIES_TO_USECS */

#ifndef BCM_HAS_USECS_TO_JIFFIES
static unsigned long usecs_to_jiffies(const unsigned int u)
{
	if (u > jiffies_to_usecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= USEC_PER_SEC && !(USEC_PER_SEC % HZ)
	return (u + (USEC_PER_SEC / HZ) - 1) / (USEC_PER_SEC / HZ);
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
	return u * (HZ / USEC_PER_SEC);
#else
	return (u * HZ + USEC_PER_SEC - 1) / USEC_PER_SEC;
#endif
}
#endif /* BCM_HAS_USECS_TO_JIFFIES */

#ifndef BCM_HAS_MSECS_TO_JIFFIES
static unsigned long msecs_to_jiffies(const unsigned int m)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	/*
	 * HZ is equal to or smaller than 1000, and 1000 is a nice
	 * round multiple of HZ, divide with the factor between them,
	 * but round upwards:
	 */
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	/*
	 * HZ is larger than 1000, and HZ is a nice round multiple of
	 * 1000 - simply multiply with the factor between them.
	 *
	 * But first make sure the multiplication result cannot
	 * overflow:
	 */
	if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return m * (HZ / MSEC_PER_SEC);
#else
	/*
	 * Generic case - multiply, round and divide. But first
	 * check that if we are doing a net multiplication, that
	 * we wouldn't overflow:
	 */
	if (HZ > MSEC_PER_SEC && m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}
#endif /* BCM_HAS_MSECS_TO_JIFFIES */

#ifndef BCM_HAS_MSLEEP
static void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
}
#endif /* BCM_HAS_MSLEEP */

#ifndef BCM_HAS_MSLEEP_INTERRUPTIBLE
static unsigned long msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}

	return 0;
}
#endif /* BCM_HAS_MSLEEP_INTERRUPTIBLE */

#ifndef BCM_HAS_PCI_IOREMAP_BAR
static inline void * pci_ioremap_bar(struct pci_dev *pdev, int bar)
{
	resource_size_t base, size;

	if (!(pci_resource_flags(pdev, bar) & IORESOURCE_MEM)) {
		printk(KERN_ERR
		       "Cannot find proper PCI device base address for BAR %d.\n",
		       bar);
		return NULL;
	}

	base = pci_resource_start(pdev, bar);
	size = pci_resource_len(pdev, bar);

	return ioremap_nocache(base, size);
}
#endif

#if (LINUX_VERSION_CODE < 0x020547)
#define pci_set_consistent_dma_mask(pdev, mask) (0)
#endif

#if (LINUX_VERSION_CODE < 0x020600)
#define pci_get_device(x, y, z)	pci_find_device(x, y, z)
#define pci_get_slot(x, y)	pci_find_slot((x)->number, y)
#define pci_dev_put(x)
#endif

#if (LINUX_VERSION_CODE < 0x020605)
#define pci_dma_sync_single_for_cpu(pdev, map, len, dir)	\
        pci_dma_sync_single(pdev, map, len, dir)
#define pci_dma_sync_single_for_device(pdev, map, len, dir)
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5704S_2
#define PCI_DEVICE_ID_TIGON3_5704S_2	0x1649
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5705F
#define PCI_DEVICE_ID_TIGON3_5705F	0x166e
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5720
#define PCI_DEVICE_ID_TIGON3_5720	0x1658
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5721
#define PCI_DEVICE_ID_TIGON3_5721	0x1659
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5750
#define PCI_DEVICE_ID_TIGON3_5750	0x1676
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751
#define PCI_DEVICE_ID_TIGON3_5751	0x1677
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5750M
#define PCI_DEVICE_ID_TIGON3_5750M	0x167c
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751M
#define PCI_DEVICE_ID_TIGON3_5751M	0x167d
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5751F
#define PCI_DEVICE_ID_TIGON3_5751F	0x167e
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5789
#define PCI_DEVICE_ID_TIGON3_5789	0x169d
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753
#define PCI_DEVICE_ID_TIGON3_5753	0x16f7
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753M
#define PCI_DEVICE_ID_TIGON3_5753M	0x16fd
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5753F
#define PCI_DEVICE_ID_TIGON3_5753F	0x16fe
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5781
#define PCI_DEVICE_ID_TIGON3_5781	0x16dd
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5752
#define PCI_DEVICE_ID_TIGON3_5752	0x1600
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5752M
#define PCI_DEVICE_ID_TIGON3_5752M	0x1601
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5714
#define PCI_DEVICE_ID_TIGON3_5714	0x1668
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5714S
#define PCI_DEVICE_ID_TIGON3_5714S	0x1669
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5780
#define PCI_DEVICE_ID_TIGON3_5780	0x166a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5780S
#define PCI_DEVICE_ID_TIGON3_5780S	0x166b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5715
#define PCI_DEVICE_ID_TIGON3_5715	0x1678
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5715S
#define PCI_DEVICE_ID_TIGON3_5715S	0x1679
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5756
#define PCI_DEVICE_ID_TIGON3_5756	0x1674
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5754
#define PCI_DEVICE_ID_TIGON3_5754	0x167a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5754M
#define PCI_DEVICE_ID_TIGON3_5754M	0x1672
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5755
#define PCI_DEVICE_ID_TIGON3_5755	0x167b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5755M
#define PCI_DEVICE_ID_TIGON3_5755M	0x1673
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5722
#define PCI_DEVICE_ID_TIGON3_5722	0x165a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5786
#define PCI_DEVICE_ID_TIGON3_5786	0x169a
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787M
#define PCI_DEVICE_ID_TIGON3_5787M	0x1693
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787
#define PCI_DEVICE_ID_TIGON3_5787	0x169b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5787F
#define PCI_DEVICE_ID_TIGON3_5787F	0x167f
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5906
#define PCI_DEVICE_ID_TIGON3_5906	0x1712
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5906M
#define PCI_DEVICE_ID_TIGON3_5906M	0x1713
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5784
#define PCI_DEVICE_ID_TIGON3_5784	0x1698
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5764
#define PCI_DEVICE_ID_TIGON3_5764	0x1684
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5723
#define PCI_DEVICE_ID_TIGON3_5723	0x165b
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5761
#define PCI_DEVICE_ID_TIGON3_5761	0x1681
#endif

#ifndef PCI_DEVICE_ID_TIGON3_5761E
#define PCI_DEVICE_ID_TIGON3_5761E	0x1680
#endif

#ifndef PCI_DEVICE_ID_APPLE_TIGON3
#define PCI_DEVICE_ID_APPLE_TIGON3	0x1645
#endif

#ifndef PCI_DEVICE_ID_APPLE_UNI_N_PCI15
#define PCI_DEVICE_ID_APPLE_UNI_N_PCI15	0x002e
#endif

#ifndef PCI_DEVICE_ID_VIA_8385_0
#define PCI_DEVICE_ID_VIA_8385_0	0x3188
#endif

#ifndef PCI_DEVICE_ID_AMD_8131_BRIDGE
#define PCI_DEVICE_ID_AMD_8131_BRIDGE	0x7450
#endif

#ifndef PCI_DEVICE_ID_SERVERWORKS_EPB
#define PCI_DEVICE_ID_SERVERWORKS_EPB	0x0103
#endif

#ifndef PCI_VENDOR_ID_ARIMA
#define PCI_VENDOR_ID_ARIMA		0x161f
#endif

#ifndef PCI_DEVICE_ID_INTEL_PXH_0
#define PCI_DEVICE_ID_INTEL_PXH_0	0x0329
#endif

#ifndef PCI_DEVICE_ID_INTEL_PXH_1
#define PCI_DEVICE_ID_INTEL_PXH_1	0x032A
#endif

#ifndef PCI_D0
typedef u32 pm_message_t;
typedef u32 pci_power_t;
#define PCI_D0		0
#define PCI_D1		1
#define PCI_D2		2
#define PCI_D3hot	3
#endif

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK ((u64) 0xffffffffffffffffULL)
#endif

#ifndef DMA_40BIT_MASK
#define DMA_40BIT_MASK ((u64) 0x000000ffffffffffULL)
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK ((u64) 0x00000000ffffffffULL)
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)  DMA_ ##n ##BIT_MASK
#endif

#if !defined(BCM_HAS_PCI_TARGET_STATE) && !defined(BCM_HAS_PCI_CHOOSE_STATE)
static inline pci_power_t pci_choose_state(struct pci_dev *dev,
					   pm_message_t state)
{
	return state;
}
#endif

#ifndef BCM_HAS_PCI_PME_CAPABLE
static bool pci_pme_capable(struct pci_dev *dev, pci_power_t state)
{
	int pm_cap;
	u16 caps;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		return false;

	pci_read_config_word(dev, pm_cap + PCI_PM_PMC, &caps);

	if (caps & PCI_PM_CAP_PME_D3cold)
		return true;

	return false;
}
#endif /* BCM_HAS_PCI_PME_CAPABLE */

#ifndef BCM_HAS_PCI_ENABLE_WAKE
static int pci_enable_wake(struct pci_dev *dev, pci_power_t state, int enable)
{
	int pm_cap;
	u16 pmcsr;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		return -EIO;

	pci_read_config_word(dev, pm_cap + PCI_PM_CTRL, &pmcsr);

	/* Clear PME_Status by writing 1 to it */
	pmcsr |= PCI_PM_CTRL_PME_STATUS;

	if (enable)
		pmcsr |= PCI_PM_CTRL_PME_ENABLE;
	else
		pmcsr &= ~PCI_PM_CTRL_PME_ENABLE;

	pci_write_config_word(dev, pm_cap + PCI_PM_CTRL, pmcsr);

	return 0;
}
#endif /* BCM_HAS_PCI_ENABLE_WAKE */

#ifndef BCM_HAS_PCI_SET_POWER_STATE
static int pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
	int pm_cap;
	u16 pmcsr;

	if (state < PCI_D0 || state > PCI_D3hot)
		return -EINVAL;

	pm_cap = pci_find_capability(dev, PCI_CAP_ID_PM);
	if (pm_cap == 0)
		return -EIO;

	pci_read_config_word(dev, pm_cap + PCI_PM_CTRL, &pmcsr);

	pmcsr &= ~(PCI_PM_CTRL_STATE_MASK);
	pmcsr |= state;

	pci_write_config_word(dev, pm_cap + PCI_PM_CTRL, pmcsr);

	msleep(10);

	return 0;
}
#endif /* BCM_HAS_PCI_SET_POWER_STATE */

#ifndef BCM_HAS_DEVICE_WAKEUP_API
#define device_init_wakeup(dev, val)
#define device_can_wakeup(dev) 1
#define device_set_wakeup_enable(dev, val)
#define device_may_wakeup(dev) 1
#endif /* BCM_HAS_DEVICE_WAKEUP_API */


#ifndef PCI_X_CMD_READ_2K
#define  PCI_X_CMD_READ_2K		0x0008
#endif
#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif
#ifndef PCI_EXP_LNKCTL
#define PCI_EXP_LNKCTL 16
#endif
#ifndef PCI_EXP_LNKCTL_CLKREQ_EN
#define PCI_EXP_LNKCTL_CLKREQ_EN 0x100
#endif

#ifndef PCI_EXP_DEVCTL_NOSNOOP_EN
#define PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800
#endif

#ifndef PCI_EXP_DEVCTL_RELAX_EN
#define PCI_EXP_DEVCTL_RELAX_EN		0x0010
#endif

#ifndef PCI_EXP_DEVCTL_PAYLOAD
#define PCI_EXP_DEVCTL_PAYLOAD		0x00e0
#endif

#ifndef PCI_EXP_DEVSTA
#define PCI_EXP_DEVSTA          10
#define  PCI_EXP_DEVSTA_CED     0x01
#define  PCI_EXP_DEVSTA_NFED    0x02
#define  PCI_EXP_DEVSTA_FED     0x04
#define  PCI_EXP_DEVSTA_URD     0x08
#endif

#ifndef BCM_HAS_PCIE_SET_READRQ
#ifndef PCI_EXP_DEVCTL
#define PCI_EXP_DEVCTL		8
#endif
#ifndef PCI_EXP_DEVCTL_READRQ
#define PCI_EXP_DEVCTL_READRQ	0x7000
#endif
static inline int pcie_set_readrq(struct pci_dev *dev, int rq)
{
	int cap, err = -EINVAL;
	u16 ctl, v;

	if (rq < 128 || rq > 4096 || (rq & (rq-1)))
		goto out;

	v = (ffs(rq) - 8) << 12;

	cap = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap)
		goto out;

	err = pci_read_config_word(dev, cap + PCI_EXP_DEVCTL, &ctl);
	if (err)
		goto out;

	if ((ctl & PCI_EXP_DEVCTL_READRQ) != v) {
		ctl &= ~PCI_EXP_DEVCTL_READRQ;
		ctl |= v;
		err = pci_write_config_dword(dev, cap + PCI_EXP_DEVCTL, ctl);
	}

out:
	return err;
}
#endif /* BCM_HAS_PCIE_SET_READRQ */

#ifndef BCM_HAS_PCI_READ_VPD
#if !defined(PCI_CAP_ID_VPD)
#define  PCI_CAP_ID_VPD		0x03
#endif
#if !defined(PCI_VPD_ADDR)
#define PCI_VPD_ADDR		2
#endif
#if !defined(PCI_VPD_DATA)
#define PCI_VPD_DATA		4
#endif
static inline ssize_t
pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, u8 *buf)
{
	int i, vpd_cap;

	vpd_cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
	if (!vpd_cap)
		return -ENODEV;

	for (i = 0; i < count; i += 4) {
		u32 tmp, j = 0;
		__le32 v;
		u16 tmp16;

		pci_write_config_word(dev, vpd_cap + PCI_VPD_ADDR, i);
		while (j++ < 100) {
			pci_read_config_word(dev, vpd_cap +
					     PCI_VPD_ADDR, &tmp16);
			if (tmp16 & 0x8000)
				break;
			msleep(1);
		}
		if (!(tmp16 & 0x8000))
			break;

		pci_read_config_dword(dev, vpd_cap + PCI_VPD_DATA, &tmp);
		v = cpu_to_le32(tmp);
		memcpy(&buf[i], &v, sizeof(v));
	}

	return i;
}
#endif /* BCM_HAS_PCI_READ_VPD */

#ifndef BCM_HAS_INTX_MSI_WORKAROUND
static inline void tg3_enable_intx(struct pci_dev *pdev)
{
#if (LINUX_VERSION_CODE < 0x2060e)
	u16 pci_command;

	pci_read_config_word(pdev, PCI_COMMAND, &pci_command);
	if (pci_command & PCI_COMMAND_INTX_DISABLE)
		pci_write_config_word(pdev, PCI_COMMAND,
				      pci_command & ~PCI_COMMAND_INTX_DISABLE);
#else
	pci_intx(pdev, 1);
#endif
}
#endif /* BCM_HAS_INTX_MSI_WORKAROUND */


#if (LINUX_VERSION_CODE >= 0x20613) || \
    (defined(VMWARE_ESX_40_DDK) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))
#define BCM_HAS_NEW_IRQ_SIG
#endif

#if defined(INIT_DELAYED_WORK_DEFERRABLE) || \
    defined(INIT_WORK_NAR) || \
    (defined(VMWARE_ESX_40_DDK) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))
#define BCM_HAS_NEW_INIT_WORK
#endif

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN 4
#endif

#ifndef BCM_HAS_PRINT_MAC

#ifndef DECLARE_MAC_BUF
#define DECLARE_MAC_BUF(_mac) char _mac[18]
#endif

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

static char *print_mac(char * buf, const u8 *addr)
{
	sprintf(buf, MAC_FMT,
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}
#endif


#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN 2
#endif


#if !defined(BCM_HAS_ETHTOOL_OP_SET_TX_IPV6_CSUM) && \
    !defined(BCM_HAS_ETHTOOL_OP_SET_TX_HW_CSUM)   && \
     defined(BCM_HAS_SET_TX_CSUM)
static int tg3_set_tx_hw_csum(struct net_device *dev, u32 data)
{
	if (data)
		dev->features |= NETIF_F_HW_CSUM;
	else
		dev->features &= ~NETIF_F_HW_CSUM;

	return 0;
}
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

#ifndef NETDEV_TX_LOCKED
#define NETDEV_TX_LOCKED -1
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef NETIF_F_IPV6_CSUM
#define NETIF_F_IPV6_CSUM 16
#define BCM_NO_IPV6_CSUM  1
#endif

#ifdef NETIF_F_TSO
#ifndef NETIF_F_GSO
#define gso_size tso_size
#define gso_segs tso_segs
#endif
#ifndef NETIF_F_TSO6
#define NETIF_F_TSO6	0
#define BCM_NO_TSO6     1
#endif
#ifndef NETIF_F_TSO_ECN
#define NETIF_F_TSO_ECN 0
#endif

#if (LINUX_VERSION_CODE < 0x2060c)
static inline int skb_header_cloned(struct sk_buff *skb) { return 0; }
#endif

#ifndef BCM_HAS_SKB_TRANSPORT_OFFSET
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return (int) (skb->h.raw - skb->data);
}
#endif

#ifndef BCM_HAS_IP_HDR
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return skb->nh.iph;
}
#endif

#ifndef BCM_HAS_IP_HDRLEN
static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}
#endif

#ifndef BCM_HAS_TCP_HDR
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif

#ifndef BCM_HAS_TCP_OPTLEN
static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}
#endif

#ifndef NETIF_F_GSO
static struct sk_buff *skb_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	unsigned int doffset = skb->data - skb->mac.raw;
	unsigned int offset = doffset;
	unsigned int headroom;
	unsigned int len;
	int nfrags = skb_shinfo(skb)->nr_frags;
	int err = -ENOMEM;
	int i = 0;
	int pos;

	__skb_push(skb, doffset);
	headroom = skb_headroom(skb);
	pos = skb_headlen(skb);

	do {
		struct sk_buff *nskb;
		skb_frag_t *frag;
		int hsize;
		int k;
		int size;

		len = skb->len - offset;
		if (len > mss)
			len = mss;

		hsize = skb_headlen(skb) - offset;
		if (hsize < 0)
			hsize = 0;
		if (hsize > len)
			hsize = len;

		nskb = alloc_skb(hsize + doffset + headroom, GFP_ATOMIC);
		if (unlikely(!nskb))
			goto err;

		if (segs)
			tail->next = nskb;
		else
			segs = nskb;
		tail = nskb;

		nskb->dev = skb->dev;
		nskb->priority = skb->priority;
		nskb->protocol = skb->protocol;
		nskb->dst = dst_clone(skb->dst);
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
		nskb->pkt_type = skb->pkt_type;
		nskb->mac_len = skb->mac_len;

		skb_reserve(nskb, headroom);
		nskb->mac.raw = nskb->data;
		nskb->nh.raw = nskb->data + skb->mac_len;
		nskb->h.raw = nskb->nh.raw + (skb->h.raw - skb->nh.raw);
		memcpy(skb_put(nskb, doffset), skb->data, doffset);

		frag = skb_shinfo(nskb)->frags;
		k = 0;

		nskb->ip_summed = CHECKSUM_PARTIAL;
		nskb->csum = skb->csum;
		memcpy(skb_put(nskb, hsize), skb->data + offset, hsize);

		while (pos < offset + len) {
			BUG_ON(i >= nfrags);

			*frag = skb_shinfo(skb)->frags[i];
			get_page(frag->page);
			size = frag->size;

			if (pos < offset) {
				frag->page_offset += offset - pos;
				frag->size -= offset - pos;
			}

			k++;

			if (pos + size <= offset + len) {
				i++;
				pos += size;
			} else {
				frag->size -= pos + size - (offset + len);
				break;
			}

			frag++;
		}

		skb_shinfo(nskb)->nr_frags = k;
		nskb->data_len = len - hsize;
		nskb->len += nskb->data_len;
		nskb->truesize += nskb->data_len;
	} while ((offset += len) < skb->len);

	return segs;

err:
	while ((skb = segs)) {
		segs = skb->next;
		kfree(skb);
	}
	return ERR_PTR(err);
}

static struct sk_buff *tcp_tso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct tcphdr *th;
	unsigned thlen;
	unsigned int seq;
	u32 delta;
	unsigned int oldlen;
	unsigned int len;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = skb->h.th;
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	len = skb_shinfo(skb)->gso_size;
	delta = htonl(oldlen + (thlen + len));

	skb = segs;
	th = skb->h.th;
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((u32)((u32)th->check +
				       (u32)delta));
		seq += len;
		skb = skb->next;
		th = skb->h.th;

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->h.raw) + skb->data_len);
	th->check = ~csum_fold((u32)((u32)th->check +
				(u32)delta));
out:
	return segs;
}

static struct sk_buff *inet_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct iphdr *iph;
	int ihl;
	int id;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	iph = skb->nh.iph;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	skb->h.raw = __skb_pull(skb, ihl);
	iph = skb->nh.iph;
	id = ntohs(iph->id);
	segs = ERR_PTR(-EPROTONOSUPPORT);

	segs = tcp_tso_segment(skb, features);

	if (!segs || IS_ERR(segs))
		goto out;

	skb = segs;
	do {
		iph = skb->nh.iph;
		iph->id = htons(id++);
		iph->tot_len = htons(skb->len - skb->mac_len);
		iph->check = 0;
		iph->check = ip_fast_csum(skb->nh.raw, iph->ihl);
	} while ((skb = skb->next));

out:
	return segs;
}

static struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EPROTONOSUPPORT);

	skb->mac.raw = skb->data;
	skb->mac_len = skb->nh.raw - skb->data;
	__skb_pull(skb, skb->mac_len);

	segs = inet_gso_segment(skb, features);

	__skb_push(skb, skb->data - skb->mac.raw);
	return segs;
}
#endif /* NETIF_F_GSO */

#endif /* NETIF_F_TSO */

#ifndef BCM_HAS_SKB_GET_QUEUE_MAPPING
#define skb_get_queue_mapping(skb)		0
#endif

#ifndef BCM_HAS_SKB_COPY_FROM_LINEAR_DATA
static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
}
#endif

#ifndef BCM_HAS_NETDEV_TX_T
typedef int	netdev_tx_t;
#endif

#ifndef BCM_HAS_NETIF_TX_LOCK
static inline void netif_tx_lock(struct net_device *dev)
{
	spin_lock(&dev->xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock(&dev->xmit_lock);
}
#endif /* BCM_HAS_NETIF_TX_LOCK */

//#if defined(BCM_HAS_STRUCT_NETDEV_QUEUE) || \
//    (defined(VMWARE_ESX_40_DDK) && defined(__USE_COMPAT_LAYER_2_6_18_PLUS__))
#if 0

#define TG3_NAPI
#define tg3_netif_rx_complete(dev, napi)	napi_complete((napi))
#define tg3_netif_rx_schedule(dev, napi)	napi_schedule((napi))
#define tg3_netif_rx_schedule_prep(dev, napi)	napi_schedule_prep((napi))

#else  /* BCM_HAS_STRUCT_NETDEV_QUEUE */

#define netdev_queue	net_device
#define netdev_get_tx_queue(dev, i)		(dev)
#define netif_tx_start_queue(dev)		netif_start_queue((dev))
#define netif_tx_start_all_queues(dev)		netif_start_queue((dev))
#define netif_tx_stop_queue(dev)		netif_stop_queue((dev))
#define netif_tx_stop_all_queues(dev)		netif_stop_queue((dev))
#define netif_tx_queue_stopped(dev)		netif_queue_stopped((dev))
#define netif_tx_wake_queue(dev)		netif_wake_queue((dev))
#define netif_tx_wake_all_queues(dev)		netif_wake_queue((dev))
#define __netif_tx_lock(txq, procid)		netif_tx_lock((txq))
#define __netif_tx_unlock(txq)			netif_tx_unlock((txq))

#if defined(BCM_HAS_NEW_NETIF_INTERFACE)
#define TG3_NAPI
#define tg3_netif_rx_complete(dev, napi)	netif_rx_complete((dev), (napi))
#define tg3_netif_rx_schedule(dev, napi)	netif_rx_schedule((dev), (napi))
#define tg3_netif_rx_schedule_prep(dev, napi)	netif_rx_schedule_prep((dev), (napi))
#else  /* BCM_HAS_NEW_NETIF_INTERFACE */
#define tg3_netif_rx_complete(dev, napi)	netif_rx_complete((dev))
#define tg3_netif_rx_schedule(dev, napi)	netif_rx_schedule((dev))
#define tg3_netif_rx_schedule_prep(dev, napi)	netif_rx_schedule_prep((dev))
#endif /* BCM_HAS_NEW_NETIF_INTERFACE */

#endif /* BCM_HAS_STRUCT_NETDEV_QUEUE */

#ifndef BCM_HAS_ALLOC_ETHERDEV_MQ
#define alloc_etherdev_mq(size, numqs)		alloc_etherdev((size))
#endif

#if !defined(TG3_NAPI) || !defined(BCM_HAS_VLAN_GRO_RECEIVE)
#define vlan_gro_receive(nap, grp, tag, skb) \
        vlan_hwaccel_receive_skb((skb), (grp), (tag))
#endif

#if !defined(TG3_NAPI) || !defined(BCM_HAS_NAPI_GRO_RECEIVE)
#define napi_gro_receive(nap, skb) \
        netif_receive_skb((skb))
#endif

#if (LINUX_VERSION_CODE < 0x020612)
static inline struct sk_buff *netdev_alloc_skb(struct net_device *dev,
		unsigned int length)
{
	struct sk_buff *skb = dev_alloc_skb(length);
	if (skb)
		skb->dev = dev;
	return skb;
}
#endif

#if !defined(HAVE_NETDEV_PRIV) && (LINUX_VERSION_CODE != 0x020603) && (LINUX_VERSION_CODE != 0x020604) && (LINUX_VERSION_CODE != 0x20605)
static inline void *netdev_priv(struct net_device *dev)
{
	return dev->priv;
}
#endif

#ifdef OLD_NETIF
static inline void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
#ifdef NONEXUS
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
#else
		msleep(10);
#endif
	}
}

static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}
#endif /* OLD_NETIF */

#ifndef VLAN_GROUP_ARRAY_SPLIT_PARTS
static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	if (vg)
		vg->vlan_devices[vlan_id] = dev;
}
#endif

#ifndef ETH_SS_TEST
#define ETH_SS_TEST  0
#endif
#ifndef ETH_SS_STATS
#define ETH_SS_STATS 1
#endif
#ifndef ADVERTISED_Pause
#define ADVERTISED_Pause		(1 << 13)
#endif
#ifndef ADVERTISED_Asym_Pause
#define ADVERTISED_Asym_Pause		(1 << 14)
#endif

#ifndef MII_CTRL1000
#define MII_CTRL1000			0x09
#endif
#ifndef MII_STAT1000
#define MII_STAT1000			0x0a
#endif
#ifndef BMCR_SPEED1000
#define BMCR_SPEED1000			0x0040
#endif
#ifndef ADVERTISE_1000XFULL
#define ADVERTISE_1000XFULL		0x0020
#endif
#ifndef ADVERTISE_1000XHALF
#define ADVERTISE_1000XHALF		0x0040
#endif
#ifndef ADVERTISE_1000XPAUSE
#define ADVERTISE_1000XPAUSE		0x0080
#endif
#ifndef ADVERTISE_1000XPSE_ASYM
#define ADVERTISE_1000XPSE_ASYM		0x0100
#endif
#ifndef ADVERTISE_PAUSE
#define ADVERTISE_PAUSE_CAP		0x0400
#endif
#ifndef ADVERTISE_PAUSE_ASYM
#define ADVERTISE_PAUSE_ASYM		0x0800
#endif
#ifndef LPA_1000XFULL
#define LPA_1000XFULL			0x0020
#endif
#ifndef LPA_1000XHALF
#define LPA_1000XHALF			0x0040
#endif
#ifndef LPA_1000XPAUSE
#define LPA_1000XPAUSE			0x0080
#endif
#ifndef LPA_1000XPAUSE_ASYM
#define LPA_1000XPAUSE_ASYM		0x0100
#endif
#ifndef LPA_PAUSE
#define LPA_PAUSE_CAP			0x0400
#endif
#ifndef LPA_PAUSE_ASYM
#define LPA_PAUSE_ASYM			0x0800
#endif
#ifndef ADVERTISE_1000HALF
#define ADVERTISE_1000HALF		0x0100
#endif
#ifndef ADVERTISE_1000FULL
#define ADVERTISE_1000FULL		0x0200
#endif

#ifndef ETHTOOL_FWVERS_LEN
#define ETHTOOL_FWVERS_LEN 32
#endif

#ifndef BCM_HAS_MII_RESOLVE_FLOWCTRL_FDX
#ifndef FLOW_CTRL_TX
#define FLOW_CTRL_TX	0x01
#endif
#ifndef FLOW_CTRL_RX
#define FLOW_CTRL_RX	0x02
#endif
static u8 mii_resolve_flowctrl_fdx(u16 lcladv, u16 rmtadv)
{
	u8 cap = 0;

	if (lcladv & ADVERTISE_PAUSE_CAP) {
		if (lcladv & ADVERTISE_PAUSE_ASYM) {
			if (rmtadv & LPA_PAUSE_CAP)
				cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
			else if (rmtadv & LPA_PAUSE_ASYM)
				cap = FLOW_CTRL_RX;
		} else {
			if (rmtadv & LPA_PAUSE_CAP)
				cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
		}
	} else if (lcladv & ADVERTISE_PAUSE_ASYM) {
		if ((rmtadv & LPA_PAUSE_CAP) && (rmtadv & LPA_PAUSE_ASYM))
			cap = FLOW_CTRL_TX;
	}

	return cap;
}
#endif /* BCM_HAS_MII_RESOLVE_FLOWCTRL_FDX */

#ifdef BCM_INCLUDE_PHYLIB_SUPPORT

#ifndef PHY_BRCM_STD_IBND_DISABLE
#define PHY_BRCM_STD_IBND_DISABLE	0x00000800
#define PHY_BRCM_EXT_IBND_RX_ENABLE	0x00001000
#define PHY_BRCM_EXT_IBND_TX_ENABLE	0x00002000
#endif

#ifndef PHY_BRCM_RX_REFCLK_UNUSED
#define PHY_BRCM_RX_REFCLK_UNUSED	0x00000400
#endif

#ifndef PHY_BRCM_CLEAR_RGMII_MODE
#define PHY_BRCM_CLEAR_RGMII_MODE	0x00004000
#endif

#ifndef PHY_BRCM_DIS_TXCRXC_NOENRGY
#define PHY_BRCM_DIS_TXCRXC_NOENRGY	0x00008000
#endif

#ifndef BCM_HAS_MDIOBUS_ALLOC
static struct mii_bus *mdiobus_alloc(void)
{
	struct mii_bus *bus;

	bus = kzalloc(sizeof(*bus), GFP_KERNEL);

	return bus;
}

void mdiobus_free(struct mii_bus *bus)
{
	kfree(bus);
}
#endif

#ifndef BCM_HAS_DEV_NAME
static inline const char *dev_name(const struct device *dev)
{
	/* will be changed into kobject_name(&dev->kobj) in the near future */
	return dev->bus_id;
}
#endif

#endif /* BCM_INCLUDE_PHYLIB_SUPPORT */
