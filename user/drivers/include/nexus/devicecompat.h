#ifndef __DEVICECOMPAT_H__
#define __DEVICECOMPAT_H__
/* A device is compiled against some Linux kernel version.  In order
   to interface properly with the compat code, the device needs to
   make sure that its structures match these in this file. */

/* some header files will be the same for linux versions and compat */
#include <time.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <asm/bitops.h>

#include <nexus/sema.h>
#include <nexus/nexuseth.h>
#include <nexus/etherdev.h>
#include <nexus/libc-protos.h>

struct pci_dev;
struct ifreq;
struct ifmap;
struct vlan_group;
struct neigh_parms;
struct dst_entry;

#define PCI_ANY_ID (~0)

#define        EBUSY           16
#define        EINVAL          22
#define        IFNAMSIZ        16
#define MAX_ADDR_LEN     8
#define ARPHRD_ETHER        1
#define ETH_HLEN  14
#define ETH_ALEN  6
#define IFF_BROADCAST   0x2
#define IFF_MULTICAST   0x1000

#define __GFP_WAIT	0x10	/* Can wait and reschedule? */
#define __GFP_HIGH	0x20	/* Should access emergency pools? */
#define __GFP_IO	0x40	/* Can start low memory physical IO? */
#define __GFP_HIGHIO	0x80	/* Can start high mem physical IO? */
#define __GFP_FS	0x100	/* Can call down to low-level FS? */
#define GFP_KERNEL     (__GFP_HIGH | __GFP_WAIT | __GFP_IO | __GFP_HIGHIO | __GFP_FS)

#define     KERN_ERR        "<3>" 

typedef struct { volatile int counter; } atomic_t;
static __inline__ void atomic_inc(atomic_t *v);
static __inline__ int atomic_dec_and_test(atomic_t *v);

typedef unsigned short	sa_family_t;

/*
 *	1003.1g requires sa_family_t and that sa_data is char.
 */
 
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};


struct list_head {
	struct list_head * next, * prev;
};

struct timer_list {
	struct list_head list;
	unsigned long expires;
	unsigned long data;
	void (*function)(unsigned long);
};

typedef struct {
	volatile unsigned int lock;
#if SPINLOCK_DEBUG
	unsigned magic;
#endif
} spinlock_t;

struct net_device
{

	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	char			name[IFNAMSIZ];

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	unsigned long		rmem_end;	/* shmem "recv" end	*/
	unsigned long		rmem_start;	/* shmem "recv" start	*/
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	unsigned long		base_addr;	/* device I/O address	*/
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */

	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	unsigned char		dma;		/* DMA channel		*/

	unsigned long		state;

	struct net_device	*next;

	/* The device initialization function. Called only once. */
	int			(*init)(struct net_device *dev);

	/* ------- Fields preinitialized in Space.c finish here ------- */

	struct net_device	*next_sched;

	/* Interface index. Unique device identifier	*/
	int			ifindex;
	int			iflink;


	struct net_device_stats* (*get_stats)(struct net_device *dev);
	struct iw_statistics*	(*get_wireless_stats)(struct net_device *dev);

	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	struct iw_handler_def *	wireless_handlers;

	/*
	 * This marks the end of the "visible" part of the structure. All
	 * fields hereafter are internal to the system, and may change at
	 * will (read: may be cleaned up at will).
	 */

	/* These may be needed for future network-power-down code. */
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/
	unsigned long		last_rx;	/* Time of last Rx	*/

	unsigned short		flags;	/* interface flags (a la BSD)	*/
	unsigned short		gflags;
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
        unsigned short          unused_alignment_fixer; /* Because we need priv_flags,
                                                         * and we want to be 32-bit aligned.
                                                         */

	unsigned		mtu;	/* interface MTU value		*/
	unsigned short		type;	/* interface hardware type	*/
	unsigned short		hard_header_len;	/* hardware hdr length	*/
	void			*priv;	/* pointer to private data	*/

	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/
	unsigned char		dev_addr[MAX_ADDR_LEN];	/* hw address	*/
	unsigned char		addr_len;	/* hardware address length	*/

	struct dev_mc_list	*mc_list;	/* Multicast mac addresses	*/
	int			mc_count;	/* Number of installed mcasts	*/
	int			promiscuity;
	int			allmulti;

	int			watchdog_timeo;
	struct timer_list	watchdog_timer;

	/* Protocol specific pointers */

	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	*/
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/

	struct list_head	poll_list;	/* Link to poll list	*/
	int			quota;
	int			weight;

	struct Qdisc		*qdisc;
	struct Qdisc		*qdisc_sleeping;
	struct Qdisc		*qdisc_list;
	struct Qdisc		*qdisc_ingress;
	unsigned long		tx_queue_len;	/* Max frames per queue allowed */

	/* hard_start_xmit synchronizer */
	spinlock_t		xmit_lock;
	/* cpu id of processor entered to hard_start_xmit or -1,
	   if nobody entered there.
	 */
	int			xmit_lock_owner;
	/* device queue lock */
	spinlock_t		queue_lock;
	/* Number of references to this device */
	atomic_t		refcnt;
	/* The flag marking that device is unregistered, but held by an user */
	int			deadbeaf;

	/* Net device features */
	int			features;
#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_DYNALLOC	16	/* Self-dectructable device. */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */

	/* Called after device is detached from network. */
	void			(*uninit)(struct net_device *dev);
	/* Called after last user reference disappears. */
	void			(*destructor)(struct net_device *dev);

	/* Pointers to interface service routines.	*/
	int			(*open)(struct net_device *dev);
	int			(*stop)(struct net_device *dev);
	int			(*hard_start_xmit) (struct sk_buff *skb,
						    struct net_device *dev);
#define HAVE_NETDEV_POLL
	int			(*poll) (struct net_device *dev, int *quota);
	int			(*hard_header) (struct sk_buff *skb,
						struct net_device *dev,
						unsigned short type,
						void *daddr,
						void *saddr,
						unsigned len);
	int			(*rebuild_header)(struct sk_buff *skb);
#define HAVE_MULTICAST
	void			(*set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR
	int			(*set_mac_address)(struct net_device *dev,
						   void *addr);
#define HAVE_PRIVATE_IOCTL
	int			(*do_ioctl)(struct net_device *dev,
					    struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	int			(*set_config)(struct net_device *dev,
					      struct ifmap *map);
#define HAVE_HEADER_CACHE
	int			(*hard_header_cache)(struct neighbour *neigh,
						     struct hh_cache *hh);
	void			(*header_cache_update)(struct hh_cache *hh,
						       struct net_device *dev,
						       unsigned char *  haddr);
#define HAVE_CHANGE_MTU
	int			(*change_mtu)(struct net_device *dev, int new_mtu);

#define HAVE_TX_TIMEOUT
	void			(*tx_timeout) (struct net_device *dev);

	void			(*vlan_rx_register)(struct net_device *dev,
						    struct vlan_group *grp);
	void			(*vlan_rx_add_vid)(struct net_device *dev,
						   unsigned short vid);
	void			(*vlan_rx_kill_vid)(struct net_device *dev,
						    unsigned short vid);

	int			(*hard_header_parse)(struct sk_buff *skb,
						     unsigned char *haddr);
	int			(*neigh_setup)(struct net_device *dev, struct neigh_parms *);
	int			(*accept_fastpath)(struct net_device *, struct dst_entry*);

	/* open/release and usage marking */
	struct module *owner;

	/* bridge stuff */
	struct net_bridge_port	*br_port;

#ifdef CONFIG_NET_FASTROUTE
#define NETDEV_FASTROUTE_HMASK 0xF
	/* Semi-private data. Keep it at the end of device struct. */
	rwlock_t		fastpath_lock;
	struct dst_entry	*fastpath[NETDEV_FASTROUTE_HMASK+1];
#endif
#ifdef CONFIG_NET_DIVERT
	/* this will get initialized at each interface type init routine */
	struct divert_blk	*divert;
#endif /* CONFIG_NET_DIVERT */
};

#define MAX_SKB_FRAGS 6

struct sk_buff {
	/* These two members must be first. */
	struct sk_buff	* next;			/* Next buffer in list 				*/
	struct sk_buff	* prev;			/* Previous buffer in list 			*/

	struct sk_buff_head * list;		/* List we are on				*/
	struct sock	*sk;			/* Socket we are owned by 			*/
	struct timeval	stamp;			/* Time we arrived				*/
	struct net_device	*dev;		/* Device we arrived on/are leaving by		*/
	struct net_device	*real_dev;	/* For support of point to point protocols 
						   (e.g. 802.3ad) over bonding, we must save the
						   physical device that got the packet before
						   replacing skb->dev with the virtual device.  */

	/* Transport layer header */
	union
	{
		struct tcphdr	*th;
		struct udphdr	*uh;
		struct icmphdr	*icmph;
		struct igmphdr	*igmph;
		struct iphdr	*ipiph;
		struct spxhdr	*spxh;
		unsigned char	*raw;
	} h;

	/* Network layer header */
	union
	{
		struct iphdr	*iph;
		struct ipv6hdr	*ipv6h;
		struct arphdr	*arph;
		struct ipxhdr	*ipxh;
		unsigned char	*raw;
	} nh;
  
	/* Link layer header */
	union 
	{	
	  	struct ethhdr	*ethernet;
	  	unsigned char 	*raw;
	} mac;

	struct  dst_entry *dst;

	/* 
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */ 
	char		cb[48];	 

	unsigned int 	len;			/* Length of actual data			*/
 	unsigned int 	data_len;
	unsigned int	csum;			/* Checksum 					*/
	unsigned char 	__unused,		/* Dead field, may be reused			*/
			cloned, 		/* head may be cloned (check refcnt to be sure). */
  			pkt_type,		/* Packet class					*/
  			ip_summed;		/* Driver fed us an IP checksum			*/
	uint32_t		priority;		/* Packet queueing priority			*/
	atomic_t	users;			/* User count - see datagram.c,tcp.c 		*/
	unsigned short	protocol;		/* Packet protocol from driver. 		*/
	unsigned short	security;		/* Security level of packet			*/
	unsigned int	truesize;		/* Buffer size 					*/

	unsigned char	*head;			/* Head of buffer 				*/
	unsigned char	*data;			/* Data head pointer				*/
	unsigned char	*tail;			/* Tail pointer					*/
	unsigned char 	*end;			/* End pointer					*/

	void 		(*destructor)(struct sk_buff *);	/* Destruct function		*/
#ifdef CONFIG_NETFILTER
	/* Can be used for communication between hooks. */
        unsigned long	nfmark;
	/* Cache info */
	uint32_t		nfcache;
	/* Associated connection, if any */
	struct nf_ct_info *nfct;
#ifdef CONFIG_NETFILTER_DEBUG
        unsigned int nf_debug;
#endif
#endif /*CONFIG_NETFILTER*/

#if defined(CONFIG_HIPPI)
	union{
		uint32_t	ifield;
	} private;
#endif

#ifdef CONFIG_NET_SCHED
       uint32_t           tc_index;               /* traffic control index */
#endif
};


typedef struct skb_frag_struct skb_frag_t;

struct skb_frag_struct
{
	struct page *page;
	uint16_t page_offset;
	uint16_t size;
};

struct skb_shared_info {
	atomic_t	dataref;
	unsigned int	nr_frags;
	struct sk_buff	*frag_list;
	skb_frag_t	frags[MAX_SKB_FRAGS];
};


enum netdev_state_t
{
	__LINK_STATE_XOFF=0,
	__LINK_STATE_START,
	__LINK_STATE_PRESENT,
	__LINK_STATE_SCHED,
	__LINK_STATE_NOCARRIER,
	__LINK_STATE_RX_SCHED
};

struct sk_buff_head {
	/* These two members must be first. */
	struct sk_buff	* next;
	struct sk_buff	* prev;

	uint32_t		qlen;
	int lock;
	//spinlock_t	lock;
};

#define NR_CPUS 1

struct softnet_data
{
	int			throttle;
	int			cng_level;
	int			avg_blog;
	struct sk_buff_head	input_pkt_queue;
	struct list_head	poll_list;
	struct net_device	*output_queue;
	struct sk_buff		*completion_queue;

	struct net_device	blog_dev;	/* Sorry. 8) */
} ____cacheline_aligned;
extern struct softnet_data softnet_data[NR_CPUS];

enum
{
	HI_SOFTIRQ=0,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	TASKLET_SOFTIRQ
};

#define current_text_addr() ({ void *pc; __asm__("movl $1f,%0\n1:":"=g" (pc)); pc; })

#ifdef CONFIG_SMP
#define LOCK_PREFIX "lock ; "
#else
#define LOCK_PREFIX ""
#endif

#define ADDR (*(volatile long *) addr)

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))


struct resource {
	const char *name;
	unsigned long start, end;
	unsigned long flags;
	struct resource *parent, *sibling, *child;
};

#define IO_SPACE_LIMIT 0xffff

/*
 * IO resources have these defined flags.
 */
#define IORESOURCE_BITS		0x000000ff	/* Bus-specific bits */

#define IORESOURCE_IO		0x00000100	/* Resource type */
#define IORESOURCE_MEM		0x00000200
#define IORESOURCE_IRQ		0x00000400
#define IORESOURCE_DMA		0x00000800

#define IORESOURCE_PREFETCH	0x00001000	/* No side effects */
#define IORESOURCE_READONLY	0x00002000
#define IORESOURCE_CACHEABLE	0x00004000
#define IORESOURCE_RANGELENGTH	0x00008000
#define IORESOURCE_SHADOWABLE	0x00010000
#define IORESOURCE_BUS_HAS_VGA	0x00080000

#define IORESOURCE_UNSET	0x20000000
#define IORESOURCE_AUTO		0x40000000
#define IORESOURCE_BUSY		0x80000000	/* Driver has marked this resource busy */

/* ISA PnP IRQ specific bits (IORESOURCE_BITS) */
#define IORESOURCE_IRQ_HIGHEDGE		(1<<0)
#define IORESOURCE_IRQ_LOWEDGE		(1<<1)
#define IORESOURCE_IRQ_HIGHLEVEL	(1<<2)
#define IORESOURCE_IRQ_LOWLEVEL		(1<<3)

/* ISA PnP DMA specific bits (IORESOURCE_BITS) */
#define IORESOURCE_DMA_TYPE_MASK	(3<<0)
#define IORESOURCE_DMA_8BIT		(0<<0)
#define IORESOURCE_DMA_8AND16BIT	(1<<0)
#define IORESOURCE_DMA_16BIT		(2<<0)

#define IORESOURCE_DMA_MASTER		(1<<2)
#define IORESOURCE_DMA_BYTE		(1<<3)
#define IORESOURCE_DMA_WORD		(1<<4)

#define IORESOURCE_DMA_SPEED_MASK	(3<<6)
#define IORESOURCE_DMA_COMPATIBLE	(0<<6)
#define IORESOURCE_DMA_TYPEA		(1<<6)
#define IORESOURCE_DMA_TYPEB		(2<<6)
#define IORESOURCE_DMA_TYPEF		(3<<6)

/* ISA PnP memory I/O specific bits (IORESOURCE_BITS) */
#define IORESOURCE_MEM_WRITEABLE	(1<<0)	/* dup: IORESOURCE_READONLY */
#define IORESOURCE_MEM_CACHEABLE	(1<<1)	/* dup: IORESOURCE_CACHEABLE */
#define IORESOURCE_MEM_RANGELENGTH	(1<<2)	/* dup: IORESOURCE_RANGELENGTH */
#define IORESOURCE_MEM_TYPE_MASK	(3<<3)
#define IORESOURCE_MEM_8BIT		(0<<3)
#define IORESOURCE_MEM_16BIT		(1<<3)
#define IORESOURCE_MEM_8AND16BIT	(2<<3)
#define IORESOURCE_MEM_SHADOWABLE	(1<<5)	/* dup: IORESOURCE_SHADOWABLE */
#define IORESOURCE_MEM_EXPANSIONROM	(1<<6)

struct pci_driver {
	struct list_head node;
	char *name;
	const struct pci_device_id *id_table;	/* NULL if wants all devices */
	int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id);	/* New device inserted */
	void (*remove) (struct pci_dev *dev);	/* Device removed (NULL if not a hot-plug capable driver) */
	int  (*save_state) (struct pci_dev *dev, uint32_t state);    /* Save Device Context */
	int  (*suspend) (struct pci_dev *dev, uint32_t state);	/* Device suspended */
	int  (*resume) (struct pci_dev *dev);	                /* Device woken up */
	int  (*enable_wake) (struct pci_dev *dev, uint32_t state, int enable);   /* Enable wake event */
};


struct pci_device_id {
	unsigned int vendor, device;		/* Vendor and device ID or PCI_ANY_ID */
	unsigned int subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	unsigned int class, class_mask;		/* (class,subclass,prog-if) triplet */
	unsigned long driver_data;		/* Data private to the driver */
};

#define DEVICE_COUNT_COMPATIBLE	4
#define DEVICE_COUNT_IRQ	2
#define DEVICE_COUNT_DMA	2
#define DEVICE_COUNT_RESOURCE	12

/* DAN: added pci_map_info for nexus */
struct pci_map_info{
  unsigned int paddr;
  unsigned int vaddr;
  int size;
};
/*
 * The pci_dev structure is used to describe both PCI and ISAPnP devices.
 */
struct pci_dev {
	struct list_head global_list;	/* node in list of all PCI devices */
	struct list_head bus_list;	/* node in per-bus list */
	struct pci_bus	*bus;		/* bus this device is on */
	struct pci_bus	*subordinate;	/* bus this device bridges to */

	void		*sysdata;	/* hook for sys-specific extension */
	struct proc_dir_entry *procent;	/* device entry in /proc/bus/pci */

	unsigned int	devfn;		/* encoded device & function index */
	unsigned short	vendor;
	unsigned short	device;
	unsigned short	subsystem_vendor;
	unsigned short	subsystem_device;
	unsigned int	class;		/* 3 bytes: (base,sub,prog-if) */
	uint8_t		hdr_type;	/* PCI header type (`multi' flag masked out) */
	uint8_t		rom_base_reg;	/* which config register controls the ROM */

	struct pci_driver *driver;	/* which driver has allocated this device */
	void		*driver_data;	/* data private to the driver */
	uint64_t	dma_mask;	/* Mask of the bits of bus address this
					   device implements.  Normally this is
					   0xffffffff.  You only need to change
					   this if your device has broken DMA
					   or supports 64-bit transfers.  */

	uint32_t        current_state;  /* Current operating state. In ACPI-speak,
					   this is D0-D3, D0 being fully functional,
					   and D3 being off. */

	/* device is compatible with these IDs */
	unsigned short vendor_compatible[DEVICE_COUNT_COMPATIBLE];
	unsigned short device_compatible[DEVICE_COUNT_COMPATIBLE];

	/*
	 * Instead of touching interrupt line and base address registers
	 * directly, use the values stored here. They might be different!
	 */
	unsigned int	irq;
	struct resource resource[DEVICE_COUNT_RESOURCE]; /* I/O and memory regions + expansion ROMs */
	struct resource dma_resource[DEVICE_COUNT_DMA];
	struct resource irq_resource[DEVICE_COUNT_IRQ];

	char		name[90];	/* device name */
	char		slot_name[8];	/* slot name */
	int		active;		/* ISAPnP: device is active */
	int		ro;		/* ISAPnP: read only */
	unsigned short	regs;		/* ISAPnP: supported registers */

	/* These fields are used by common fixups */
	unsigned short	transparent:1;	/* Transparent PCI bridge */

	int (*prepare)(struct pci_dev *dev);	/* ISAPnP hooks */
	int (*activate)(struct pci_dev *dev);
        int (*deactivate)(struct pci_dev *dev);

  struct pci_map_info map_info[DEVICE_COUNT_RESOURCE];
  int pci_dev_oid; // This should be the only difference between the user struct and the kernel struct
};

#define EIO              5      /* I/O error */
#define PCI_LATENCY_TIMER      0x0d    /* 8 bits */
#define PCI_VENDOR_ID		0x00	/* 16 bits */
#define PCI_DEVICE_ID		0x02	/* 16 bits */
#define PCI_COMMAND		0x04	/* 16 bits */
#define  PCI_COMMAND_IO		0x1	/* Enable response in I/O space */
#define  PCI_COMMAND_MEMORY	0x2	/* Enable response in Memory space */
#define  PCI_COMMAND_MASTER	0x4	/* Enable bus mastering */
#define  PCI_COMMAND_SPECIAL	0x8	/* Enable response to special cycles */
#define  PCI_COMMAND_INVALIDATE	0x10	/* Use memory write and invalidate */
#define  PCI_COMMAND_VGA_PALETTE 0x20	/* Enable palette snooping */
#define  PCI_COMMAND_PARITY	0x40	/* Enable parity checking */
#define  PCI_COMMAND_WAIT 	0x80	/* Enable address/data stepping */
#define  PCI_COMMAND_SERR	0x100	/* Enable SERR */
#define  PCI_COMMAND_FAST_BACK	0x200	/* Enable back-to-back writes */

#define ETH_P_802_3       0x0001          /* Dummy type for 802.3 frames  */

struct ethhdr 
{
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
} __attribute__((packed));

/* Standard interface flags (netdevice->flags). */
#define	IFF_UP		0x1		/* interface is up		*/
#define	IFF_BROADCAST	0x2		/* broadcast address valid	*/
#define	IFF_DEBUG	0x4		/* turn on debugging		*/
#define	IFF_LOOPBACK	0x8		/* is a loopback net		*/
#define	IFF_POINTOPOINT	0x10		/* interface is has p-p link	*/
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers	*/
#define	IFF_RUNNING	0x40		/* resources allocated		*/
#define	IFF_NOARP	0x80		/* no ARP protocol		*/
#define	IFF_PROMISC	0x100		/* receive all packets		*/
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets*/

#define IFF_MASTER	0x400		/* master of a load balancer 	*/
#define IFF_SLAVE	0x800		/* slave of a load balancer	*/

#define IFF_MULTICAST	0x1000		/* Supports multicast		*/

#define IFF_VOLATILE	(IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|IFF_MASTER|IFF_SLAVE|IFF_RUNNING)

#define IFF_PORTSEL	0x2000          /* can set media type		*/
#define IFF_AUTOMEDIA	0x4000		/* auto media select active	*/
#define IFF_DYNAMIC	0x8000		/* dialup device with changing addresses*/

/* Private (from user) interface flags (netdevice->priv_flags). */
#define IFF_802_1Q_VLAN 0x1             /* 802.1Q VLAN device.          */


#define IF_GET_IFACE	0x0001		/* for querying only */
#define IF_GET_PROTO	0x0002

/* For definitions see hdlc.h */
#define IF_IFACE_V35	0x1000		/* V.35 serial interface	*/
#define IF_IFACE_V24	0x1001		/* V.24 serial interface	*/
#define IF_IFACE_X21	0x1002		/* X.21 serial interface	*/
#define IF_IFACE_T1	0x1003		/* T1 telco serial interface	*/
#define IF_IFACE_E1	0x1004		/* E1 telco serial interface	*/
#define IF_IFACE_SYNC_SERIAL 0x1005	/* cant'b be set by software	*/

/* For definitions see hdlc.h */
#define IF_PROTO_HDLC	0x2000		/* raw HDLC protocol		*/
#define IF_PROTO_PPP	0x2001		/* PPP protocol			*/
#define IF_PROTO_CISCO	0x2002		/* Cisco HDLC protocol		*/
#define IF_PROTO_FR	0x2003		/* Frame Relay protocol		*/
#define IF_PROTO_FR_ADD_PVC 0x2004	/*    Create FR PVC		*/
#define IF_PROTO_FR_DEL_PVC 0x2005	/*    Delete FR PVC		*/
#define IF_PROTO_X25	0x2006		/* X.25				*/


#define     KERN_DEBUG      "<7>"   /* debug-level messages                 */

#define PACKET_HOST		0		/* To us		*/
#define PACKET_BROADCAST	1		/* To all		*/
#define PACKET_MULTICAST	2		/* To group		*/
#define PACKET_OTHERHOST	3		/* To someone else 	*/
#define PACKET_OUTGOING		4		/* Outgoing of any type */
/* These ones are invisible by user level */
#define PACKET_LOOPBACK		5		/* MC/BRD frame looped back */
#define PACKET_FASTROUTE	6		/* Fastrouted frame	*/

/* Packet socket options */

#define PACKET_ADD_MEMBERSHIP		1
#define PACKET_DROP_MEMBERSHIP		2
#define PACKET_RECV_OUTPUT		3
/* Value 4 is still used by obsolete turbo-packet. */
#define PACKET_RX_RING			5
#define PACKET_STATISTICS		6
#define PACKET_COPY_THRESH		7


#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
#define ETH_P_802_2	0x0004		/* 802.2 frames 		*/
#define ETH_P_SNAP	0x0005		/* Internal only		*/
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type 	*/
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2	0x0011		/* 802.2 frames 		*/
#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net)	*/
#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
#define ETH_P_IRDA	0x0017		/* Linux-IrDA			*/
#define ETH_P_ECONET	0x0018		/* Acorn Econet			*/
#define ETH_P_HDLC	0x0019		/* HDLC frames			*/

typedef struct {
	volatile unsigned int lock;
#if SPINLOCK_DEBUG
	unsigned magic;
#endif
} rwlock_t;
#define LL_MAX_HEADER	96 //XXX what shoud this be?

struct hh_cache
{
	struct hh_cache *hh_next;	/* Next entry			     */
	atomic_t	hh_refcnt;	/* number of users                   */
	unsigned short  hh_type;	/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
	int		hh_len;		/* length of header */
	int		(*hh_output)(struct sk_buff *skb);
	rwlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - ((__len) & (HH_DATA_MOD - 1)))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER)];
};

struct neighbour
{
	struct neighbour	*next;
	struct neigh_table	*tbl;
	struct neigh_parms	*parms;
	struct net_device		*dev;
	unsigned long		used;
	unsigned long		confirmed;
	unsigned long		updated;
	uint8_t			flags;
	uint8_t			nud_state;
	uint8_t			type;
	uint8_t			dead;
	atomic_t		probes;
	rwlock_t		lock;
	unsigned char		ha[(MAX_ADDR_LEN+sizeof(unsigned long)-1)&~(sizeof(unsigned long)-1)];
	struct hh_cache		*hh;
	atomic_t		refcnt;
	int			(*output)(struct sk_buff *skb);
	struct sk_buff_head	arp_queue;
	struct timer_list	timer;
	struct neigh_ops	*ops;
	uint8_t			primary_key[0];
};

#define SPINLOCK_MAGIC  0xdead4ead

#if SPINLOCK_DEBUG
#define SPINLOCK_MAGIC_INIT     , SPINLOCK_MAGIC
#else
#define SPINLOCK_MAGIC_INIT     /* */
#endif

#define SPIN_LOCK_UNLOCKED (spinlock_t) { 1 SPINLOCK_MAGIC_INIT }

/* Use nexus spinlocks */
#define spin_lock_init(x)       do { *(x) = 0; } while(0)
#define spin_lock_irqsave(lock, flags)		spinlock(lock)
#define spin_unlock_irqrestore(lock, flags)	spinunlock(lock)

/* Internal */
#define skb_shinfo(SKB)		((struct skb_shared_info *)((SKB)->end))

void skb_over_panic(struct sk_buff *skb, int len, void *here);
void skb_under_panic(struct sk_buff *skb, int len, void *here);

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

#define LOCK ""
/*
 * Make sure gcc doesn't try to be clever and move things around
 * on us. We need to use _exactly_ the address the user gave us,
 * not some alias that contains the same information.
 */

#define ATOMIC_INIT(i)	{ (i) }

/**
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically reads the value of @v.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
#define atomic_read(v)		((v)->counter)

/**
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 * 
 * Atomically sets the value of @v to @i.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
#define atomic_set(v,i)		(((v)->counter) = (i))

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 * 
 * Atomically adds @i to @v.  Note that the guaranteed useful range
 * of an atomic_t is only 24 bits.
 */
static __inline__ void atomic_add(int i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "addl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));
}

/**
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */
static __inline__ void atomic_sub(int i, atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "subl %1,%0"
		:"=m" (v->counter)
		:"ir" (i), "m" (v->counter));
}

/**
 * atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 * 
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */
static __inline__ int atomic_sub_and_test(int i, atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK "subl %2,%0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		:"ir" (i), "m" (v->counter) : "memory");
	return c;
}

/**
 * atomic_inc - increment atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ void atomic_inc(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "incl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ void atomic_dec(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "decl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK "decl %0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		:"m" (v->counter) : "memory");
	return c != 0;
}

/**
 * atomic_inc_and_test - increment and test 
 * @v: pointer of type atomic_t
 * 
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ int atomic_inc_and_test(atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK "incl %0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		:"m" (v->counter) : "memory");
	return c != 0;
}

/**
 * atomic_add_negative - add and test if negative
 * @v: pointer of type atomic_t
 * @i: integer value to add
 * 
 * Atomically adds @i to @v and returns true
 * if the result is negative, or false when
 * result is greater than or equal to zero.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */ 
static __inline__ int atomic_add_negative(int i, atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK "addl %2,%0; sets %1"
		:"=m" (v->counter), "=qm" (c)
		:"ir" (i), "m" (v->counter) : "memory");
	return c;
}

/* These are x86-specific, used by some header files */
#define atomic_clear_mask(mask, addr) \
__asm__ __volatile__(LOCK "andl %0,%1" \
: : "r" (~(mask)),"m" (*addr) : "memory")

#define atomic_set_mask(mask, addr) \
__asm__ __volatile__(LOCK "orl %0,%1" \
: : "r" (mask),"m" (*addr) : "memory")

/* Atomic operations are already serializing on x86 */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

struct sk_buff *alloc_skb(unsigned int size, int gfp_mask);

/**
 *	skb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
 
static inline int skb_queue_empty(struct sk_buff_head *list)
{
	return (list->next == (struct sk_buff *) list);
}

/**
 *	skb_get - reference buffer
 *	@skb: buffer to reference
 *
 *	Makes another reference to a socket buffer and returns a pointer
 *	to the buffer.
 */
 
static inline struct sk_buff *skb_get(struct sk_buff *skb)
{
	atomic_inc(&skb->users);
	return skb;
}

/*
 * If users==1, we are the only owner and are can avoid redundant
 * atomic change.
 */
 
/**
 *	kfree_skb - free an sk_buff
 *	@skb: buffer to free
 *
 *	Drop a reference to the buffer and free it if the usage count has
 *	hit zero.
 */
extern void			__kfree_skb(struct sk_buff *skb); 
static inline void kfree_skb(struct sk_buff *skb)
{
	if (atomic_read(&skb->users) == 1 || atomic_dec_and_test(&skb->users))
		__kfree_skb(skb);
}

/**
 *	skb_cloned - is the buffer a clone
 *	@skb: buffer to check
 *
 *	Returns true if the buffer was generated with skb_clone() and is
 *	one of multiple shared copies of the buffer. Cloned buffers are
 *	shared data so must not be written to under normal circumstances.
 */

static inline int skb_cloned(struct sk_buff *skb)
{
	return skb->cloned && atomic_read(&skb_shinfo(skb)->dataref) != 1;
}

/**
 *	skb_shared - is the buffer shared
 *	@skb: buffer to check
 *
 *	Returns true if more than one person has a reference to this
 *	buffer.
 */
 
static inline int skb_shared(struct sk_buff *skb)
{
	return (atomic_read(&skb->users) != 1);
}

/**
 *	skb_peek
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the head element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
 
static inline struct sk_buff *skb_peek(struct sk_buff_head *list_)
{
	struct sk_buff *list = ((struct sk_buff *)list_)->next;
	if (list == (struct sk_buff *)list_)
		list = NULL;
	return list;
}

/**
 *	skb_peek_tail
 *	@list_: list to peek at
 *
 *	Peek an &sk_buff. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the tail element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */

static inline struct sk_buff *skb_peek_tail(struct sk_buff_head *list_)
{
	struct sk_buff *list = ((struct sk_buff *)list_)->prev;
	if (list == (struct sk_buff *)list_)
		list = NULL;
	return list;
}

/**
 *	skb_queue_len	- get queue length
 *	@list_: list to measure
 *
 *	Return the length of an &sk_buff queue. 
 */
 
static inline uint32_t skb_queue_len(struct sk_buff_head *list_)
{
	return(list_->qlen);
}

static inline void skb_queue_head_init(struct sk_buff_head *list)
{
	spin_lock_init(&list->lock);
	list->prev = (struct sk_buff *)list;
	list->next = (struct sk_buff *)list;
	list->qlen = 0;
}

/*
 *	Insert an sk_buff at the start of a list.
 *
 *	The "__skb_xxxx()" functions are the non-atomic ones that
 *	can only be called with interrupts disabled.
 */

/**
 *	__skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 
static inline void __skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	struct sk_buff *prev, *next;

	newsk->list = list;
	list->qlen++;
	prev = (struct sk_buff *)list;
	next = prev->next;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}


/**
 *	skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_head(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}

/**
 *	__skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 

static inline void __skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	struct sk_buff *prev, *next;

	newsk->list = list;
	list->qlen++;
	next = (struct sk_buff *)list;
	prev = next->prev;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}

/**
 *	skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_tail(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}

/**
 *	__skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *next, *prev, *result;

	prev = (struct sk_buff *) list;
	next = prev->next;
	result = NULL;
	if (next != prev) {
		result = next;
		next = next->next;
		list->qlen--;
		next->prev = prev;
		prev->next = next;
		result->next = NULL;
		result->prev = NULL;
		result->list = NULL;
	}
	return result;
}

/**
 *	skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, flags);
	result = __skb_dequeue(list);
	spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

/*
 *	Insert a packet on a list.
 */

static inline void __skb_insert(struct sk_buff *newsk,
	struct sk_buff * prev, struct sk_buff *next,
	struct sk_buff_head * list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
	newsk->list = list;
	list->qlen++;
}

/**
 *	skb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newsk: buffer to insert
 *
 *	Place a packet before a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	A buffer cannot be placed on two lists at the same time.
 */

static inline void skb_insert(struct sk_buff *old, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&old->list->lock, flags);
	__skb_insert(newsk, old->prev, old, old->list);
	spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 *	Place a packet after a given packet in a list.
 */

static inline void __skb_append(struct sk_buff *old, struct sk_buff *newsk)
{
	__skb_insert(newsk, old, old->next, old->list);
}

/**
 *	skb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */


static inline void skb_append(struct sk_buff *old, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&old->list->lock, flags);
	__skb_append(old, newsk);
	spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 * remove sk_buff from list. _Must_ be called atomically, and with
 * the list known..
 */
 
static inline void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	struct sk_buff * next, * prev;

	list->qlen--;
	next = skb->next;
	prev = skb->prev;
	skb->next = NULL;
	skb->prev = NULL;
	skb->list = NULL;
	next->prev = prev;
	prev->next = next;
}

/**
 *	skb_unlink	-	remove a buffer from a list
 *	@skb: buffer to remove
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	
 *	Works even without knowing the list it is sitting on, which can be 
 *	handy at times. It also means that THE LIST MUST EXIST when you 
 *	unlink. Thus a list must have its contents unlinked before it is
 *	destroyed.
 */

static inline void skb_unlink(struct sk_buff *skb)
{
	struct sk_buff_head *list = skb->list;

	if(list) {
		unsigned long flags;

		spin_lock_irqsave(&list->lock, flags);
		if(skb->list == list)
			__skb_unlink(skb, skb->list);
		spin_unlock_irqrestore(&list->lock, flags);
	}
}

/* XXX: more streamlined implementation */

/**
 *	__skb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct sk_buff *__skb_dequeue_tail(struct sk_buff_head *list)
{
	struct sk_buff *skb = skb_peek_tail(list); 
	if (skb)
		__skb_unlink(skb, list);
	return skb;
}

/**
 *	skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct sk_buff *skb_dequeue_tail(struct sk_buff_head *list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, flags);
	result = __skb_dequeue_tail(list);
	spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

static inline int skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->data_len;
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

int out_of_line_bug(int line);

#define SKB_PAGE_ASSERT(skb) do { if (skb_shinfo(skb)->nr_frags) out_of_line_bug(__LINE__); } while (0)
#define SKB_FRAG_ASSERT(skb) do { if (skb_shinfo(skb)->frag_list) out_of_line_bug(__LINE__); } while (0)
#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(__LINE__); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	if(skb->tail>skb->end) {
		skb_over_panic(skb, len, current_text_addr());
	}
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
	if (skb->len < skb->data_len)
		out_of_line_bug(__LINE__);
	return 	skb->data+=len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */

static inline unsigned char * skb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __skb_pull(skb,len);
}

static inline void netif_stop_queue(struct net_device *dev)
{
	set_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_queue_stopped(struct net_device *dev)
{
	return test_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_running(struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}

#endif

