#ifndef _DRIVER_SKBUFF_H_
#define _DRIVER_SKBUFF_H_

// Copied from  Linux 2.4

#ifndef __KERNEL__

#ifndef HAVE_FULL_LIBC
typedef long		__kernel_time_t;
typedef long		__kernel_suseconds_t;

typedef __kernel_suseconds_t	suseconds_t;
typedef __kernel_time_t		time_t;
#endif

#ifndef _STRUCT_TIMEVAL
#define _STRUCT_TIMEVAL
struct timeval {
	time_t		tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* microseconds */
};
#endif // _STRUCT_TIMEVAL

typedef struct { volatile int counter; } atomic_t;

typedef struct {
	volatile unsigned int lock;
#if SPINLOCK_DEBUG
	unsigned magic;
#endif
} spinlock_t;

/*
 * Default implementation of macro that returns current
 * instruction pointer ("program counter").
 */
#define current_text_addr() ({ void *pc; __asm__("movl $1f,%0\n1:":"=g" (pc)); pc; })

#endif // __KERNEL__

struct sk_buff_head {
	/* These two members must be first. */
	struct sk_buff	* next;
	struct sk_buff	* prev;

	__u32		qlen;
	spinlock_t	lock;
};


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
	__u32		priority;		/* Packet queueing priority			*/
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
	__u32		nfcache;
	/* Associated connection, if any */
	struct nf_ct_info *nfct;
#ifdef CONFIG_NETFILTER_DEBUG
        unsigned int nf_debug;
#endif
#endif /*CONFIG_NETFILTER*/

#if defined(CONFIG_HIPPI)
	union{
		__u32	ifield;
	} private;
#endif

#ifdef CONFIG_NET_SCHED
       __u32           tc_index;               /* traffic control index */
#endif
};

#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(); } while (0)
static inline int skb_is_nonlinear(const struct sk_buff *skb)
{
	return skb->data_len;
}

static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
        unsigned char *tmp=skb->tail;
#ifndef HAVE_FULL_LIBC
        SKB_LINEAR_ASSERT(skb);
#else
		assert(0);
#endif
        skb->tail+=len;
        skb->len+=len;
        if(skb->tail>skb->end) {
#ifndef HAVE_FULL_LIBC
                skb_over_panic(skb, len, current_text_addr());
#else
		assert(0);
#endif
        }
        return tmp;
}

#endif // _DRIVER_SKBUFF_H_
