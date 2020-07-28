/** NexusOS: network subsystem selftest 
 
    We send a packet from a dummy driver through the stack to
    a dummy handler (nxnet_test_rx) */

#include <linux/skbuff.h>

#include <nexus/defs.h>
#include <nexus/net.h>
#include <nexus/synch-inline.h>

#define TESTREQUEST "dummy"
#define TESTREPLY   "reply"
#define HEADERLEN (sizeof(PktEther) + sizeof(PktIp) + sizeof(PktUdp))
const char dummymac[] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
const char remotemac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6}; // pretend to arrive from the net
Sema testpacket_sema = SEMA_INIT;

/** Create a dummy packet. 
    Payload is fixed at 5 bytes long. 
    Doesn't need to be complete: just be able to travel netstack

    @param direction selects between device->kernel (0) and k->d (1) */
sk_buff *
dummy_pkt_create(const char *msg, int direction)
{
	PktEther *eth;
	PktIp *ip;
	PktUdp *udp;
	sk_buff *skb;
	uint16_t len;

	skb = skb_allocate(HEADERLEN + 5);
	skb_put(skb, HEADERLEN + 5);

	// eth
	eth = (void *) skb->mac.raw;
	if (!direction) {// to kernel
		memcpy(eth->dstaddr, default_mac_address, 6);
		memcpy(eth->srcaddr, remotemac, 6);
	}
	else {
		memcpy(eth->dstaddr, remotemac, 6);
		memcpy(eth->srcaddr, default_mac_address, 6);
	}
	eth->h_proto = htons(ETHER_PROTO_IP);

	// ip
	ip  = ((void *) eth) + sizeof(PktEther);
	len = HEADERLEN - sizeof(PktEther);	// stupid conversion because ip->len is a char[2]
	memcpy(ip->len, &len, 2);
	ip->proto = IP_PROTO_UDP;

	// udp
	udp = ((void *) ip) + sizeof(PktIp);
	len = htons(UDP_PROTO_TEST);
	memcpy(udp->dstport, &len, 2);

	// payload
	memcpy(skb->mac.raw + HEADERLEN, msg, 5);

	skb->data = skb->mac.raw + 14;
	return skb;
}

/** Handler for packets of our test type. */
int
nxnet_test_rx(const void *pkt, int plen)
{
	struct sk_buff *skb;

	// verify that this is a test packet
	if (plen < HEADERLEN + 5 || memcmp(pkt + HEADERLEN, TESTREQUEST, 5))
		return -1;

	// build a reply. need not fully conform, only pass through our stack
	skb = dummy_pkt_create(TESTREPLY, 1);
	nexus_send(skb->mac.raw, skb->len);
	gfree(skb);

	return 0;
}

/** A dummy linux device driver hard_start_xmit implementation */
static void
dummy_driver_tx(struct sk_buff *skb, void *dev)
{
	static int seen;

	if (skb->len == HEADERLEN + 5 &&
	    !memcmp(skb->mac.raw + HEADERLEN, TESTREPLY, 5)) {
		seen = 1;
		V(&testpacket_sema);
	}

	// note that (1) the kernel hangs if the test packet is never seen
	// and (2) dummy remains active, so will get all broadcast packets
	if (!seen)
		printkx(PK_TEST, PK_WARN, "[test] wrong pkt. shell may hang\n");
}
		

int
nxnet_test(void)
{
	sk_buff *skb;
	int portnum;

	// initialize dummy device
	portnum = nxnet_dev_init(dummymac, dummy_driver_tx, NULL);
	if (portnum <= 0) {
		printk("[test] net device init failed\n");
		return 1;
	}

	// prepare a packet
	skb = dummy_pkt_create(TESTREQUEST, 0);

	// send packet to the kernel (i.e., 'recv from the net')
	nxnet_dev_rx(skb);

	// wait for reply
	P(&testpacket_sema);

	printkx(PK_TEST, PK_DEBUG, "[test] net OK\n");
	return 0;
}

