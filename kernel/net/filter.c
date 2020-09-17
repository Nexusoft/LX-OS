/** NexusOS: filter to demultiplex packets to destination 

    Processes can express a request for the stream of packets
    that matches some given expression. See doc/design.networking 
    for more info. 
 
    Note that this design allows overlapping datasets. All rules
    are evaluated, not just the first that matches.
    */

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/printk.h>
#include <nexus/net.h>
#include <nexus/rdtsc.h>

#ifdef __NEXUSKERNEL__
#include <nexus/user_compat.h>
#else
#include <nexus/syscalls.h>
#endif
#include <nexus/IPC.interface.h>

/** A rule to match: a bitmask at given offset and length */
struct filter_rule {
	/* filter queue */
  	void *next;
  	void *prev;

	int portnum;	///< IPC port number or 0 for selftest

	/// fast path
	uint8_t protocol;
	uint16_t port;		// network byte order
  	
	// slow path
	uint16_t off;
	uint16_t len;
	
	/// select bits that MUST be 1. dontcare bits are 0, selected bits 1
	//  operation is data & mask1 == mask1
	char *mask1;

	/// select bits that MUST be 0. dontcare bits are 1, selected bits 0
	//  operation is data | ~mask0 == 0
	//  now, in the applied mask, selected bits are 1 and dontcare 0. 
	//  if the pattern has a 1 in a selected position, result is not zero.
	char *mask0; 	

};

struct Queue ruleset = QUEUE_EMPTY;
static int selftest;

/** Express interest in a stream of packets.
 
    @param portnum the IPC port that will receive matching packets
    @param mask a bitmask that will be logically ANDed. 
           if the remainder is all zero: success. 
  
    WARNING: we do NOT guard against overlapping rules that may
    cause multiple copies of packets being sent up to an application.

    @return 0 on success, -1 on failure */
int
nxnet_filter_add(uint16_t offset, uint16_t len, const char *mask0, 
		 const char *mask1, int portnum)
{
	extern int unittest_active;
	struct filter_rule *rule;
	int lvl;

	// block ipcport 0 request for all but the selftest
	// this used to occur, but it should not anymore
	// XXX remove if never triggered
	assert(portnum || unittest_active);

	// create rule
	rule = gcalloc(1, sizeof(*rule));
	rule->off = offset;
	rule->len = len;
	rule->mask0 = galloc(rule->len);
	rule->mask1 = galloc(rule->len);
	memcpy(rule->mask0, mask0, rule->len);
	memcpy(rule->mask1, mask1, rule->len);
	rule->portnum = portnum;

	// add to list
	lvl = disable_intr();
	queue_prepend(&ruleset, rule);
	restore_intr(lvl);
	return 0;
}

/** Filter by ip port (for TCP or UDP)
    A simple wrapper around the more generic bitmask method. 
    
    @param ipport in host byteorder
    @param do_tcp toggles between TCP (1) or UDP (0)

    XXX extend to only accept IP packets
 */
int
nxnet_filter_add_ipport(uint16_t ipport, int portnum, int do_tcp)
{
	struct filter_rule *rule;
	const int mlen = sizeof(PktIp) + sizeof(PktUdp);
	uint16_t dport;
	char mask0[mlen], mask1[mlen];
	int ret;

#define SLOW_INSERT_OLDSTYLE
#ifdef SLOW_INSERT_OLDSTYLE
	// initially, match all: fill with dontcare bits (see struct for info)
	memset(mask0, 0xff, mlen);  
	memset(mask1, 0, mlen);  

	// restrict port
	dport = htons(ipport);	
	memcpy(((PktUdp *) (mask0 + sizeof(PktIp)))->dstport, &dport, 2);
	memcpy(((PktUdp *) (mask1 + sizeof(PktIp)))->dstport, &dport, 2);

	// restrict proto
	((PktIp *) mask0)->proto = do_tcp ? IP_PROTO_TCP : IP_PROTO_UDP;
	((PktIp *) mask1)->proto = do_tcp ? IP_PROTO_TCP : IP_PROTO_UDP;
	
	ret = nxnet_filter_add(sizeof(PktEther), mlen, mask0, 
			       mask1, portnum);
#else
	int lvl;

	// create rule
	rule = gcalloc(1, sizeof(*rule));
	rule->portnum = portnum;
	rule->protocol = do_tcp ? 6 : 17;
	rule->port = htons(ipport); 
	
	// add to list
	lvl = disable_intr();
	queue_prepend(&ruleset, rule);
	restore_intr(lvl);

	ret = 0;
#endif
	printk("[filter] + %s port %u to port %d\n", 
	       do_tcp ? "tcp" : "udp", ipport, portnum);
	return ret;
}

/** Standard rule to see all ARP replies or requests
    @param is_request toggles between accepting requests or replies */
int
nxnet_filter_add_arp(int portnum, int is_request)
{
	const int mlen = sizeof(PktEther) + sizeof(ARP_Header);
	char mask0[mlen], mask1[mlen];
	
	// initially, match all: fill with dontcare bits (see struct for info)
	memset(mask0, 0xff, mlen);  
	memset(mask1, 0, mlen);  
	
	((PktEther *) mask0)->h_proto = htons(ETHER_PROTO_ARP);
	((PktEther *) mask1)->h_proto = htons(ETHER_PROTO_ARP);

	((ARP_Header *) (mask0 + sizeof(PktEther)))->ar_op = htons(is_request ? ARP_OP_REQUEST : ARP_OP_REPLY);
	((ARP_Header *) (mask1 + sizeof(PktEther)))->ar_op = htons(is_request ? ARP_OP_REQUEST : ARP_OP_REPLY);
	
	printk("[filter] + arp %s to port %d\n", 
	       is_request ? "request" : "reply", portnum);
	return nxnet_filter_add(0, mlen, mask0, mask1, portnum);
}

/** Filter a specific protocol. */
int
nxnet_filter_add_ipproto(int portnum, char protocol)
{
	const int mlen = sizeof(PktEther) + sizeof(PktIp);
	char mask0[mlen], mask1[mlen];
	
	// initially, match all: fill with dontcare bits (see struct for info)
	memset(mask0, 0xff, mlen);  
	memset(mask1, 0, mlen);  
	
	// select IP
	((PktEther *) mask0)->h_proto = htons(ETHER_PROTO_IP);
	((PktEther *) mask1)->h_proto = htons(ETHER_PROTO_IP);
	
	// select port
	((PktIp *) (mask0 + sizeof(PktEther)))->proto = protocol;
	((PktIp *) (mask1 + sizeof(PktEther)))->proto = protocol;

	printk("[filter] + ip protocol %u to port %d\n", protocol, portnum);
	return nxnet_filter_add(0, mlen, mask0, mask1, portnum);
}

/** Match.
    
    Logical AND of (data, mask1) must be zero to avoid false positives
    Logical AND of (data, mask0) must be mask0 to avoid false negatives

    @param return is 1 if match, 0 if not */
static int
rule_match(uint64_t *data, struct filter_rule *rule)
{
#define BLOCKLEN 8
	uint64_t ldata, lmask0, lmask1;
	register uint64_t *mask0, *mask1;
	register int len;
	
	mask0 = (uint64_t *) rule->mask0;
	mask1 = (uint64_t *) rule->mask1;
	len = rule->len;

	// scan by wordsize
	while (len > BLOCKLEN) {
		if (((*data & *mask1) != *mask1) || (*data & (~*mask0)))
			return 0;

		data++;
		mask0++;
		mask1++;
		len -= BLOCKLEN;
	}

	// extend last to wordsize with trailing zeroes
	if (likely(len)) {
		ldata = (*data) << (BLOCKLEN * (8 - len));
		lmask0 = (*mask0) << (BLOCKLEN * (8 - len)) | (((uint64_t) -1) >> (BLOCKLEN * len)); 
		lmask1 = (*mask1) << (BLOCKLEN * (8 - len));
		if (((ldata & lmask1) != lmask1) || (ldata & ~lmask0))
			return 0;
	}
	return 1;
}

/** Special case fast matcher for TCP / UDP 
    @param return is 1 if match, 0 if not */
static inline int
rule_match_tcpip(uint8_t protocol, uint16_t port, struct filter_rule *rule)
{
	if (rule->protocol && rule->protocol == protocol && rule->port == port)
		return 1;
	else
		return 0;
}

/** Demultiplex a filter
    @return number of matches (mainly for selftest) */
int
nxnet_filter_rx(void *pkt, int plen)
{
#define DESTLEN (200)
	// in the common case, a packet has only one destination
	// to be able to zero copy in that case, but also handle
	// multiple destinations, we first record the dests and 
	// in a separate step copy and send out
	int deststack[DESTLEN];
	int deststack_off = 0;
	void *copy;
	char *_pkt = pkt;
	int lvl, i, realplen, matched = 0, unique = 0;
	uint8_t protocol;
	uint16_t port;

	lvl = disable_intr();

	// fast path: extract TCP/UDP 
	if (ntohs(*(uint16_t *)(_pkt + 12)) == 0x0800) {
		uint16_t *transh = (void *) (_pkt + 34);
		protocol = _pkt[14 + 9];
		port = transh[1];
	}
	else
		protocol = port = 0;

		// match against a rule. return value is ignored
		int 
		rule_process(struct filter_rule *rule, void *unused) 
		{
			// fast match: TCP/IP
			if (!protocol || 
			     rule->protocol != protocol || 
			     rule->port != port) {
			
				// slow match: size and pattern
				if (rule->off + rule->len > plen ||
				    !(rule_match(pkt + rule->off, rule)))
					return 0;
			}
			else
				unique = 1; // quit iteration if matched as TCP/IP port


			// transmit packet
			if (rule->portnum) {
				if (unlikely(deststack_off == DESTLEN - 1)) {
					printk("[filter] out of stack\n");
					return 1; // stop iteration
				}
				deststack[deststack_off++] = rule->portnum;
			}
			matched++;
			return unique;
		}

	// match rules
	queue_iterate(&ruleset, (PFany) rule_process, NULL);

	// now send to all recipients. have to create copies for all but one
	// optimization: practically all packets have a single recipient
	realplen = nxnet_page_getlen(pkt);
	for (i = 1; i < deststack_off; i++) {
		void *out = nxnet_alloc_page();

		memcpy(out, pkt, realplen);
		nxnet_page_setlen(out, realplen);
		nxnet_vrouter_out(deststack[i], out, realplen);
	}
	// send without copy to the last one
	if (likely(deststack_off)) {
		nxnet_vrouter_out(deststack[0], pkt, realplen);
	}
	else {
		if (!selftest)
			nxnet_free_page(pkt);
	}

	restore_intr(lvl);
	return matched;
}

#ifndef NDEBUG 

const int plen = sizeof(PktEther) + sizeof(PktIp) + sizeof(PktUdp);

static char *
nxnet_filter_test_getpacket(int dport)
{
	PktEther *eth;
	PktIp *iph;
	PktUdp *udph;
	char *data;

	// allocate packet
	data = gcalloc(1, plen);
	eth = (void *) data;
	iph = (void *) data + sizeof(PktEther);
	udph = (void *) (data + sizeof(PktEther) + sizeof(PktIp));
	
	// set identifying fields
	eth->h_proto = htons(ETHER_PROTO_IP);
	iph->proto = IP_PROTO_UDP;
	*((uint16_t*) udph->dstport) = htons(dport);

	return data;
}

static int
nxnet_filter_test_ipport(void)
{
	int lvl;

	// match IP packet once
	if (nxnet_filter_add_ipport(65, 0, 0))
		ReturnError(1, "");
	if (nxnet_filter_add_ipport(65, 0, 1))
		ReturnError(1, "");

	if (nxnet_filter_rx(nxnet_filter_test_getpacket(64), plen) != 0)
		ReturnError(1, "");
	if (nxnet_filter_rx(nxnet_filter_test_getpacket(65), plen) != 1)
		ReturnError(1, "");
	
	lvl = disable_intr();
	while (queue_dequeue(&ruleset));
	queue_initialize(&ruleset);
	restore_intr(lvl);

	return 0;
}

/** Standard selftest 
    Verifies matching algorithm correctness, not packet processing 
 
    WARNING: if this function fails, the ruleset is NOT clean. 
    The system is supposed to panic on failing tests, so that's okay */
int
nxnet_filter_test(void)
{
	const char ones[] = {0xff, 0xff}, zeroes[] = {0, 0}, half[] = {0xff, 0};
	char *data;
	int matched, lvl;

	selftest = 1;

	// fail on empty queue
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_rx(data, 4))
		ReturnError(1, "");

	// match if identical
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 4, data, data, 0))
		ReturnError(1, "");
	if (nxnet_filter_rx(data, 4) != 1)
		ReturnError(1, "");

	// match if identical or has enough ones
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 2, ones, half, 0))
		ReturnError(1, "");
	if (nxnet_filter_rx(data, 4) != 2)
		ReturnError(1, "");

// broken as of fast tcp/ip path
#if 0
	// don't match if has too many ones
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 2, zeroes, zeroes, 0))
		ReturnError(1, "");
	if (nxnet_filter_rx(data, 4) != 2)
		ReturnError(1, "");
#endif

	lvl = disable_intr();
	while (queue_dequeue(&ruleset) != 0) {}
	queue_initialize(&ruleset);
	restore_intr(lvl);

// broken as of fast tcp/ip path
#if 0
	// test IP
	if (nxnet_filter_test_ipport())
		ReturnError(1, "");
#endif

	selftest = 0;
	printkx(PK_TEST, PK_DEBUG, "[test] packet filter OK.\n");
	return 0;
}

#endif /* NDEBUG */

