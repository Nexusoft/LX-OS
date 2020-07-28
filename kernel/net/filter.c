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

#include <nexus/IPC.interface.h>

/** A rule to match: a bitmask at given offset and length */
struct filter_rule {
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
	
	int portnum;	///< IPC port number or 0 for selftest
};

struct UQueue *ruleset;

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
	struct filter_rule *rule;

	if (!ruleset)
		ruleset = uqueue_new();

	// XXX add guard check

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
	uqueue_enqueue(ruleset, rule);
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
	const int mlen = sizeof(PktIp) + sizeof(PktUdp);
	uint16_t dport;
	char mask0[mlen], mask1[mlen];

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

	// insert. XXX shorten the filter: we don't need full IP+UDP headers
	return nxnet_filter_add(sizeof(PktEther), mlen, mask0, 
			        mask1, portnum);
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

	return nxnet_filter_add(0, mlen, mask0, mask1, portnum);
}

/** Match.
    
    Logical AND of (data, mask1) must be zero to avoid false positives
    Logical AND of (data, mask0) must be mask0 to avoid false negatives

    XXX use optimized assembly if this has to be really fast

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

/** Demultiplex a filter
    @return number of matches (mainly for selftest) */
int
nxnet_filter_rx(void *pkt, int plen)
{
	void *copy;
	int matched = 0;

	if (likely(ruleset != NULL)) {
		// match against a rule. return value is ignored
		int 
		rule_process(struct filter_rule *rule, void *unused) 
		{
			// size and pattern match
			if (rule->off + rule->len <= plen &&
			    (rule_match(pkt + rule->off, rule))) {

				// transmit packet
				if (rule->portnum) {
					copy = galloc(plen);
					memcpy(copy, pkt, plen);
					IPC_Send(rule->portnum, copy, plen);
				}
				matched++;
			}
			return 0;
		}

		// iterate over rules
		uqueue_iterate(ruleset, (PFany) rule_process, NULL);
	}

	gfree(pkt);
	return matched;
}

#ifndef NDEBUG 

#define ReturnError(x) do { printk("%s failed at %d\n", __FUNCTION__, __LINE__); return 1; } while (0);

const int plen = sizeof(PktEther) + sizeof(PktIp) + sizeof(PktUdp);

static char *
nxnet_filter_test_getpacket(int dport)
{
	PktIp *iph;
	PktUdp *udph;
	char *data;

	// allocate packet
	data = gcalloc(1, plen);
	iph = (void *) data + sizeof(PktEther);
	udph = (void *) (data + sizeof(PktEther) + sizeof(PktIp));
	
	// set identifying fields
	iph->proto = IP_PROTO_UDP;
	*((uint16_t*) udph->dstport) = htons(dport);
	return data;
}

static int
nxnet_filter_test_ipport(void)
{
	// match IP packet once
	if (nxnet_filter_add_ipport(65, 0, 0))
		ReturnError(1);
	if (nxnet_filter_add_ipport(65, 0, 1))
		ReturnError(1);

	if (nxnet_filter_rx(nxnet_filter_test_getpacket(64), plen) != 0)
		ReturnError(1);
	if (nxnet_filter_rx(nxnet_filter_test_getpacket(65), plen) != 1)
		ReturnError(1);
	
	uqueue_destroy(ruleset);
	ruleset = NULL;

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
	int matched;

	// fail on empty queue
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_rx(data, 4))
		ReturnError(1);

	// match if identical
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 4, data, data, 0))
		ReturnError(1);
	if (nxnet_filter_rx(data, 4) != 1)
		ReturnError(1);

	// match if identical or has enough ones
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 2, ones, half, 0))
		ReturnError(1);
	if (nxnet_filter_rx(data, 4) != 2)
		ReturnError(1);

	// don't match if has too many ones
	data = galloc(4);
	*((uint32_t *) data) = (0xff << 24) + 0xff;
	if (nxnet_filter_add(0, 2, zeroes, zeroes, 0))
		ReturnError(1);
	if (nxnet_filter_rx(data, 4) != 2)
		ReturnError(1);

	uqueue_destroy(ruleset);
	ruleset = NULL;

	// test IP
	if (nxnet_filter_test_ipport())
		ReturnError(1);
	
	printkx(PK_TEST, PK_DEBUG, "[test] packet filter OK.\n");
	return 0;
}

#endif /* NDEBUG */

