/** NexusOS: low-level packet information */

#include <nexus/defs.h>
#include <nexus/net.h>

/* These defines govern global nexus_netthread_debug */
#define NETTHREAD_DEBUG
#define NETTHREAD_DEBUG_VERBOSE

void
nxnet_pktinfo_macaddr(const void *mac)
{
	const char *eth = mac;
	
	printk("%02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n",
		eth[0] & 0xff, eth[1] & 0xff, eth[2] & 0xff,
		eth[3] & 0xff, eth[4] & 0xff, eth[5] & 0xff);
}

static void
nxnet_pktinfo_eth(const char *eth)
{
	printk("ethernet: proto=%d"
		" dst=%02hx.%02hx.%02hx.%02hx.%02hx.%02hx"
		" src=%02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n", 
		ntohs(*(uint16_t *) (eth + 12)),
		eth[0] & 0xff, eth[1] & 0xff, eth[2] & 0xff,
		eth[3] & 0xff, eth[4] & 0xff, eth[5] & 0xff,
		eth[6] & 0xff, eth[7] & 0xff, eth[8] & 0xff,
		eth[9] & 0xff, eth[10] & 0xff, eth[11] & 0xff);
}

/** print an ip address in network byte order */
void
nxnet_pktinfo_ipaddr(const uint32_t ip)
{
	uint32_t ipl = ntohl(ip);
	nxcompat_printf("%hu.%hu.%hu.%hu\n", 
	                (ipl >> 24) & 0xff, (ipl >> 16) & 0xff, 
	                (ipl >> 8) & 0xff, ipl & 0xff);
}


/** Print network packet information.

    It is not necessary to disable these taps everywhere, undefine
    the global NETTHREAD_DEBUG define to silence this code.

    @param caller_id is a simple int to differentiate between different 
           caller locations in the network stack
 */
void 
nxnet_pktinfo(const void *ptr, int caller_id)
{
#ifdef NETTHREAD_DEBUG
	const struct PktEther *eth = ptr;
	const struct PktIp *ip;
	const struct PktUdp *udp;
	const struct PktBootp *bootp;
	const char *tcph8;
	const uint16_t *tcph16;
	const uint32_t *tcph32;
	int off;

	printk("NET caller=%d pkt=%p type=", caller_id, ptr);
#ifdef NETTHREAD_DEBUG_VERBOSE
	nxnet_pktinfo_eth(ptr);
#endif
	// parse header
	if (ntohs(*(uint16_t*) eth->proto) == ETHER_PROTO_IP) {
		off = sizeof(struct PktEther);
		ip = (struct PktIp *) (ptr + off);
		
		// warning: little endianness assumption hardcoded
		printk("IP proto=%u len=%u [%u.%u.%u.%u->%u.%u.%u.%u].", 
			ip->proto, ntohs(*(uint16_t*)(ip->len)),
			ip->src[0] & 0xff, ip->src[1] & 0xff, 
			ip->src[2] & 0xff, ip->src[3] & 0xff,
			ip->dst[0] & 0xff, ip->dst[1] & 0xff, 
			ip->dst[2] & 0xff, ip->dst[3] & 0xff);

		// UDP
		if (ip->proto == IP_PROTO_UDP) {
			uint16_t dstport, srcport;

			off += sizeof(struct PktIp);
			udp = (struct PktUdp *) (ptr + off);
			dstport = ntohs(*(uint16_t*) udp->dstport);
			srcport = ntohs(*(uint16_t*) udp->srcport);
			
			printk ("UDP[%hu->%hu].", srcport, dstport);

			// TFTP
			if (srcport == 69 || dstport == 69) {
				printk ("TFTP");
			}
			// BOOTP if magic cookie is found
			else if (srcport == 67 || dstport == 67) {
				char dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
				off += sizeof(struct PktUdp);
				bootp = (struct PktBootp *) (ptr + off);

				if (!memcmp(bootp->dhcp_option_cookie, 
					    dhcp_cookie, 4))
					printk ("BOOTP");
				else
					printk ("BOOTP?");

				if (ntohs(*(uint16_t*) udp->dstport) == 67)
					printk(" request");
				else
					printk(" reply");
			}
		}
		// ICMP
		else if (ip->proto == IP_PROTO_ICMP) {
			printk("ICMP");
		}
		else if (ip->proto == IP_PROTO_TCP) {
			off += sizeof(struct PktIp);
			tcph8 = ptr + off;
			tcph16 = ptr + off;
			tcph32 = ptr + off;
			printk("TCP src=%d dst=%d seq=%x ack=%x "
			       "ack=%d syn=%d fin=%d\n", 
			       ntohs(tcph16[0]), ntohs(tcph16[1]),
			       tcph32[1], tcph32[2],
			       // NB: following is little-endian specific
			       tcph8[13] & 0x10 ? 1 : 0,
			       tcph8[13] & 0x2 ? 1 : 0,
			       tcph8[13] & 0x1 ? 1 : 0);

		}
		else
			printk("Proto=%hx,Len=%hx\n", ip->proto, ntohs(*(uint16_t*) ip->len));
	}
	else if (ntohs(*(uint16_t*) eth->proto) == ETHER_PROTO_ARP) {
		ARP_Header *arph;

		arph = (void *) (ptr + sizeof(struct PktEther));
		printk("ARP %s", ntohs(arph->ar_op) == 1 ? "request" : "reply");
	}
	else
		printk("Eth.Proto[%hx]\n", ntohs(*(uint16_t*) eth->proto));
	printk("\n");
#endif /* NETTHREAD_DEBUG */
}

