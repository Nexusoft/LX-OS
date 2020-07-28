/** NexusOS: low-level packet information */

#include <nexus/defs.h>
#include <nexus/net.h>

/* These defines govern global nexus_netthread_debug */
#undef NETTHREAD_DEBUG
#undef NETTHREAD_DEBUG_VERBOSE

void
nxnet_pktinfo_macaddr(const void *mac)
{
	const char *_mac = mac;
	int off;

	for (off = 0; off < 6; off++)
		nxcompat_printf("%02hx.", _mac[off] & 0xff);
	nxcompat_printf("\n");
}

/** print an ip address in network byte order */
void
nxnet_pktinfo_ipaddr(const uint32_t ip)
{
	uint32_t ipl = ntohl(ip);
	nxcompat_printf("%03hu.%03hu.%03hu.%03hu\n", 
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

// only enable when really needed
#ifdef NETTHREAD_DEBUG_VERBOSE
	printk("ethernet: proto=%d dest=%s src=%s\n", 
	       ntohs(eth->h_proto)
	       nxnet_pktinfo_mac(eth->dstaddr),
	       nxnet_pktinfo_mac(eth->srcaddr));

#endif
	// parse header
	printk("NET caller=%d pkt=%p type=", caller_id, ptr);
	if (ntohs(*(uint16_t*) eth->proto) == ETHER_PROTO_IP) {
		off = sizeof(struct PktEther);
		ip = (struct PktIp *) (ptr + off);
		printk("%d:IP.", caller_id);

		// UDP
		if (ip->proto == IP_PROTO_UDP) {
			off += sizeof(struct PktIp);
			udp = (struct PktUdp *) (ptr + off);
			printk ("UDP.");

			// TFTP
			if (ntohs(*(uint16_t*) udp->srcport) == 69 ||
			    ntohs(*(uint16_t*) udp->dstport) == 69) {
				printk ("TFTP");
			}
			// BOOTP if magic cookie is found
			else if (ntohs(*(uint16_t*) udp->srcport) == 67 ||
				 ntohs(*(uint16_t*) udp->dstport) == 67) {
				char dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
				off += sizeof(struct PktUdp);
				bootp = (struct PktBootp *) (ptr + off);

				if (!memcmp(bootp->dhcp_option_cookie, 
					    dhcp_cookie, 4))
					printk ("BOOTP");
				else
					printk ("BOOTP?");
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
		printk("ARP");
	}
	else
		printk("Eth.Proto[%hx]\n", ntohs(*(uint16_t*) eth->proto));
	printk("\n");
#endif /* NETTHREAD_DEBUG */
}

