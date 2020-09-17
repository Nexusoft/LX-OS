/** NexusOS: Interface between Linux network drivers 
    and Nexus userspace NIC interface 
 */

#include <asm/bitops.h>			// has to be at top to fix compiler error

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <linux/ip.h>
#include <linux/icmp.h>

#include <nexus/device.h>
#include <nexus/devicecompat.h>

#include <nexus/Thread.interface.h>

#define ETH_P_IP (0x0800)

// XXX get proper headers for the Nexus netdevice interface
extern struct net_device *_global_netdev;
extern void pci_enable_pfault_handler(void);
extern int __e1000_init_module(void);
extern int pcnet32_init_module(void);

/** User network device registration. 
    Initializes the device and registers it as a nexus network driver.

    @param driver_init is usually the linux kernel module __init */
int
nxunet_init(void)
{
	// setup userlevel MMIO
	pci_enable_pfault_handler();

	// initialize device
	// notice that probe functions have different return conventions
	if (__e1000_init_module() == 1) {
		fprintf(stderr, "[netdrv] Intel Pro/1000 device found\n");
	}
	else if (!pcnet32_init_module()) {
		fprintf(stderr, "[netdrv] AMD PCnet32 device found\n");
	}
	else if (tg3_init()) {
		fprintf(stderr, "[netdrv] Broadcom TG3 device found\n");
	}
	else {
		fprintf(stderr, "[netdrv] No supported device found\n");
		return 1;
	}

	if (!_global_netdev) {
		// be quiet: no device is a common scenario
		return 1;
	}
	if (_global_netdev->open(_global_netdev)) {
		fprintf(stderr, "[netdrv] error: device open failed\n");
		return 1;
	}

	printf("[netdrv] up at %02hx.%02hx.%02hx.%02hx.%02hx.%02hx\n",
	       _global_netdev->dev_addr[0],
	       _global_netdev->dev_addr[1],
	       _global_netdev->dev_addr[2],
	       _global_netdev->dev_addr[3],
	       _global_netdev->dev_addr[4],
	       _global_netdev->dev_addr[5]);

	return 0;
}

#define PINGLEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))

unsigned short checksum(char *buf, int len) {
	unsigned int sum = 0;
	int i;

	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for(i=0; i < len; i += 2) {
		sum = sum + (unsigned int) ntohs(*(uint16_t *) (buf+i));
	}

	//XXX magic 16?
	// take only 16 bits out of the 32 bit sum
	while(sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);
	// one's complement the result
	sum = ~sum;

	return (unsigned short) sum;
}

void 
send_test_packet(void)
{
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct icmphdr *icmph;
	static int seqno;
	uint16_t csum;

	skb = alloc_skb(PINGLEN, 0);
	memset(skb->head, 0, PINGLEN);
	skb_put(skb, PINGLEN);
	assert(skb->data == skb->head);

	eth = (void*) skb->head;
	iph = (void*) skb->head + 14;
	icmph = (void*) skb->head + 14 + sizeof(struct iphdr);

	// ethernet
	memset(eth->h_dest, 0xff, 6);
	memcpy(eth->h_source, _global_netdev->dev_addr, 6);
	eth->h_proto = htons(ETH_P_IP);

	// ip
	iph->ihl = 5;
	iph->version = 4;
	iph->ttl = 2;
	iph->tot_len = ntohs(sizeof(struct iphdr) + sizeof(struct icmphdr));
	iph->protocol = 1;  // icmp
	iph->saddr = htonl((128 << 24) + (84 << 16) + (98 << 8) + 253); // NB: alwaysupdate to fit local net
	iph->daddr = htonl((128 << 24) + (84 << 16) + (98 << 8) + 99); // NB: alwaysupdate to fit local net

	// icmp
	icmph->type = 8;  		// echo request
	icmph->un.echo.sequence = seqno++;

	// checksums
	csum = checksum((char *) icmph, sizeof(*icmph));
	icmph->checksum = htons(csum);
	csum = checksum((char *) iph, sizeof(*iph));
	iph->check = htons(csum);

	_global_netdev->hard_start_xmit(skb, _global_netdev);
	printf("[netdrv] sent test packet\n");
}

int 
main(void) 
{
	if (nxunet_init())
		return 1;

	printf("Press [enter] to send a test ICMP packet\n");
	while (getchar()) {
		send_test_packet();
	}

	return 0;
}

