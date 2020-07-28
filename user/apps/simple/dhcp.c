/** NexusOS: DHCP client to set systemwide IP address 
    Based on lwIP network stack */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/dhcp.h>
#include <lwip/netif.h>

#include <nexus/sema.h>
#include <nexus/net.h>
#include <nexus/Net.interface.h>
#include <nexus/Thread.interface.h>

err_t nexusif_init(struct netif *netif);
err_t ethernet_input(struct pbuf *p, struct netif *netif);

static struct netif nexusif;

int 
main(int argc, char **argv)
{
	struct ip_addr ipaddr, netmask, gw;
	pthread_t thread;
	int msecs;

	printf("Nexus DHCP client -- built using lwIP\n");

    	IP4_ADDR(&gw, 0, 0, 0, 0);
   	IP4_ADDR(&ipaddr, 0, 0, 0, 0);
    	IP4_ADDR(&netmask, 0, 0, 0, 0);

	// initialize and start network stack
	netif_init();
	lwip_init();
	
	// register as network device to the lwIP stack
	netif_add(&nexusif, &ipaddr, &netmask, &gw, NULL, nexusif_init, ethernet_input);
	netif_set_default(&nexusif);
	dhcp_start(&nexusif);

	// request all UDP packets to DHCP client port from kernel
	Net_filter_ipport(0, 68, nexusif_port);
	Net_filter_arp(nexusif_port, 0);
	Net_filter_arp(nexusif_port, 1);

	printf("[dhcp] waiting for reply\n");
	while (!nexusif.ip_addr.addr) {
		
		// wait for fine timer to expire 
		Thread_USleep(DHCP_FINE_TIMER_MSECS * 100 /* speed up : not 1000, but 100 */);
		netif_poll(&nexusif);
		dhcp_fine_tmr();

		// optionally expire coarse timer
		if (msecs > 1000 * DHCP_COARSE_TIMER_SECS) {
			dhcp_coarse_tmr();
			msecs = 0;
		}

		msecs += DHCP_FINE_TIMER_MSECS;
	};

	// warning: assumption that host byteorder is LSB
	printf("[dhcp] acquired IPv4 address %02hu.%02hu.%02hu.%02hu\n",
               (nexusif.ip_addr.addr) & 0xff, 
               (nexusif.ip_addr.addr >>  8) & 0xff, 
               (nexusif.ip_addr.addr >> 16) & 0xff, 
               (nexusif.ip_addr.addr >> 24) & 0xff);

	Net_set_ip(nexusif.ip_addr.addr, nexusif.netmask.addr, nexusif.gw.addr);

	// keep running to have our network stack respond to ARP requests
	// the DHCP daemon runs the authoritative stack for this IP address
	while (1) 
		Thread_USleep(1000 * 1000 * 10);

	return 0;
}

