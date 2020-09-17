/** NexusOS: kernel core networking code */

#include <nexus/defs.h>
#include <nexus/queue.h>
#include <nexus/synch.h>
#include <nexus/machineprimitives.h>
#include <nexus/device.h>
#include <nexus/net.h>
#include <nexus/thread.h>
#include <nexus/clock.h>
#include <nexus/util.h> // for atoi
#include <nexus/queue.h> // for atoi
#include <nexus/syscalls.h>
#include <nexus/clock.h>
#include <nexus/user_compat.h>
#include <asm/param.h> // for HZ

// linux/skbuff.h expects this
void __out_of_line_bug(int param) 
{ 
	nexuspanic();
	while (1);
}

/// default source for all userspace packets. is overwritten
//  with true MAC of default address in the vswitch.
char default_mac_address[6];			///< who to send outgoing packets as
int default_nic_port;				///< where to send packets out on

unsigned int my_ipaddress = (127) + (1 << 24);	///< 10.0.0.1 (warning: assumes little endian)
unsigned int my_gateway;
unsigned int my_netmask = 0x00ffffff; 		///< 255.255.255.0 (warning: assumes little endian)
unsigned int switch_packetcount;


//////// virtual router IO

/** Forward data to destination,
    called by both filter and switch */
void
nxnet_vrouter_out(int port, char *page, int len)
{
	ipc_sendpage_impl(curr_map, port, page);
}

/** Extract protocol  
    Blind drivers need to do that here in kernelspace, because they cannot 
    touch data in userspace. Needed to set TCP Offload descriptor flags */
static int
nxnet_vrouter_getproto(char *page)
{
	struct PktEther *eth = (void *) page;
	struct PktIp *iph;
	
        eth = (void *) page;
	iph = (void *) page + 14 /* eth header length */;
        if (ntohs(*(uint16_t*) eth->proto) == ETHER_PROTO_IP) {
	        if (iph->proto == IP_PROTO_TCP)
	      		return IP_PROTO_TCP;
	        else if (iph->proto == IP_PROTO_UDP)
	      		return IP_PROTO_UDP;
	        else
	      		return IP_PROTO_ICMP; /* interpreted as 'generic IP' */
	}
	else 
 	        return 0;
}

/** Receive a packet from the virtual router
    @param paddr will hold the physical address on return unless NULL
    @param proto will hold 0 or IP_PROTO_[ICMP|UDP|TCP] unless NULL
    @return packet length */
int
nxnet_vrouter_from(int port, char **page, char **paddr, int *proto) 
{
	int ret;

	assert(page);

	ret = ipc_recvpage_impl(curr_map, port, (void **) page, NULL);
	ret = ret ? -1 : nxnet_page_getlen(*page);

	if (ret < 0)
		return ret;

	// extract protocol
	if (proto)
          *proto = nxnet_vrouter_getproto(*page);

	// calculate physical address
	if (paddr) {
		*paddr = (char *) fast_virtToPhys(curr_map, (unsigned long) *page, 0, 0);
		assert(*paddr);
	}

	return ret;
}

/** Send a packet to the virtual router */
void
nxnet_vrouter_to(char *pkt, int plen)
{
	assert((((unsigned long) pkt) & (PAGE_SIZE - 1)) == 0);
	nxnet_page_setlen(pkt, plen);
	ipc_sendpage_impl(curr_map, default_switch_port, pkt);
}

//////// networking shell commands

/** Shell command to initialize network devices 
    Starts the device in a separate background thread, because the driver
    must belong to process 0 (kernelIPD), but this command is called from
    a userspace shell. */
int 
shell_netopen(int ac, char **av) 
{
#ifdef ENABLE_KDRIVERS
	int 
	netopen_thread(void *unused)
	{
		extern int tg3_init(void);
		extern int __e1000_init_module(void);
		extern int pcnet32_init_module(void);
		extern int nexus_open_netdev(void);
		extern struct net_device *global_netdev;
	
		// XXX support multiple devices	
		__e1000_init_module();
		if (!global_netdev)
			tg3_init();
		if (!global_netdev)
			pcnet32_init_module();
		
		if (global_netdev)
			nexus_open_netdev();
		return 0;
	}

	nexusthread_fork(netopen_thread, NULL);
#endif
	return 0;
}

