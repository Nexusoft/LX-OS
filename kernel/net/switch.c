/** NexusOS: virtual (minimal) ethernet switch 
    Main functionality is lookup: MAC -> ipcport */

#include <nexus/defs.h>
#include <nexus/net.h>
#include <nexus/user_compat.h>
#include <nexus/hashtable.h>
#include <nexus/printk.h>

/// Entry in the lookup table. for lookup, portnum suffices if we hash on mac.
//  We need the mac in results to guard against double hash collisions, though.
//  Plus, it simplifies source matching to avoid broadcast to source.
struct nxswitch_entry {
	char mac[6];
	int port_num;
};

/// we only support a single virtual switch. 
static HashTable *static_switch;

/** Have the switch process a packet: select outgoing port and transmit.
    FREES the handed packet. */
void 
nxnet_switch_tx(char *pkt, int plen) 
{
	struct nxswitch_entry *elem;
	char mac_broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	PktEther *eth;
	int port_num;

	switch_packetcount++;
	eth = (PktEther *) pkt;

	// drop all traffic but ARP and IP
	// XXX eventually remove
	if (eth->h_proto != htons(ETHER_PROTO_IP) &&
	    eth->h_proto != htons(ETHER_PROTO_ARP)) {
		gfree(pkt);
		return;
	}

	// unicast default dest: send to filter to demultiplex
	if (!memcmp(eth->dstaddr, default_mac_address, 6)) {
		nxnet_filter_rx(pkt, plen);
		return;
	}

	// broadcast: to all ports except source
	if (!memcmp(eth->dstaddr, mac_broadcast, 6)) {

		// nested function called for each nic
		void iterate_nics(void *entry, void *arg) 
		{
			char *copy;
			elem = entry;

			// send on port if not source
			// or if default src, in which case it came from upper layers
			if (memcmp(eth->srcaddr, elem->mac, 6) ||
			    !memcmp(eth->srcaddr, default_mac_address, 6)) { 
				copy = galloc(plen);
				memcpy(copy, pkt, plen);
				IPC_Send(elem->port_num, copy, plen);
			}
		}
		hash_iterate(static_switch, iterate_nics, NULL);

		// send bcast not from local source to upper layers
		if (memcmp(eth->srcaddr, default_mac_address, 6))
			nxnet_filter_rx(pkt, plen);
		else
			gfree(pkt);
		return;
	}

	// unicast other: lookup nic by mac and forward
	elem = hash_findItem(static_switch, eth->dstaddr);
	if (elem) {
		IPC_Send(elem->port_num, pkt, plen);
		return;
	}

	// other destination and default src ? send out on default NIC
	if (!memcmp(eth->srcaddr, default_mac_address, 6)) {
		IPC_Send(default_nic_port, pkt, plen);
		return;
	}

	// trash. bin it.
	gfree(pkt);
}

/** Listen for incoming packets over IPC */
static int 
nxnet_switch_thread(void *arg) 
{
	const int mtu = 1514;
	char *buf;
	int len;

	while (1) {
		// receive a packet
		buf = nxcompat_alloc(mtu);
		len = IPC_Recv((long) arg, buf, mtu);
		if (len <= 0)
			printkx(PK_NET, PK_DEBUG, "switch rx failed\n");
		else
			nxnet_switch_tx(buf, len);
	}

	// not reached
	return -1;
}

/** Associate a MAC address with a netdevice. */
void 
nxnet_switch_add(const char *mac, int port_num)
{
	struct nxswitch_entry *elem;
	
	elem = nxcompat_alloc(sizeof(*elem));
	memcpy(elem->mac, mac, 6);
	elem->port_num = port_num;

        // we do not guard against duplicates
        hash_insert(static_switch, mac, elem);	
	nxnet_pktinfo_macaddr(mac);

	// policy: set the last registered device as system default
	// the background to this is that the first dev is a test dummy
	memcpy(default_mac_address, mac, 6);
	default_nic_port = port_num;
}

/** Start the default switch */
int 
nxnet_switch_init(void)
{
	int port_num;

	static_switch = hash_new(47 /* prime of reasonable size */, 
			         6 /* Ethernet MAC address length */);

	// listen on default switch port
	port_num = default_switch_port;
	port_num = IPC_CreatePort(&port_num);
	if (port_num != default_switch_port) {
		printkx(PK_NET, PK_WARN, "[net] switch is NOT default\n");
		return 1;
	}
  	nexusthread_fork(nxnet_switch_thread, (void *) port_num);
	return 0;
}

