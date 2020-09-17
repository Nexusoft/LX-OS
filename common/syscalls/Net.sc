syscall Net {
  
  decls __callee__ {
    includefiles { "<nexus/defs.h>", "<nexus/ipc.h>" }
    includefiles { "<nexus/thread.h>" }
    includefiles { "<nexus/machineprimitives.h>" }
    includefiles { "<nexus/syscall-private.h>" }

    includefiles { "<nexus/queue.h>" }
    includefiles { "<nexus/synch.h>" }
    includefiles { "<nexus/synch-inline.h>" }
    includefiles { "<nexus/net.h>" }
    includefiles { "<nexus/clock.h>" }
    includefiles { "<linux/skbuff.h>" }
    includefiles { "<nexus/rdtsc.h>" }
    includefiles { "<nexus/net.h>" }

  }

  decls __caller__ {
    includefiles { "<nexus/net.h>" }
  }

  /** Give exclusive (<- XXX ENFORCE) ownership of a port to a process.
      @param portnumber is a port in host byte order
             or 0 to dynamically assign a port
      @param return the portnumber on success or -1 on failure 
   */
  interface int port_get(int portnumber) {
  	static int dynamic_port = 20000;

	if (portnumber)
		// XXX protect exclusive ownership
		return portnumber;
	else
		return dynamic_port++;
  }

  /** Attach a device to the kernel switch */
  interface void add_mac(const char *mac, int port_num) {
	  nxnet_switch_add(mac, port_num);
  }

  /** Return the system default MAC address */
  interface void get_mac(char *mac) {
	  memcpy(mac, default_mac_address, 6);
  }

  /** Set the system default IP address, gateway and netmask.
      All parameters are in NETWORK byteorder */
  interface void set_ip(unsigned int ip,
		  	unsigned int netmask,
			unsigned int gateway) {
	  // XXX guard this call

	  memcpy(&my_ipaddress, &ip, 4);
	  memcpy(&my_netmask, &netmask, 4);
	  memcpy(&my_gateway, &gateway, 4);

	  nxcompat_printf("[net] received address %02hu.%02hu.%02hu.%02hu\n",
                          ip & 0xff, 
			  (ip >>  8) & 0xff, 
			  (ip >> 16) & 0xff, 
			  (ip >> 24) & 0xff);
  }

  /** Learn the system default IP address, gateway and netmask.
      All parameters are in NETWORK byte order */
  interface void get_ip(unsigned int *ip, 
		  	unsigned int *netmask, 
			unsigned int *gateway) {
	if (ip)
  		poke_user(curr_map, (unsigned long) ip, &my_ipaddress, 4);
	if (netmask)
  		poke_user(curr_map, (unsigned long) netmask, &my_netmask, 4);
	if (gateway)
  		poke_user(curr_map, (unsigned long) gateway, &my_gateway, 4);
  }

  /** Request all incoming packets with the given <proto, port> destination 
      @return 0 on success, -1 on failure */
  interface int filter_ipport(int tcp, unsigned short ipport, int ipcport) {
	  // XXX guard this call
	  return nxnet_filter_add_ipport(ipport, ipcport, tcp);
  }

  /** Request all ARP replies or request (depending on @param is_request) 
      @return 0 on success, -1 on failure */
  interface int filter_arp(int ipcport, int is_request) {
	  // XXX guard this call
	  return nxnet_filter_add_arp(ipcport, is_request);
  }

  /** Request all packets with a given IP protocol*/
  interface int filter_ipproto(int ipcport, int ipproto) {
	  return nxnet_filter_add_ipproto(ipcport, ipproto);
  }

  /** Send a packet to the network switch */
  interface void vrouter_to(unsigned long page, int plen) {
	  nxnet_vrouter_to((char *) page, plen);
  }

  /** Wait on the kernel for a page to transmit */
  interface int 
  vrouter_from(int port, unsigned long _page, 
	       unsigned long _paddr, unsigned long proto) 
  {
	  char **page = (void *) _page; // stupid IDL does not support **
	  char **paddr = (void *) _paddr;
	  int ret;

	  if (!page)
		  return -1;

	  return nxnet_vrouter_from(port, page, paddr, (int *) proto);
  }

  /** Wait on the kernel for a page to transmit */
  interface int 
  vrouter_from_blind(int port, unsigned long _page, 
	             unsigned long _paddr, unsigned long proto, int hw_pseudo) 
  {
	  int nxnet_checksum_prepare(char *frame, int do_pseudo);
	  char **page = (void *) _page; // stupid IDL does not support **
	  char **paddr = (void *) _paddr;
	  int ret;

	  if (!page)
		  return -1;

	  ret = nxnet_vrouter_from(port, page, paddr, (int *) proto);

	  if (ret > 0) {
#if NXCONFIG_DEVICE_BLIND
		// set mapping to kernel only
		PageTableEntry *pte;
		pte = fast_virtToPTE(curr_map, (unsigned long) *page, 1, 0);
		if (pte) 
			pte->user = 0;

		nxnet_checksum_prepare(*page, hw_pseudo);
#endif
	  }

	  return ret;
  }
}

