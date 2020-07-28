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

  /** Attach a device to the kernel switch */
  interface void add_mac(const char *mac, int port_num) {
	  nxnet_switch_add(mac, port_num);
  }

  /** Return the system default MAC address */
  interface void get_mac(char *mac) {
	  poke_user(nexusthread_current_map(), (unsigned long) mac, 
		    default_mac_address, 6);
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
  		poke_user(nexusthread_current_map(), (unsigned long) ip, &my_ipaddress, 4);
	if (netmask)
  		poke_user(nexusthread_current_map(), (unsigned long) netmask, &my_netmask, 4);
	if (gateway)
  		poke_user(nexusthread_current_map(), (unsigned long) gateway, &my_gateway, 4);
  }

  /** Request all incoming packets with the given <proto, port> destination */
  interface int filter_ipport(int tcp, unsigned short ipport, int ipcport) {
	  // XXX guard this call
	return nxnet_filter_add_ipport(ipport, ipcport, tcp);
  }

  /** Request all ARP replies or request (depending on @param is_request) */
  interface int filter_arp(int ipcport, int is_request) {
	  // XXX guard this call
  	return nxnet_filter_add_arp(ipcport, is_request);
  }

  /** Request all packets with a given IP protocol*/
  interface int filter_ipproto(int ipcport, int ipproto) {
	  return nxnet_filter_add_ipproto(ipcport, ipproto);
  }

  interface int GetServerIP(char *user_ip, int size) {
    char ip[16], *bin_ip;
    int len;

    bin_ip = getserverip();
    if (!bin_ip)
	    return -1;

    snprintf(ip, 15, "%hu.%hu.%hu.%hu", bin_ip[0] & 0xff, bin_ip[1] & 0xff, 
		    		        bin_ip[2] & 0xff, bin_ip[3] & 0xff);
    len = strlen(ip) + 1;
    if (size < len)
	    return -1;

    if (poke_user(nexusthread_current_map(), (unsigned int) user_ip, ip, len))
      return -1;

    return 0;
  }

  interface int set_l2sec_key(const unsigned char *u_new_key, int key_len) {
    // deprecated. xxx remove
    return -1;
  }
}
