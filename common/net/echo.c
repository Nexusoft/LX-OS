/** NexusOS: generate a UDP echo reply (for benchmarking) 
 
    built to work with user/apps/net/echo_client */

/** @return 1 if packet was taken over and should be transmitted */
int
nxnet_echoreply(char *page)
{
	uint32_t *iph;
	uint32_t addr;
	uint16_t *udph;
	uint16_t port;
	char mac[6];
	iph  = (void *) (page + 14);
	udph = (void *) (page + 34);

	if (ntohs(*(uint16_t *)(page + 12)) == 0x0800 &&
	    page[14 + 9] == 17 &&
	    ntohs(udph[1]) == 8000) {

		// swap udp
		port = udph[1];
		udph[1] = udph[0];
		udph[0] = port;

		// swap ip
		addr = iph[4];
		iph[4] = iph[3];
		iph[3] = addr;

		// swap eth
		memcpy(mac, page, 6);
		memcpy(page, page + 6, 6);
		memcpy(page + 6, mac, 6);
	
		return 1;	
	}

	return 0;
}

