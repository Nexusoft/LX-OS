/** NexusOS: TCP/IP checksumming 
    Main routines taken from lwip */

#ifdef __NEXUSKERNEL__
#include <linux/types.h>
#include <nexus/net.h>
#else
#include <stdint.h>
#include <arpa/inet.h>
#include <nexus/packet_headers.h>
#endif

#include <nexus/defs.h>

#define SWAP_BYTES_IN_WORD(w) htons(w)
#define FOLD32(u)          ((u >> 16) + (u & 0x0000ffffUL))

#define U16(x)	(*((uint16_t *) x))

static uint16_t
lwip_standard_chksum(void *dataptr, int len)
{
  uint8_t *pb = dataptr;
  uint16_t *ps, t = 0;
  uint32_t *pl;
  uint32_t sum = 0, tmp;
  /* starts at odd byte address? */
  int odd = ((uint32_t)pb & 1);

  if (odd && len > 0) {
    ((uint8_t *)&t)[1] = *pb++;
    len--;
  }

  ps = (uint16_t *)pb;

  if (((uint32_t)ps & 3) && len > 1) {
    sum += *ps++;
    len -= 2;
  }

  pl = (uint32_t *)ps;

  while (len > 7)  {
    tmp = sum + *pl++;          /* ping */
    if (tmp < sum) {
      tmp++;                    /* add back carry */
    }

    sum = tmp + *pl++;          /* pong */
    if (sum < tmp) {
      sum++;                    /* add back carry */
    }

    len -= 8;
  }

  /* make room in upper bits */
  sum = FOLD32(sum);

  ps = (uint16_t *)pl;

  /* 16-bit aligned word remaining? */
  while (len > 1) {
    sum += *ps++;
    len -= 2;
  }

  /* dangling tail byte remaining? */
  if (len > 0) {                /* include odd byte */
    ((uint8_t *)&t)[0] = *(uint8_t *)ps;
  }

  sum += t;                     /* add end bytes */

  /* Fold 32-bit sum to 16 bits
     calling this twice is propably faster than if statements... */
  sum = FOLD32(sum);
  sum = FOLD32(sum);

  if (odd) {
    sum = SWAP_BYTES_IN_WORD(sum);
  }

  return sum;
}

/** Checksum only the pseudoheader component of the TCP/UDP checksums
    HW checksum offload may require this to be precalculated.  */
static uint32_t
nxnet_csum_pseudo(char *unused, int unusedlen,
		  uint32_t src_addr, uint32_t dst_addr,
		  uint16_t ip_proto, uint16_t tot_len)
{
  return (src_addr & 0xffff) +
         ((src_addr >> 16) & 0xffff) +
  	 (dst_addr & 0xffff) +
  	 ((dst_addr >> 16) & 0xffff) +
  	 htons(ip_proto) +	// htons is NOT a mistake: treat as 16bit (little endian specific hack)
 	 htons(tot_len);
}

/** Clear checksum field
    HW checksum offload may require this instead of pseudoheader calculation */
static uint32_t
nxnet_csum_null(char *unsed, int unusedlen,
		uint32_t a, uint32_t b,
		uint16_t c, uint16_t d)
{
  return 0;
}

/** Checksum
    @param ip_proto is the transport layer protocol number
    @param tot_len is the length of the TCP/UDP pseudo header + payload */
static uint32_t
nxnet_csum_tcpudp(char *transheader, int thlen,
	          uint32_t src_addr, uint32_t dst_addr,
		  uint16_t ip_proto, uint16_t tot_len)
{
  uint32_t sum;
  struct pbuf *q;
  uint8_t swapped;

  // checksum pseudoheader
  sum = nxnet_csum_pseudo(NULL, 0, src_addr, dst_addr, ip_proto, tot_len);

  // checksum payload
  sum += lwip_standard_chksum(transheader, thlen);
  
  // fold carry bit into 16bit sum
  sum = (sum & 0xffff) + (sum >> 16);

  // calculate one's complement
  return ~sum & 0xffff;
}

/** Calculate one's complement checksum over a memory region */
uint16_t
nxnet_checksum_basic(void *data, int len)
{
  return ~lwip_standard_chksum(data, len);
}

/** Shared version of checksum generate and verify 
    @param verify toggles whether to verify against existing checksum field

    XXX remove code duplication between TCP and UDP */
static int
__nxnet_checksum(int verify, char *frame, uint32_t(*fn)(char *, int, 
			                    uint32_t, uint32_t, 
					    uint16_t, uint16_t))
{
	PktEther *eth;
	PktIp *iph;
	PktUdp *udph;
	PktTcp *tcph;
	uint32_t csum_prefold;
	uint16_t csum_bak, thlen;
	uint8_t iphlen;

	eth = (void *) frame;
	if (*((uint16_t *) eth->proto) != htons(ETHER_PROTO_IP))
		return 0;

	// network layer: never offloaded
	iph = (void *) frame + sizeof(PktEther);
	iphlen = (iph->vihl & 0xf) << 2;
	csum_bak = U16(iph->hdrcsum);
	U16(iph->hdrcsum) = 0;
	U16(iph->hdrcsum) = nxnet_checksum_basic(iph, iphlen);
	if (verify && csum_bak != U16(iph->hdrcsum)) {
		U16(iph->hdrcsum) = csum_bak;
		return 1;
	}

	// transport layer
	thlen = ntohs(U16(iph->len)) - iphlen;
	if (iph->proto == IP_PROTO_UDP) {
		udph = (void *) ((char *) iph) + iphlen;
		csum_bak = U16(udph->csum);

		// UDP without checksums is allowed
		if (verify && csum_bak == 0)
			return 0;

		// create checksum (full or pseudo)
		U16(udph->csum) = 0;
		csum_prefold = fn((char *) udph, thlen, 
				  *(uint32_t *) iph->src, *(uint32_t *) iph->dst, 
				  iph->proto, thlen);
	
		// use checksum (verify or apply)
		if (verify) {
#ifdef __NEXUSKERNEL__
			if (csum_prefold > 0xffff)
				nexuspanic();
#endif
			if (csum_bak != csum_prefold) 
				return 1;
		}
		else
			U16(udph->csum) = (csum_prefold >> 16) + (csum_prefold & 0xffff);
	}
	else if (iph->proto == IP_PROTO_TCP) {
		tcph = (void *) ((char *) iph) + iphlen;
		csum_bak = U16(tcph->csum);
		
		// create checksum (full or pseudo)
		U16(tcph->csum) = 0;
		csum_prefold = fn((char *) tcph, thlen, 
				  *(uint32_t *) iph->src, *(uint32_t *) iph->dst, 
				  iph->proto, thlen);

		// use checksum (verify or apply)
		if (verify) {
			// carry already taken care of by nxnet_csum_tcpudp
#ifdef __NEXUSKERNEL__
			if (csum_prefold > 0xffff)
				nexuspanic();
#endif
			if (csum_bak != csum_prefold)
				return 1;
		}
		else
			// carry not taken care of by  nxnet_csum_pseudo
			U16(tcph->csum) = (csum_prefold >> 16) + (csum_prefold & 0xffff);
	}

	return 0;
}

/** Checksum IPv4 and TCP/UDP headers 
    @return 0 if passes all required tests (if any), 1 if fails 
            checksum fields are updated to our calculation */
int
nxnet_checksum_generate(char *frame)
{
	return __nxnet_checksum(0, frame, (void *) nxnet_csum_tcpudp);
}

int
nxnet_checksum_verify(char *frame)
{
	return __nxnet_checksum(1, frame, (void *) nxnet_csum_tcpudp);
}

/** Setup the checksum fields for hardware accelerated checksumming */
int
nxnet_checksum_prepare(char *frame, int do_pseudo)
{
// correct version depends on hardware:
// Broadcom chips do not need pseudo, but Intel Pro/1000 does
if (do_pseudo)
	return __nxnet_checksum(0, frame, (void *) nxnet_csum_pseudo);
else
	return __nxnet_checksum(0, frame, (void *) nxnet_csum_null);
}

