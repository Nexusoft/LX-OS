#define ETHER_ADDR_LEN 6
#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <assert.h>

#include "bgp.h"
#include "bgpcheck.h"
#include "overlay.h"
#include "cap-passive.h"
#include "nbgp.h"

//these defines and structs liberally stolen from the pcap tutorial 
//(http://www.tcpdump.org)
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN];
  u_char ether_shost[ETHER_ADDR_LEN];
  u_short ether_type;
};

#define SNIFF_ETHERNET_SZ (ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2)

struct sniff_ip {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;		/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


/* TCP header */
struct sniff_tcp {
  u_short th_sport;	/* source port */
  u_short th_dport;	/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */

  u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};


void discard_bytes(bc_pcap_server *server, int going_in, int count){
  bc_pcap_data *temp;

#ifdef PRINT_DEBUG_CAPTURE
  printf("Discarding %d bytes\n", count);
#endif

  while(count > 0){
    if(server->data[going_in]->len - server->offset[going_in] > count){
      //			printf("Single packet discard: %d\n", count);
      server->offset[going_in] += count;
      count = 0;
    } else {
      //			printf("Total packet discard: %d\n", server->data[going_in]->len);
      temp = server->data[going_in];
      server->data[going_in] = temp->next;
      count -= temp->len - server->offset[going_in];
      server->seqno[going_in] = temp->seqno + temp->len;
      server->offset[going_in] = 0;
      free(temp);
    }
  }
}

int find_start(bc_pcap_server *server, int going_in){
  int count = 0, discarded = -16;
  int pos = server->offset[going_in];
  bc_pcap_data *curr = server->data[going_in];

  //BGP specifies a 16 byte message header that is typically
  //composed of 16 bytes of (char)255;

  while(curr != NULL){
    while(pos < curr->len){
      if(((unsigned char)curr->data[pos]) == 0xFF){
	count ++;
      } else {
	count = 0;
      }
      if(count >= 16){
	return discarded;
      }
      discarded ++;
      pos++;
    }
    pos = 0;
    curr = curr->next;
  }
  return 0;
}

void check_data(bc_pcap_server *server, int going_in, bc_pcap_info *info){
  int count = 0, totalcount = 0, i, read;
  bc_pcap_data *curr = server->data[going_in];
  bgp_datasource data;
  unsigned int seqno = server->seqno[going_in];
  bgp_packet packet;

#ifdef PRINT_DEBUG_CAPTURE
  printf("Counting ready packets\n");
#endif

  while((curr != NULL) && ((seqno == 0) || (seqno == curr->seqno))){
    seqno = curr->seqno + curr->len;
    count++; 
    curr = curr->next;
  }
  totalcount = count;
  while(curr != NULL){
    totalcount ++;
    curr = curr->next;
  }

  if(totalcount-count > 20){ 
    // if this is true, we've got packets missing from the front of the
    // packet queue.  Assume we never got them.
    server->seqno[going_in] = 0;
    while(server->data[going_in] != NULL){
      curr = server->data[going_in];
      //server->data[going_in] = curr->next;
#ifdef PRINT_DEBUG_CAPTURE
      printf("======= EXPLODED: MISSING PACKETS =======\n");
      printf("%s: ", going_in?"source":"destination");
      bgp_print_ip(server->ip);
      printf(" (%u)\n", server->as);
      bgp_print_hex(curr->data, curr->len);
#endif
      nbgp_missing_packets(server->as, curr->seqno - server->offset[going_in], going_in);
      server->offset[going_in] = 0;
      //free(curr);
    }
    return;
  }

  
  if(count > 15){
    // The BGP parser will return with an exception-like message if it tries to
    // read a packet that's larger than the buffer we give it.  If this happens
    // we just return and wait for another packet to show up.  At some point 
    // however, we have to accept the possibility that either the packet has
    // a corrupt length field or that the parser exploded somehow.  If this happens
    // we drop the packet at the head of the queue and try again.  
    server->seqno[going_in] = 0;
    curr = server->data[going_in];
    server->data[going_in] = curr->next;
#ifdef PRINT_DEBUG_CAPTURE
    printf("======= EXPLODED: FAILED CHECKS =======\n");
    printf("%s: ", going_in?"source":"destination");
    bgp_print_ip(server->ip);
    printf(" (%u)\n", server->as);
    printf("seq #: %u, len: %u\n", curr->seqno, curr->len);
    bgp_print_hex(&(curr->data[server->offset[going_in]]), curr->len - server->offset[going_in]);
    if(curr->next != NULL){
      printf(" - next field - \n");
      printf("seq #: %u, len: %u\n", curr->next->seqno, curr->next->len);
      bgp_print_hex(curr->next->data, curr->next->len);
    }
#endif
    nbgp_oversized_message(server->as, curr->len - server->offset[going_in], going_in);
    free(curr);
    server->offset[going_in] = 0;
    //if we don't recurse at least once, we'll end up with a count of 10
    //the next time we get a packet and call this function.  This recursion
    //will not be infinite because we remove a packet every time we 
    //recurse, so eventually it will end up being less than 10.
    check_data(server, going_in, info);
    return;		
  }

#ifdef PRINT_DEBUG_CAPTURE
  printf("Ready to process %d/%d packets (expected seq #: %u, next seq #: %u)\n", count, totalcount, server->seqno[going_in], (unsigned int)server->data[going_in]->seqno);
#endif

  if(count < 1){
    return;
  }

  data.contents.vector.buff = alloca(count * sizeof(char *));
  data.contents.vector.len = alloca(count * sizeof(int *));
  data.contents.vector.bcursor = 0;
  data.contents.vector.cursor = server->offset[going_in];
  data.contents.vector.blen = count;
  data.type = BGP_VECTOR;
  data.error = 0;
  curr = server->data[going_in];

#ifdef PRINT_DEBUG_CAPTURE
  printf("---\n");
#endif
  for(i = 0; i < count; i++){
#ifdef PRINT_DEBUG_CAPTURE
    printf("Seq #:%u / %u\n", curr->seqno, curr->len);
    //		bgp_print_hex(curr->data, curr->len);
#endif
    data.contents.vector.buff[i] = curr->data;
    data.contents.vector.len[i] = curr->len;
    curr = curr->next;
  }

#ifdef PRINT_DEBUG_CAPTURE
  printf("Passing packet to %s\n", going_in?"monitor":"verifier");
#endif

  while((data.contents.vector.bcursor < count) && 
	((data.contents.vector.bcursor < (count - 1)) || 
	 (data.contents.vector.cursor < data.contents.vector.len[count-1]))){
    read = bgp_read_packet(&data, &packet);
    if(data.error){
      //something bad happened, let's find out what
      if(data.error & DEBUG_FORMAT){
	//there was a parser error... somehow we got a corrupted packet
	server->seqno[going_in] = 0;
	curr = server->data[going_in];
	server->data[going_in] = curr->next;
#ifdef PRINT_DEBUG_CAPTURE
	printf("======= EXPLODED: MALFORMED PACKET =======\n");
	printf("%s: ", going_in?"source":"destination");
	bgp_print_ip(server->ip);
	printf(" (%u)\n", server->as);
	printf("seq #: %u, len: %u\n", curr->seqno, curr->len);
	bgp_print_hex(&(curr->data[server->offset[going_in]]), curr->len - server->offset[going_in]);
	if(curr->next != NULL){
	  printf(" - next field - \n");
	  printf("seq #: %u, len: %u\n", curr->next->seqno, curr->next->len);
	  bgp_print_hex(curr->next->data, curr->next->len);
	}
#endif
	nbgp_malformed_message(server->as, curr->len - server->offset[going_in], going_in);
	free(curr);
	server->offset[going_in] = 0;
      } else if(data.error & DEBUG_DATA) {
	//we don't have enough data to fully parse the packet
	//don't do anything until we get more data
      }
      return;
    } else {
      assert(read > 0);
      if(going_in){
	//discard packet validity data, we can't do jack about it
	nbgp_incoming_packet(server->parser, info->overlay, &packet, server->as, server->ip);
      } else {
	nbgp_outgoing_packet(server->parser, info->overlay, &packet, server->as, server->ip);
      }
      bgp_cleanup_packet(&packet);
      discard_bytes(server, going_in, read);
    }
  }
}

void insert_packet(u_char *pdata, int len, unsigned int seqno, bc_pcap_server *server, int going_in, bc_pcap_info *info){
  bc_pcap_data *newdata;
  bc_pcap_data *curr;

  if(seqno < server->seqno[going_in]){
#ifdef PRINT_DEBUG_CAPTURE
    printf("discarding already seen %s packet (sequence # %u; %d bytes)\n", going_in?"incoming":"outgoing", seqno, len);
#endif
    return;
  }

  newdata = malloc(BC_PCAP_DATALEN(len));

#ifdef PRINT_DEBUG_CAPTURE
  printf("inserting %s packet (sequence # %u; %d bytes)\n", going_in?"incoming":"outgoing", seqno, len);
#endif

  if(newdata == NULL){
    printf("Error: out of memory\n");
  }

  newdata->seqno = seqno;
  newdata->len = len;
  newdata->next = NULL;
  memcpy(newdata->data, pdata, len);

  if(server->data[going_in] == NULL){
    //  	printf("queue empty\n");
    server->data[going_in] = newdata;
  } else {
    //  	printf("queue not empty:");
    if(server->data[going_in]->seqno > seqno){
      //    	printf("earlier packet\n");
      newdata->next = server->data[going_in];
      server->data[going_in] = newdata;
    } else if(server->data[going_in]->seqno == seqno){
      //drop the packet
    } else {
      //    	printf("later packet\n");
      curr = server->data[going_in];
      while((curr->next != NULL) && (curr->next->seqno < seqno )){
	curr = curr->next;
      }
      if((curr->next == NULL) || (curr->next->seqno != seqno)){
	newdata->next = curr->next;
	curr->next = newdata;
      }
    }
  }
#ifdef PRINT_DEBUG_CAPTURE
  printf("Insertion complete\n");
#endif
  /*  
      normally we'd parse the data here, but that may not be such a good idea
      We're losing a lot of data to the initial burst of traffic a bgp client sees
      as soon as it starts up.  BGP is however, bursty so I'm going to move
      this line down to bc_check_data().  Calling it only if there aren't any packets
      arriving should do the trick.  -OK
  */
  info->read_packet = 1;
  //  check_data(server, going_in, info);

}

bc_pcap_server *create_peer(int ip, int peer_as, int capport, int my_as){
  bc_pcap_server *server;

  server = malloc(sizeof(bc_pcap_server));
  server->ip = ip;
  server->as = peer_as;
  server->port = capport;
  server->seqno[0] = server->seqno[1] = 0;
  server->offset[0] = server->offset[1] = 0;
  server->data[0] = server->data[1] = NULL;
  server->next = NULL;
  server->parser = bc_create_data(peer_as, my_as);
  return server;
}

void bc_add_peer(int ip, int peer_as, int my_as, int capport, bc_pcap_info *info){
  bc_pcap_server *server = create_peer(ip, peer_as, capport, my_as);
  server->next = info->peers;
  info->peers = server;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  bc_pcap_info *info = (bc_pcap_info *)args;
  int sz_ip, sz_tcp, sz_payload;
  struct sniff_ethernet *enet_hdr;
  struct sniff_ip *ip_hdr = NULL;
  struct sniff_tcp *tcp_hdr = NULL;
  const u_char *pdata = NULL;
  bc_pcap_server *server;
  unsigned int src, dst;

  //printf("sniffed!\n");

  pdata = packet;
  enet_hdr = (struct sniff_ethernet *)pdata;

  pdata += SNIFF_ETHERNET_SZ;
  ip_hdr = (struct sniff_ip *)pdata;

  sz_ip = IP_HL(ip_hdr) * 4;
  pdata += sz_ip;
  tcp_hdr = (struct sniff_tcp *)pdata;

  sz_tcp = TH_OFF(tcp_hdr) * 4;
  pdata += sz_tcp;

#ifdef PRINT_DEBUG_CAPTURE
  printf("Got packet (%d bytes; seq # %u)\n", header->caplen, tcp_hdr->th_seq);
#endif

  if(header->caplen < header->len){
    fprintf(stderr, "WARNING: PCAP GOT PACKET THAT EXCEEDS ITS BUFFER: %d / %d bytes actually read\n", header->caplen, header->len);
  }

  //payload size is the packet size - the headers and the 4 byte checksum
  //sz_payload = header->caplen - SNIFF_ETHERNET_SZ - sz_ip - sz_tcp - 4;
  //WRONG!  payload size is defined in the IP header, adjusted for ip and tcp header sizes
  sz_payload = ntohs(ip_hdr->ip_len) - sz_ip - sz_tcp;
  printf("PACKET\t%u\t%u\t%d\t%u\t%u\n", ip_hdr->ip_src.s_addr, ip_hdr->ip_dst.s_addr, header->caplen, ntohl(tcp_hdr->th_seq), sz_payload);
  return;


#ifdef PRINT_DEBUG_CAPTURE
  printf("%d bytes of ethernet header, %d bytes of ip header, %d bytes of tcp header\n", SNIFF_ETHERNET_SZ, sz_ip, sz_tcp);

  //bgp_print_hex((char *)packet, header->caplen);
#endif

  if(sz_payload > 0){ //make sure it's not an ack
    src = ntohl(ip_hdr->ip_src.s_addr);
    dst = ntohl(ip_hdr->ip_dst.s_addr);
    
    if(src == info->serverIP){
      server = info->peers;
      while(server != NULL){
	if(server->ip == dst){
	  break;
	}
	server = server->next;
      }
      if(server == NULL){
#ifdef PRINT_DEBUG_CAPTURE
	printf("Found new outgoing server\n");
#endif
#ifdef SPONTANEOUS_SERVER
	server = create_peer(dst, 0, 0, 179);
	server->next = info->peers;
	info->peers = server;
#else
#ifdef PRINT_DEBUG_CAPTURE
	printf("WARNING: MONITORED HOST SENT TRAFFIC TO A NON-CONFIGURED PEER (");
	bgp_print_ip(ip_hdr->ip_dst.s_addr);
	printf(")\n");
#endif
	nbgp_invalid_peer(dst, 0);
	return;
#endif
      } 
#ifdef PRINT_DEBUG_CAPTURE
      else {
    	printf("Found existing outgoing server\n");
      }
#endif
      insert_packet((u_char *)pdata, sz_payload, ntohl(tcp_hdr->th_seq), server, 0, info);
    } else if(dst == info->serverIP){
      server = info->peers;
      while(server != NULL){
	if(server->ip == src){
	  break;
	}
	server = server->next;
      }
      if(server == NULL){
#ifdef PRINT_DEBUG_CAPTURE
	printf("Found new incoming server\n");
#endif
#ifdef SPONTANEOUS_SERVER
	server = create_peer(src, 0, 0, 179);
	server->next = info->peers;
	info->peers = server;
#else
#ifdef PRINT_DEBUG_CAPTURE
	printf("WARNING: MONITORED HOST RECEIVED TRAFFIC FROM A NON-CONFIGURED PEER (");
	bgp_print_ip(src);
	printf(")\n");
#endif
	nbgp_invalid_peer(src, 1);
	return;
#endif
      }
#ifdef PRINT_DEBUG_CAPTURE
      else {
    	printf("Found existing incoming server\n");
      }
#endif
      insert_packet((u_char *)pdata, sz_payload, ntohl(tcp_hdr->th_seq), server, 1, info);
    }
#ifdef PRINT_DEBUG_CAPTURE
    else {
      printf("discarding packet from ");
      bgp_print_ip(src);
      printf(" to ");
      bgp_print_ip(dst);
      printf(" (I want ");
      bgp_print_ip(info->serverIP);
      printf(")\n");
    }
  } else {
    printf("discarding TCP control packet\n");
#endif  	
  }
}

bc_pcap_info *bc_passive_init(char *device, bol_info *olinfo){
  bc_pcap_info *info = malloc(sizeof(bc_pcap_info));
  char errbuff[PCAP_ERRBUF_SIZE];

  //this should set all the pointers to null
  bzero(info, sizeof(bc_pcap_info));

  if(device != NULL){
    info->handle = pcap_open_offline(device, errbuff);
  } else {
    device = pcap_lookupdev(errbuff);
    if(device == NULL){
      fprintf(stderr, "ERROR: No device given and couldn't find default device: %s\n", errbuff);
      exit(1);
    }
    printf("Inititalizing scan on %s\n", device);

    if(pcap_lookupnet(device, &info->net, &info->mask, errbuff) == -1){
      fprintf(stderr, "ERROR: Couldn't get netmask for device: %s\n", errbuff);
      exit(1);
    }

    //1024*64 = 2^16 = maximum IP packet size
    info->handle = pcap_open_live(device, 1024 * 64 + SNIFF_ETHERNET_SZ, 1, 1000, errbuff);
    //info->handle = pcap_open_live(device, 96, 1, 1000, errbuff);
  }

  if(info->handle == NULL){
    fprintf(stderr, "ERROR: Couldn't open device: %s\n", errbuff);
    exit(1);
  }

  info->overlay = olinfo;

  return info;
}

int bc_set_select_fd(bc_pcap_info *info, fd_set *set, fd_set *exception){
  int fd = pcap_get_selectable_fd(info->handle);

  FD_SET(fd, set);
  return fd;
}

void bc_check_data(bc_pcap_info *info, fd_set *set, fd_set *exception){
//	if(FD_ISSET(pcap_get_selectable_fd(info->handle)){

  /*
    according to the pcap docs, there's a bug in most BSDs
    (including the one I'm testing this on) where select() doesn't
    necessarilly detect the presence of data in a promiscuous socket.
    As a result we don't bother to check if the socket descriptor is
    in the ready list.  -OK
  */

  /*
    This -1 here signals that we should process all the packets in one
    pcap buffer... this scares me a little.  There might be an
    incomplete packet at the end of that buffer.  If we start getting
    strange malformed packets, this'd be the place to look. -OK
    
    fortunately, that doesn't seem to ever happen. -OK
  */

  info->read_packet = 0;
  pcap_dispatch(info->handle, -1, &got_packet, (unsigned char *)info);
  if(!info->read_packet){
    /*
       optimization trickery alert...
       the pcap code is dropping packets like crazy during the initial burst.
       this means we need to speed up packet processing.  BGP is incredibly
       bursty, so we can just allocate a bunch of memory to store a bunch of 
       packets incoming, and then clean up after ourselves once we have a chance
       to catch our breath.  We should get called here if a packet fails to arrive
       within 500ms of the last one.  That should be enough leeway.
    */
    bc_pcap_server *server = info->peers;
    for(; server != NULL; server = server->next){
      check_data(server, 0, info);
      check_data(server, 1, info);
    }
  }

//	}
}

void bc_set_my_ip(bc_pcap_info *info, int ip, int port){
  info->serverIP = ip;
  info->serverPort = port;
}

void bc_install_filter(bc_pcap_info *info){
  char *filter_exp, *cursor;
  int peer_count = 0;
  bc_pcap_server *curr;
  unsigned int ip;
  char errbuff[PCAP_ERRBUF_SIZE];  

  for(curr = info->peers; curr != NULL; curr = curr->next){
    peer_count++;
  }

  filter_exp = malloc(sizeof(char) * 110 * (peer_count + 1));

  cursor = filter_exp;

  for(curr = info->peers; curr != NULL; curr = curr->next){
    ip = curr->ip;
    cursor += snprintf(cursor, 110, 
		       "((src host %u.%u.%u.%u)&&(src port %u))||((dst host %u.%u.%u.%u)&&(dst port %u))||\n",
		       (ip >> 24)&0xFF,(ip >> 16)&0xFF,(ip >> 8)&0xFF,(ip >> 0)&0xFF,
		       curr->port,
		       (ip >> 24)&0xFF,(ip >> 16)&0xFF,(ip >> 8)&0xFF,(ip >> 0)&0xFF,
		       curr->port);
  }
  ip = info->serverIP;
  cursor += snprintf(cursor, 110, 
		     "((src host %u.%u.%u.%u)&&(src port %u))||((dst host %u.%u.%u.%u)&&(dst port %u))",
		     (ip >> 24)&0xFF,(ip >> 16)&0xFF,(ip >> 8)&0xFF,(ip >> 0)&0xFF,
		     info->serverPort,
		     (ip >> 24)&0xFF,(ip >> 16)&0xFF,(ip >> 8)&0xFF,(ip >> 0)&0xFF,
		     info->serverPort);

  printf("Installing filter: \n%s\n", filter_exp);

  if(pcap_compile(info->handle, &info->fp, "port 179"/*filter_exp*/, 0, info->net) == -1){
    fprintf(stderr, "ERROR: Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(info->handle));
    exit(1);
  }
  if(pcap_setfilter(info->handle, &info->fp) == -1){
    fprintf(stderr, "ERROR: Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(info->handle));
    exit(1);
  }
  if(pcap_setnonblock(info->handle, 1, errbuff) == -1){
    fprintf(stderr, "ERROR: Can't switch pcap to nonblocking mode: %s\n", errbuff);
    exit(1);
  }

  free(filter_exp);

}
