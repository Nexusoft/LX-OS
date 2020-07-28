#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <arpa/inet.h>
extern "C"{
#include <nexus/Net.interface.h>
}

#include "../include/util/ghetto_pcap.h"

/*
 *Router_Enable(1);
 *char packetdata[1500];
 *int real_len = Router_Recv(packetdata, sizeof(packetdata), 1);
 *
 *? : Is the NIC in promiscuous mode. Most likely not.
 *? : Is the Nexus filtering MAC addresses? Maybe. Probably not.
 *
 *filtering happens in the set_multicast
 *8390.c: dev->flags |= IFF_PROMISC
 *
 *Call the "dev->set_multicast_list".
 *
 *After dev initialization, set IFF_PROMISC on dev->flags and call
 *dev->set_multicast_list(dev)
 *
 *(set_rx_mode on 3c59x)
 *
 **init_one is the function called when a matching PCI device is found
 *during a PCI bus scan.
 *
 *----
 *Notes about Linux:
 *flag is passed in via dev_change_flags() (in net/core/dev.c)
 *dev_mc_upload(dev)
 *dev_set_promiscuity()
 *
 */

#if 1
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, const char *errbuff){
  pcap_t *ret = (pcap_t *)malloc(sizeof(pcap_t));
  Net_Router_Enable(1);

  snaplen = 2000;
  
  ret->buff = (u_char *)malloc(snaplen);
  //printf("capture buffer: %0lx\n", ret->buff);

  ret->bufflen = snaplen;
  ret->filter = NULL;

  return ret;
}
int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask){
  fp->filter = (ghetto_filter *)str;
  return 0;
}
char *gcap_addfilter(char *fp, unsigned int ip, unsigned short port){
  ghetto_filter *ret = (ghetto_filter *)malloc(sizeof(ghetto_filter));

  ret->next = (ghetto_filter *)fp;
  ret->ip = ip;
  ret->port = port;

  return (char *)ret;
}
int pcap_setfilter(pcap_t *p, struct bpf_program *fp){
  p->filter = fp->filter;
  return 0;
}

#define WORD(p) (((*(p))<<8)+(*((p)+1)))
#define LONG(p) (((*(p))<<24)+(*((p)+1)<<16)+(*((p)+2)<<8)+(*((p)+3)))
int gcap_checkfilter(ghetto_filter *f, u_char *buff, int len){
  //this entire thing is ghettotastic. -OK

  //printf("checking ip header\n");

  if(WORD(buff+12) != 0x0800) return 0; //not IP
  
  const unsigned char *ip = buff+14;
  int iplen = WORD(ip+2);
  if (ip[9] != 0x06) return 0;  /* not TCP */
  const unsigned char *tcp = ip + (ip[0]&0x0F)*4;
  const unsigned char *data = tcp + ((tcp[12]&0xF0)>>4)*4;
  unsigned int seq = LONG(tcp+4);
  unsigned int dlen = iplen - (data-ip);
  if (dlen == 0) return 0;   /* ACK or other empty packet */
  assert(dlen > 0);

  //printf("extracting relevant numbers\n");

  unsigned short from_port = WORD(tcp);
  unsigned short to_port = WORD(tcp+2);
  unsigned long from_addr = LONG(ip+12);
  unsigned long to_addr = LONG(ip+16);

//  printf("Checking filter list: %d->%d\n", from_port, to_port);

  while(f != NULL){
//    printf("Filter: %d\n",ntohs(f->port));
    if((f->port == from_port)||(f->port == to_port)){
      if((f->ip == from_addr)||(f->ip == to_addr)){
//	printf("success!\n");
	return 1;
      }
    }
    f = f->next;
  }
  //printf("failure!\n");
  return 0;
}

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user){
  pcap_pkthdr header;
  struct timezone tz;

  //assert(cnt == 1); //changing this makes things messy, and I want this done tonight -OK

  int len = Net_Router_Recv((char *)p->buff, p->bufflen, 1);

  //printf("Got a packet \n");

  if(len < 0) {
    printf("Boom: len = %d/%d @ %p\n", len, p->bufflen, p->buff);
    printf("mem0\n");
    p->buff[0] = 0xff;
    printf("mem1\n");
    p->buff[p->bufflen - 1] = 0xa0;
    printf("mem2\n");
  }
  assert(len >= 0); //this should be handled more gracefully, but eh... -OK

  // gettimeofday(&header.ts, &tz);
  header.len = len;
  header.caplen = len; //the nexus router code doesn't let us get partial reads -OK
  
  if(gcap_checkfilter(p->filter, p->buff, len)){
    //printf("Calling callback\n");
    callback(user, &header, p->buff);
  }
  //printf("Back from callback\n");

  return 0;
}
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user){
  p->loop = 1;
  while(p->loop){
    pcap_dispatch(p, cnt, callback, user);
  }
  return 0;
}
int pcap_stats(pcap_t *p, pcap_stat *ps){
  ps->ps_recv = 0;
  ps->ps_drop = 0;
  ps->ps_ifdrop = 0;
  return 0;
}
void pcap_breakloop(pcap_t *p){
  printf("aborting loop\n");
  p->loop = 0;
}
#else
void pcap_get_error(char *buf, pcap_error_type err){}
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, const char *errbuff){}
int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask){}
int pcap_setfilter(pcap_t *p, struct bpf_program *fp){}
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user){}
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user){}
int pcap_stats(pcap_t *p, struct pcap_stat *ps){}
void pcap_breakloop(pcap_t *p){}
char *gcap_addfilter(char *fp, unsigned int ip, unsigned short port){}

#endif
