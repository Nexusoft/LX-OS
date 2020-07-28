#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include "../include/util/ghetto_pcap.h"
#include "../include/util/g_tl.h"
#include "../include/runtime/minipipe.h"
#include "../include/util/reassemble.h"
#include "../include/util/common.h"
#include "../include/util/safe_malloc.h"

static Ghetto_Vector flows(10);

static pcap_t *pcap;

static void cb_output(const Flow &flow, const unsigned char *data, int len);
static void cb_gap(const Flow &flow, int len);
static void handle_packet(unsigned char *user, const struct pcap_pkthdr *hdr, const unsigned char *eth);

Minipipe *reassemble_output;

void reassemble_main(reassemble_params *params) {
  char errbuf[PCAP_ERRBUF_SIZE];
  //pcap_t *pcap;

  printf("Setting up pcap\n");

  pcap = pcap_open_live(params->device, 4096, 1, 1000, errbuf);
  if (!pcap) {
    //fprintf(stderr, "pcap_open_live: %s\n", errbuf);
    exit(1);
  }
  if (params->filter) {
    struct bpf_program bpf;
    if (pcap_compile(pcap, &bpf, (char *)params->filter, 1, 0) == -1) {
      //fprintf(stderr, "pcap_compile: %s\n", errbuf);
      exit(1);
    }
    if (pcap_setfilter(pcap, &bpf) == -1) {
      //fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
      exit(1);
    }
  }

  reassemble_output = params->pipe;

  printf("Starting pcap\n");

  pcap_loop(pcap, 1, handle_packet, (u_char *)params);

  printf("Out of pcap loop\n");
  pcap_stat st;
  if (pcap_stats(pcap, &st) == -1) {
    //fprintf(stderr, "pcap: %s\n", errbuf);
    exit(1);
  }
  //fprintf(stderr, "%d received, %d dropped, %d dropped by interface\n",
  //	  st.ps_recv, st.ps_drop, st.ps_ifdrop);
}

#ifdef PROFILE_PCAP
unsigned int profile_time = 0;
int profile_count = 0;
unsigned int profile_bytes = 0;
#endif


#define WORD(p) (((*(p))<<8)+(*((p)+1)))
#define LONG(p) (((*(p))<<24)+(*((p)+1)<<16)+(*((p)+2)<<8)+(*((p)+3)))

TCPStream *get_stream(Flow _flow){
  TCPStream *fp;
  //printf("get_stream: %0lx\n", &flows);

  for(flows.iterator_reset(), fp = (TCPStream *)flows.iterator_next(); fp != NULL; fp = (TCPStream *)flows.iterator_next()){
    //printf("get_stream_body\n");
    fp->is(_flow);
    break;
  }
  fp = (TCPStream *)safe_malloc(sizeof(TCPStream));
  fp->buf = Ghetto_PQueue();
  fp->received_one = false;
  fp->flow = _flow;
  fp->output = cb_output;
  fp->gap = cb_gap;

  flows.push_back(fp);
  return fp;
}

static void handle_packet(unsigned char *user,
			  const struct pcap_pkthdr *hdr, const unsigned char *eth) {
#ifdef PROFILE_PCAP
  struct timeval start = start_profile();
#endif
  //printf("handle_packet\n");
  //fprintf(stderr, "got a packet: %d bytes\n", hdr->caplen);
  if (WORD(eth+12) != 0x0800) return;  /* not IP */

  //printf("0\n");


  const unsigned char *ip = eth+14;
  int iplen = WORD(ip+2);
  if (ip[9] != 0x06) return;  /* not TCP */

  //printf("1\n");

  const unsigned char *tcp = ip + (ip[0]&0x0F)*4;
  const unsigned char *data = tcp + ((tcp[12]&0xF0)>>4)*4;
  unsigned int seq = LONG(tcp+4);
  unsigned int len = iplen - (data-ip);
  if (len == 0) return;   /* ACK or other empty packet */
  //printf("2\n");
  assert(len > 0);

  Flow f;
  f.from.port = WORD(tcp);
  f.to.port = WORD(tcp+2);
  memcpy(&f.from.addr, ip+12, 4);
  memcpy(&f.to.addr, ip+16, 4);

  //printf("3\n");
  //fprintf(stderr, "%s:%d -> ", inet_ntoa(f.from.addr), f.from.port);
  //fprintf(stderr, "%s:%d (%d bytes)\n", inet_ntoa(f.to.addr), f.to.port, len);
  TCPStream *fp = get_stream(f);
  assert(fp != NULL);
  //printf("5\n");
  //flows[f].push_packet(data, seq, len);
  fp->push_packet(data, seq, len);
  //printf("6\n");
#ifdef PROFILE_PCAP
  profile_count ++;
  profile_time += stop_profile(start);
  profile_bytes += len;
  
  if(profile_count >= PROFILE_PCAP){
    printf("%d packets (%u bytes) received and processed in %uus: \n%uus/packet, %uus/kb\n", profile_count, profile_bytes, profile_time, (profile_time/profile_count), ((profile_time*1024)/profile_bytes));
    profile_count = 0;
    profile_time = 0;
    profile_bytes = 0;
  }
#endif
}

Packet::Packet(const unsigned char *_data, unsigned int _seq, unsigned int _len)
  : seq(_seq), len(_len) {
  data = (unsigned char *)safe_malloc(sizeof(unsigned char) * _len);
  memcpy(data, _data, _len);
  //fprintf(stderr, "%p: packet allocated: %p (%d bytes)\n", this, data, _len);
  refcnt = (unsigned short *)safe_malloc(sizeof(unsigned short));
  *refcnt = 1;
}
Packet &Packet::operator=(const Packet &other) {
  release();
  assign(other);
  return *this;
}
void Packet::assign(const Packet &other) {
  seq = other.seq;
  len = other.len;
  data = other.data;
  refcnt = other.refcnt;
  (*refcnt)++;
  //fprintf(stderr, "%p: packet copied: %p refcnt=%d\n", this, data, *refcnt);
}
void Packet::release(void) {
  --(*refcnt);
  if (*refcnt == 0) {
    safe_free(refcnt);
    safe_free(data);
    //fprintf(stderr, "%p: packet freed: %p (%d bytes)\n", this, data, len);
  }
  //else
  //fprintf(stderr, "%p: packet released: %p refcnt=%d\n", this, data, *refcnt);
}

void TCPStream::push_packet(const unsigned char *packet, unsigned int seq,
			    unsigned int len) {
  //printf("push packet\n");
  if (!received_one) {
    received_one = true;
    expected_seq = seq;
  }
  if (seq < expected_seq) return; // !! what about wrap-around?
  if (seq == expected_seq) {
    output(flow, packet, len);
    expected_seq += len;
    while (!buf.empty() && ((unsigned int)buf.peek_priority() == expected_seq)) {
      //Packet *pkt = buf.dequeue
      ShortPacket *pkt = (ShortPacket *)buf.dequeue(NULL);
      output(flow, (unsigned char *)pkt->data, pkt->len);
      expected_seq += pkt->len;
      safe_free(pkt);
      //fprintf(stderr, "buffer ready: pkt=%p pkt.data=%p len=%u\n",
      //      &buf.top(), buf.top().data, buf.top().len);
    }
  }
  else {
    //fprintf(stderr, "%p: pushing seq=%u len=%u when expecting %u\n",
    //    this, seq, len, expected_seq);
    ShortPacket *pkt = (ShortPacket *)safe_malloc(len + sizeof(int));
    pkt->len = len;
    memcpy(pkt->data, packet, len);

    buf.insert(seq, pkt);
  }
  if (buf.size() > MAX_BACKLOG) pcap_breakloop(pcap);
}

int TCPStream::is(Flow _flow){
  return (memcmp(&flow, &_flow, sizeof(Flow)) == 0);
}

static void cb_output(const Flow &flow, const unsigned char *data, int len) {
  //printf("cb_output\n");
  char *buffer = (char *)safe_malloc(sizeof(char) * len + sizeof(Flow) + sizeof(int));
  //printf("cb1\n");
  memcpy(&(buffer[0]), &flow, sizeof(flow));
  //printf("cb2\n");
  memcpy(&(buffer[sizeof(Flow)]), &len, sizeof(int));
  //printf("cb3: %d\n", len);
  memcpy(&(buffer[sizeof(Flow) + sizeof(int)]), data, sizeof(char) * len);
  //printf("cb4\n");
//  printf("Writing output:%lu->%lu\n", (unsigned long)len, (unsigned long int)reassemble_output->get_bytes());
  reassemble_output->write_malloced(buffer, len*sizeof(char) + sizeof(Flow) + sizeof(int));
  //printf("Wrote output\n");
}

static void cb_gap(const Flow &flow, int len) {
  char *buffer = (char *)safe_malloc(sizeof(Flow) + sizeof(int));
  memcpy(&(buffer[0]), &flow, sizeof(flow));
  len = -len;
  memcpy(&(buffer[sizeof(Flow)]), &len, sizeof(int));
  reassemble_output->write_malloced(buffer, sizeof(Flow) + sizeof(int));
}
