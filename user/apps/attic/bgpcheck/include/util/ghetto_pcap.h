#ifndef GHETTO_PCAP_H_SHIELD
#define GHETTO_PCAP_H_SHIELD

typedef long int bpf_u_int32;
typedef unsigned char u_char;

struct ghetto_filter {
  unsigned int ip;
  unsigned int port;
  ghetto_filter *next;
};

struct bpf_program {
  ghetto_filter *filter;
};

struct pcap_t {
  int loop;
  int bufflen;
  ghetto_filter *filter;
  u_char *buff;
};

struct pcap_stat {
  bpf_u_int32 ps_recv;
  bpf_u_int32 ps_drop;
  bpf_u_int32 ps_ifdrop;
};

struct pcap_pkthdr {
  struct timeval ts;
  bpf_u_int32 caplen;
  bpf_u_int32 len;
};

enum pcap_error_type {
  PCAP_NO_ERR
};

#define PCAP_ERRBUF_SIZE 100

typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *hdr, const unsigned char *eth);

void pcap_get_error(char *buf, pcap_error_type err);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, const char *errbuff);
int pcap_compile(pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
int pcap_stats(pcap_t *p, struct pcap_stat *ps);
void pcap_breakloop(pcap_t *p);
char *gcap_addfilter(char *fp, unsigned int ip, unsigned short port);

#endif
