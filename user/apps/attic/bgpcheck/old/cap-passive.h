
#ifndef CAP_PASSIVE_H_SHIELD
#define CAP_PASSIVE_H_SHIELD

#define BC_PCAP_DATALEN(x) ((sizeof(int) * 2) + (sizeof(struct bc_pcap_data_t *) * 2) + x)

typedef struct bc_pcap_data_t {
  unsigned int seqno;
  int len;
  struct bc_pcap_data_t *next;
  char data[];
} bc_pcap_data;

//we need to optimize this structure for later use
typedef struct bc_pcap_server_t {
  int ip;
  int as;
  int port;
  unsigned int seqno[2];
  struct bc_pcap_data_t *data[2];
  struct bc_pcap_server_t *next;
  int offset[2];
  bc_global_data *parser;
} bc_pcap_server;

typedef struct bc_pcap_info_t {
  bc_pcap_server *peers;
  bpf_u_int32 serverIP;
  int serverPort;
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  pcap_t *handle;
  bol_info *overlay;
  int read_packet;
} bc_pcap_info;

bc_pcap_info *bc_passive_init(char *device, bol_info *info);
void bc_add_peer(int ip, int peer_as, int my_as, int capport, bc_pcap_info *info);
void bc_set_my_ip(bc_pcap_info *info, int ip, int capport);
int bc_set_select_fd(bc_pcap_info *info, fd_set *set, fd_set *exception);
void bc_check_data(bc_pcap_info *info, fd_set *set, fd_set *exception);
void bc_install_filter(bc_pcap_info *info);

int bc_set_select_fd(bc_pcap_info *info, fd_set *set, fd_set *exception);
#endif
