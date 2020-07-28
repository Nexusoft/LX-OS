
#ifndef NBGP_H_SHIELD
#define NBGP_H_SHIELD

typedef struct nbgp_badlist_t {
  struct nbgp_badlist_t *next;
  unsigned int prefix;
  unsigned short prefix_len;
  unsigned int as_path_len;
  unsigned short *as_path;
  unsigned int id;
  unsigned int errtype;
} nbgp_badlist;

void nbgp_make_report(bol_error_report *report);
void nbgp_withdraw_report(bol_error_withdrawal *report);
void nbgp_malformed_message(int AS, int bytes, int incoming);
void nbgp_oversized_message(int AS, int bytes, int incoming);
void nbgp_missing_packets(int AS, int bytes, int incoming);
void nbgp_invalid_peer(int ip, int incoming);
int nbgp_incoming_packet(bc_global_data *parser, bol_info *info, bgp_packet *p, int as, int ip);
int nbgp_outgoing_packet(bc_global_data *parser, bol_info *info, bgp_packet *p, int as, int ip);

#endif
