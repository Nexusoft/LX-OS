#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcap.h>

#include "common.h"
#include "bgp.h"
#include "bgpcheck.h"
#include "overlay.h"
#include "cap-passive.h"
#include "nbgp.h"
#include "bgpcheck.h"

nbgp_badlist *badlist = NULL;

void nbgp_make_report(bol_error_report *report){
  printf("Got an error report from AS %u\n", report->reporting_AS);
  free(report);
}

void nbgp_withdraw_report(bol_error_withdrawal *report){
  printf("Got an error withdrawal from AS %u\n", report->reporting_AS);
  free(report);
}

void nbgp_malformed_message(int AS, int bytes, int incoming){
   printf("WARNING: Parser couldn't decode some packets (dropping %d malformed bytes %s AS %d)\n", bytes, incoming?"coming from":"going to", AS); 
}

void nbgp_oversized_message(int AS, int bytes, int incoming){
   printf("WARNING: Parser couldn't decode some packets (dropping %d oversized bytes %s AS %d)\n", bytes, incoming?"coming from":"going to", AS); 
}

void nbgp_missing_packets(int AS, int bytes, int incoming){
  printf("WARNING: Pcap dropped some packets (%d bytes %s AS %d)\n", bytes, incoming?"coming from":"going to", AS);
}

void nbgp_invalid_peer(int ip, int incoming){
  //damn
  printf("Our monitored client %s an invalid peer: ", incoming?"received from":"sent to");
  bgp_print_ip(ip);
  printf("\n");
  //assert(!"nbgp invalid peer");
}
int nbgp_incoming_packet(bc_global_data *parser, bol_info *info, bgp_packet *p, int as, int ip){
  nbgp_badlist *curr = badlist, *last = NULL;
  bgp_as_path path;
  int x;

  bc_parse_incoming_packet(p, parser);

  //now let's see if it fixed anything we're worrying about...
  path.type = 1;
  path.next = NULL;

  for(; curr != NULL; curr = curr->next){
    path.len = curr->as_path_len;
    //urngh... this is ugly.  Need to clean it up so it uses shorts everywhere
    path.list = malloc(sizeof(short) * path.len);
    for(x = 0; x < path.len; x++){
      path.list[x] = curr->as_path[x];
    }
    //path.list = curr->as_path;

    if(bc_aggregated_verify(parser->root, curr->prefix, curr->prefix_len, &path)){
      //hey, that update made this update valid.
      
      bol_inject_withdrawal(info, curr->id);
    }
    free(path.list);

    last = curr;
  }

  return 1;
}

unsigned short *nbgp_extract_aspath(bgp_as_path *path_base, int *len){
  unsigned short *path;
  bgp_as_path *curr;
  int x, y;

  *len = 0;
  for(curr = path_base; curr != NULL; curr = curr->next){
    *len += curr->len;
  }

  path = (unsigned short*)malloc(sizeof(unsigned short) * (*len));

  x = 0;
  for(curr = path_base; curr != NULL; curr = curr->next){
    for(y = 0; y < curr->len; y++,x++){
      path[x] = curr->list[y];
    }
  }

  return path;
}

int nbgp_outgoing_packet(bc_global_data *parser, bol_info *info, bgp_packet *p, int as, int ip){
  int count = bc_count_packet_ads(p);
  int ret = 1, x, len, errtype;
  unsigned short *as_path;
  bgp_ipmaskvec *ad;
  nbgp_badlist *badlist_entry;

  if(p->type != UPDATE){
    return 1;
  }

  for(x = 0; x < count; x++){
    if((errtype = bc_parse_outgoing_ad(p, parser, x)) != 0){
      ret = 0;

      bgp_timestamp();
      printf("Detected failure with rule: %d\n", -errtype);

      //so umm... the code below is segfaulting, but it's not really needed
      //if all we're doing is screening for false positives.  For testing, let's
      //skip this bit.
      continue;

      //well shit, we're trying to spit out a bad packet.  Let's tell 
      //everyone about it.

      ad = bc_get_dest_vec(p, x);
      as_path = nbgp_extract_aspath(bc_get_dest_path(p), &len);
      
      //though we should first check to see if it's a repeat report...
      for(badlist_entry = badlist; badlist_entry != NULL; badlist_entry = badlist_entry->next){
	if(badlist_entry->prefix_len == ad->mask){
	  if(badlist_entry->prefix == ad->ip){
	    if(badlist_entry->as_path_len == len){
	      if(memcmp(badlist_entry->as_path, as_path, len * sizeof(unsigned short))){
		break;
	      }
	    }
	  }
	}
      }

      if(badlist_entry != NULL){
	free(as_path);
	continue;
      }
      
      //It's possible that the conditions generating the error might be reversed
      //in this case keep a record in case the path becomes valid later on
      badlist_entry = malloc(sizeof(nbgp_badlist));
      badlist_entry->prefix = ad->ip;
      badlist_entry->prefix_len = ad->mask;
      badlist_entry->as_path_len = len;
      badlist_entry->as_path = as_path;
      badlist_entry->errtype = errtype;
      badlist_entry->next = badlist;
      badlist = badlist_entry;

      //now let everyone else know

      //printf("AAAAAAAAA, I'm sending a message about an error!\n");

      badlist_entry->id = 
	bol_inject_badUpdate(info,                           //overlay data
			     info->as,                       //affected AS
			     bc_calculate_knowledge(parser), //knowledge
			     ad->mask,                       //prefix info
			     ad->ip,
			     len,                            //as_path info
			     as_path);
      
      continue;
    }
  }

  return ret;
}

bc_pcap_info *init(int argc, char **argv, bol_info *olinfo){
  char *configFile = ".nbgp";
  char *device = NULL;
  FILE *config;
  bc_pcap_info *info;
  char ip[20];
  char cmd[21];
  unsigned int my_as, peer_as, port, capport;
  
  if(argc > 1){
    if(strcmp(argv[1], "-") != 0){
      device = argv[1];
    }
  }
  if(argc > 2){
    configFile = argv[2];
  }
	
  config = fopen(configFile, "r");

  if(config == NULL){
    perror("error opening file");
    exit(0);
  }
  
#ifndef DEBUG_DISABLE_SNIFFER
  printf("Initializing Passive Capture\n");

  info = bc_passive_init(device, olinfo);
#endif

  printf("Loading configuration file:%s\n", configFile);

	config = fopen(configFile, "r");
	if (!config) {
		perror(configFile);
		return info;
	}

  while(fscanf(config, "%20s", cmd) != EOF){
    printf("command: %s\n", cmd);
    if(strcmp(cmd, "self") == 0){
      fscanf(config, "%15s %d %d %d\n", ip, &my_as, &port, &capport);
#ifndef DEBUG_DISABLE_SNIFFER
      bc_set_my_ip(info, ntohl(inet_addr(ip)), capport);
#endif
#ifndef DEBUG_DISABLE_OVERLAY
      bol_set_ip(olinfo, ntohl(inet_addr(ip)), port, my_as);
#endif
      printf("Me: %s:%d, OL port: %d, AS: %d\n", ip, capport, port, my_as);
    } else if(strcmp(cmd, "peer") == 0){
      fscanf(config, "%15s %d %d\n", ip, &peer_as, &capport);
#ifndef DEBUG_DISABLE_SNIFFER
      bc_add_peer(ntohl(inet_addr(ip)), peer_as, my_as, capport, info);
#endif
      printf("Peer: %s:%d, AS: %d\n", ip, capport, peer_as);
    } else if(strcmp(cmd, "monitor") == 0){
      fscanf(config, "%15s %d\n", ip, &port); 
#ifndef DEBUG_DISABLE_OVERLAY
      bol_add_peer(ntohl(inet_addr(ip)), port, olinfo);
#endif
      printf("Monitor: %s:%d\n", ip, port);
    } else {
      printf("Unknown command: %s\n", cmd);
    }
  }

  bc_install_filter(info);

  printf("done\n");

  fclose(config);
  return info;
}

int main(int argc, char **argv){
  bc_pcap_info *info;
  bol_info *olinfo;
  fd_set readfds, writefds, exceptfds;
  int maxfd = 0, fd;
  int keep_going = 1;
  struct timeval timeout;

#ifndef DEBUG_DISABLE_OVERLoAY
  printf("Initializing overlay\n");
  olinfo = bol_initialize();
#endif
  printf("Initializing capture device\n");
  info = init(argc, argv, olinfo);

  printf("Starting polling\n");
  while(keep_going){
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

#ifndef DEBUG_DISABLE_SNIFFER		
    fd = bc_set_select_fd(info, &readfds, &exceptfds);
    maxfd = MAX(maxfd, fd);
#endif
#ifndef DEBUG_DISABLE_OVERLAY
    fd = bol_set_select_fd(olinfo, &readfds, &writefds, &exceptfds);
    maxfd = MAX(maxfd, fd);
#endif

    /* we poll because promiscuous sockets don't always set their "read"
       flag in select. */
    timeout.tv_sec = 0;
    timeout.tv_usec = 500;

    select(maxfd+1, &readfds, &writefds, &exceptfds, &timeout);

#ifndef DEBUG_DISABLE_SNIFFER		
    bc_check_data(info, &readfds, &exceptfds);
#endif
#ifndef DEBUG_DISABLE_OVERLAY
    bol_check_data(olinfo, &readfds, &writefds, &exceptfds);
#endif
  }

  return 0;
}
