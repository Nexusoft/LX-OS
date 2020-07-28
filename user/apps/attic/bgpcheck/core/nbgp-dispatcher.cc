#include <stdio.h>
#include "../include/nbgp/nbgp.h"
#include "../include/util/common.h"
#include "../include/runtime/socket.h"
extern "C" {
#include "../include/nbgp/bgp.h"
};

//Grassroots messages and the corresponding advertisements might come a short time apart.
//Correspondingly, there has to be a limit on the amount of time we wait before flagging an ad.
//SYNC_TIMEOUT is the amount of time we're willing to wait after receiving a bgp message before
//  we flag it as bad.
//PRESYNC_TIMEOUT is the amount of time we're willing to hold onto a grassroots message before
//  discarding it.  (for this amount of time, all agreeable messages will be pre-verified)
#define GRASSROOTS_SYNC_TIMEOUT 15000
#define GRASSROOTS_PRESYNC_TIMEOUT 15000

BGP_Dispatcher::BGP_Dispatcher(Runtime *_runtime) {
  overlay = NULL;
  indb = NULL;
  routerip = 0;
  routerpass = NULL;
  routeras = 0;
  badcount = 0;
  grassrootsdb = NULL;
  logfile = NULL;
  runtime = _runtime;
  recheck_callback = new BGP_Recheck_Callback(this);
  runtime->register_handler(recheck_callback);
  debug_outdb = debug_grassroots = NULL;
  //nothing to see here, carry on.
}

void BGP_Dispatcher::start_logging(char *_logfile){
  printf("Logging to : %s\n", _logfile);
  logfile = fopen(_logfile, "w");
  fprintf(logfile, "===== Logfile started =====\n");
//  fflush(logfile);
}

void BGP_Dispatcher::stop_logging(void){
  fclose(logfile);
  logfile = NULL;
}

void BGP_Dispatcher::set_overlay(Overlay_Server_Handler *_overlay){
  overlay = _overlay;
}

void BGP_Dispatcher::set_incoming_db(BC_Database *_indb){
  indb = _indb;
}

void BGP_Dispatcher::set_grassroots(Grassroots *_grassrootsdb){
  grassrootsdb = _grassrootsdb;
}

void BGP_Dispatcher::set_router(unsigned int _routerip, char *_routerpass, char *_routeruser, unsigned short _routeras){
  routerip = _routerip;
  routerpass = _routerpass;
  routeruser = _routeruser;
  routeras = _routeras;
}

int get_mask(int input){
  int ret = 0;
  if(input > 8) { input = 8; }
  while(input > 0){
    ret <<= 1;
    ret |= 1;
    input--;
  }
  return ret;
}

void load_bgp_path(std::vector<unsigned short> *path, bgp_as_path *base_path){
  int i;
  bgp_as_path *curr;
  
  for(curr = base_path; curr != NULL; curr = curr->next){
    for(i = 0; i < curr->len; i++){
      path->push_back(curr->list[i]);
    }
  }
}

void BGP_Dispatcher::report_ad(unsigned int prefix, unsigned short prefixlen, bgp_as_path *base_path){
  unsigned short *path;
  bgp_as_path *bgp_path;
  int i, j;

  i = 0;
  for(bgp_path = base_path; bgp_path != NULL; bgp_path = bgp_path->next){
    i += bgp_path->len;
  }
  path = (unsigned short *)alloca((i + 1) * sizeof(unsigned short));
  j = 0;
  for(bgp_path = base_path; bgp_path != NULL; bgp_path = bgp_path->next){
    for(i = 0; i < bgp_path->len; i++, j++){
      path[j] = bgp_path->list[i];
    }
  }
  path[j] = 0;
  
  report_ad(prefix, prefixlen, path);
}

void BGP_Dispatcher::report_ad(unsigned int prefix,unsigned short prefixlen, unsigned short *path){
  //assert(overlay);
  int x;
  return; //let's not print stuff out during a timing test.

  printf("Ad reported: prefix: ");print_ip(prefix, 0);printf("; length : %d @ %d\n", prefixlen, (int)time(NULL));
  
  if(logfile){
    fprintf(logfile, "Ad reported: prefix: ");
    fwrite_ip(prefix, 0, logfile);
    fprintf(logfile, "/%d", prefixlen);
    for(x = 0; path[x] != 0; x++){
      fprintf(logfile, " [%d]", path[x]);
    }
    fprintf(logfile, " @ %d\n", (int)time(NULL));
//    fflush(logfile);
  }

  if(overlay){
    printf("Sending warning to overlay\n");
    overlay->send_warning(path, prefix, prefixlen);
  }
  
  if(routerip){
    //XXX this can be done much more cleanly  std::string?
    char *data = (char *)alloca(1000);
    char *aspath = (char *)alloca(500);
    int tempmask;
    Socket *router = new Socket();
    printf("Disabling route on router\n\tOpening telnet session with "); print_ip(routerip, 1); printf("\n");
    if(router->connect_s(routerip, 23) < 0){
      printf("\tCan't telnet to router\n");
    } else {
      printf("\tGenerating and sending kill command\n");
      aspath[0] = '\0';
      x = 0;
      while(path[x] != 0){
        sprintf(&(aspath[strlen(aspath)]), " %d", path[x]);
        x++;
      }
      sprintf(data, "%s\n%s\nconfigure terminal\naccess-list badpath%d deny %d.%d.%d.%d mask %d.%d.%d.%d\nip as-path access-list deny badprefix%d %s\nroute-map bogus%d\nmatch ip address badprefix%d as-path badpath%d\nexit\nrouter bgp %d\ntable-map bogus%d deny\n",
        routeruser,
        routerpass,
        badcount,
        (prefix >> 24)&0xff, (prefix >> 16)&0xff, (prefix >> 8)&0xff, (prefix >> 0)&0xff,
        get_mask(prefixlen), get_mask(prefixlen - 8), get_mask(prefixlen - 16), get_mask(prefixlen - 24),
        badcount,
        aspath,
        badcount,
        badcount,
        badcount,
        routeras,
        badcount);
      router->send_s(data, strlen(data));
      router->close_s();
    }
  }
}

void BGP_Dispatcher::handle_reported(unsigned int prefix, unsigned short prefixlen, unsigned short *path){
  int i;
  printf("Got a path warning!  "); print_ip(prefix, 1); printf("/%d", prefixlen);
  for(i = 0; path[i] != 0; i++){
    printf(" [%d]", path[i]);
  }
  printf("\n");
}

void BGP_Dispatcher::rvq(unsigned int prefix, unsigned short prefixlen, unsigned short *aspath){
  if(indb) {
    if(!indb->check_forward(prefix, (int)prefixlen, aspath)){
      report_ad(prefix, prefixlen, aspath);
    }
  }
}
void BGP_Dispatcher::sent_packet(bgp_packet *packet, unsigned short peer, unsigned int peer_ip){
  if(indb) {
    if(!debug_outdb) { debug_outdb = debug_get_stateptr("RVQ_STORE"); }
    debug_start_timing(debug_outdb);
    indb->forward(packet, peer);
    debug_stop_timing(debug_outdb, 1);
  }
}


void BGP_Dispatcher::got_packet(bgp_packet *packet, unsigned short peer, unsigned int peer_ip){
    
  if(packet->type != 2){ return; } //updates only
    
  if(grassrootsdb){
    int cnt = 0;
    if(!debug_grassroots) { debug_grassroots = debug_get_stateptr("GRASSROOTS"); }
    debug_start_timing(debug_grassroots);
    bgp_ipmaskvec *vec; // vec's ip field is alread in host byte order
    
    if(packet->contents.UPDATE.destv){
      vec = packet->contents.UPDATE.destv;
      cnt = 0;
      while(vec){
        if(!grassrootsdb->validate_advertisers(htonl(vec->ip), vec->mask, packet->contents.UPDATE.as_path)){
          report_ad(vec->ip, vec->mask, packet->contents.UPDATE.as_path);
        }
        vec = vec->next;
        cnt++;
      }
    }
    debug_stop_timing(debug_grassroots, cnt);
  }
}

void BGP_Dispatcher::report_policy(bgp_packet *packet, int ad, int rule){
  printf("Reporting policy violation!  (Prefix #%d, Rule #%d)\n", ad, rule);
  bgp_print_packet(packet);
  
}



BGP_Dispatcher::BGP_Recheck_Event::~BGP_Recheck_Event(){
  std::vector<BC_Advertisement *>::iterator ad;
  BC_Advertisement *curr;
  if(b_ads){
    for(ad = b_ads->begin(); ad != b_ads->end(); ++ad){
      curr = *ad;
      curr->ref_down();
    }
    delete b_ads;
  }
}

int BGP_Dispatcher::BGP_Recheck_Event::validate(BGP_Dispatcher *owner){
  std::vector<BC_Advertisement *>::iterator ad;
  BC_Advertisement *curr;
  int errors = 0;
  
  for(ad = b_ads->begin(); ad != b_ads->end(); ++ad){
    curr = *ad;
//    if(!curr->validated() && !curr->withdrawn()){
//      //raise hell.
//      unsigned short *path = curr->dump_path();
//      printf("recheck failed!\n");
//      owner->report_ad(prefix, prefix_len, path);
//      owner->stop_logging();
//      assert(0);
//      delete path;
//      errors++;
//    }
  }
  return errors;
}
int BGP_Dispatcher::BGP_Recheck_Event::timeleft(){
  return trigger_time - (time(NULL) * 1000);
}

BGP_Dispatcher::BGP_Recheck_Callback::BGP_Recheck_Callback(BGP_Dispatcher *_owner) : Runtime_Handler("BGP_Recheck_Callback"){
  owner = _owner;
  scheduled = 0;
}
void BGP_Dispatcher::BGP_Recheck_Callback::schedule(int time){
  if(scheduled) return;
  scheduled = 1;
  set_periodic_time(time);
}
int BGP_Dispatcher::BGP_Recheck_Callback::handle_periodic(Runtime *runtime){
  return owner->finish_recheck(this);
}

void BGP_Dispatcher::schedule_recheck(int t_time, std::vector<BC_Advertisement *> *b_ads, unsigned int prefix, unsigned short prefix_len){
  BGP_Recheck_Event *evt = new BGP_Recheck_Event();
  if(logfile){
    std::vector<BC_Advertisement *>::iterator ad_i;
    fprintf(logfile,"Scheduling recheck for : \n");
    for(ad_i = b_ads->begin(); ad_i != b_ads->end(); ++ad_i){
      BC_Advertisement *ad = *ad_i;
      fprintf(logfile, "   (");
      fwrite_ip(prefix, 0, logfile);
      fprintf(logfile,"/%d: ", prefix_len);
      ad->print_path(logfile);
      fprintf(logfile, " @ %d)\n", (int)time(NULL));
    }
//    fflush(logfile);
  }
  
  recheck_callback->schedule(t_time);
  
  evt->trigger_time = t_time + (time(NULL) * 1000);
  evt->b_ads = b_ads;
  evt->prefix = prefix;
  evt->prefix_len = prefix_len;
  
  pending_checks.push_back(evt);
}
int BGP_Dispatcher::finish_recheck(BGP_Recheck_Callback *cb){
  BGP_Recheck_Event *curr = NULL;
  int errcnt = 0;
  
  while(pending_checks.size() > 0){
    curr = pending_checks.front();
    if(curr->timeleft() > 0){
      break;
    }
    errcnt += curr->validate(this);
    pending_checks.pop_front();
    delete curr;
  }
  
  if(errcnt){
    stop_logging();
    assert(0);
  }
  
  if(pending_checks.size() > 0){
    return curr->timeleft();
  } else {
    return 0;
  }
}


