#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <math.h>

#include "bgpdump.h"
#include "../../../include/util/common.h"

#include "../../../include/util/common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

using namespace std;

double doubleTime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}

void print_all(void) {
  cout.flush();
  fflush(stdout);
  fsync(fileno(stdout));
}

void sig_break(int v) {
  cerr << "Got break\n";
  exit(0);
}

void sigpipe(int v) {
  cerr << "Got SIGPIPE!\n";
  exit(0);
}

extern "C" {
#include "../../../include/nbgp/bgp.h"
}

#define BGP_TIMEOUT 240

int ipcount = 0;
int pathcount = 0; 
unsigned int myip;
unsigned int cornellip;
int myas = 0;
unsigned int destip = 0;
int myport = 179;
int destport = 179;
unsigned int me;
unsigned int display_p = 0;
unsigned char display_p_len = 0;
int fast_test = 0;

std::map<unsigned int, FILE *> *filelist = NULL;
int ip_update = 0;
int write_fd = -1;
int hold_time = 60;
// source file type : 3 = binary rib format
int source_file_type = 2;
std::vector<unsigned int> *ipeers = NULL;

void read_packet_proc(int fd){
  bgp_packet packet;
  bgp_datasource source;
  int r = 1;

  source.type = (typeof(source.type))1;
  source.contents.pipe = fd;

  while(r > 0){
    r = bgp_read_packet(&source, &packet);
    
    if(r > 0){
      bgp_print_packet(&packet);
      bgp_cleanup_packet(&packet);
    }
  }
}

FILE *open_ipdump(unsigned int ip, char *mode){
  char ip_str[40];
  sprintf(ip_str, "%s%d.%d.%d.%d.src", 
	  ip_update?"updates/":"",
	  (ip >> (24))&0xff, 
	  (ip >> (16))&0xff, 
	  (ip >> (8))&0xff,
	  (ip)&0xff);
  printf("Opening auto-generated file : %s\n", ip_str);
  return fopen(ip_str, mode);
}

char *my_fgetln(FILE *f, int *len){
  static char ret[500];
  int c;
  unsigned int c2;
  unsigned char c3;
  *len = 0;

  do {
    c = fgetc(f);
    if(c < 0) break;
    c2 = (unsigned int)c;
    c3 = (unsigned char)c2;
    ret[*len] = (char)c3;
    (*len)++;
    if(*len >= 499){
      ret[499] = '\0';
//      printf("Input line with an absurd number of characters! %s\n", ret);
//      exit(1);
      break;
    }
    //printf("read: %c %d\n", ret[*len], ret[*len]);
  } while((!feof(f))&&(ret[(*len)-1] != '\n'));
  //printf("done\n");
  return ret;
}

FILE *open_dump(const char *file){
  char buff[60];
  sprintf(buff, "cat %30s | zebra-dump-parser.pl 2> /dev/null", file);
  return popen(buff, "r");
}

int find_param(char *line, char **param){
  for(; *line != ':'; line++){
    if(*line == '\0') return 0;
  }
  *line = '\0';
  line++;
  if(*line == ' ') line++;
  *param = line;
  
  for(; *line != '\0'; line++){
    if(line[0] == ' '){
      if(line[1] == ' '){
        line[0] = '\0';
	break;
      }
    }
    if(line[0] == '\n'){
      line[0] = '\0';
      break;
    }
  }
  return 1;
}

unsigned int extract_ip(char *dat, unsigned int len){
  unsigned int curr, ip, i, found = 0;
  curr = 0; ip = 0;
	
  for(i = 0; i < len; i++){
    switch(dat[i]){
    case '1': case '2': case '3': case '4': case '5':	
    case '6': case '7': case '8': case '9': case '0':
      curr *= 10;
      curr += (dat[i] - '0');
      found = 1;
      break;
    default:
      i = len;
    case '.':
      if(found){
	ip <<= 8;
	ip += curr&0xFF;
	curr = 0;
	found = 0;
      }
      break;
    }		
  }
  if(found){
    ip <<= 8;
    ip += curr&0xFF;
    curr = 0;
    found = 0;
  }
  return ip;
}

unsigned int extract_prefix(char *dat, unsigned int len, unsigned char *plen){
  unsigned int ip, i;
  short found = 0;
  *plen = 0;
  for(i = 0; i < len; i++){
    switch(dat[i]){
    case '1': case '2': case '3': case '4': case '5':	
    case '6': case '7': case '8': case '9': case '0':
      if(found){
	*plen *= 10;
	*plen += (dat[i] - '0');
      }
      break;
    case '/':
      found = 1;
      break;
    case '.':
      if(!found) break;
    default:
      i = len;
      break;
    }		
  }
  ip = extract_ip(dat, len);
  if(!found){ // default prefix length based on class
    found = ip >> 24;
    if(found <= 126){
      *plen = 8;
    } else if(found <= 191) {
      *plen = 16;
    } else if(found <= 223) {
      *plen = 28;
    } else {
      assert(!"Asked to use default prefix length for a class D/E address");
    }
  }
  return ip;
}

int extract_num(char *dat, unsigned int len){
  int num = 0;
  unsigned int i;
	
  for(i = 0; i < len; i++){
    switch(dat[i]){
    case '1': case '2': case '3': case '4': case '5':	
    case '6': case '7': case '8': case '9': case '0':
      num *= 10;
      num += (dat[i] - '0');
      break;
    default:
      num = 0;
      break;
    }		
  }
  return num;
}

std::vector<unsigned short> extract_path(char *dat, unsigned int len, int *originflags){
  std::vector<unsigned short> path;
  unsigned short curr = 0;
  unsigned int i;
	
  *originflags = 1;
	
  for(i = 0; i < len; i++){
    switch(dat[i]){
    case '1': case '2': case '3': case '4': case '5':	
    case '6': case '7': case '8': case '9': case '0':
      curr *= 10;
      curr += (dat[i] - '0');
      break;
    case ' ':
      if(curr != 0){
	//printf("[%d]  ", curr);
	path.push_back(curr);
      }
      curr = 0;
      break;
    case 'i':
      *originflags = 0;
      curr = 0;
      break;
    default:
      i = len;
      break;
    }
  }
  if(curr != 0){
    path.push_back(curr);
  }

  return path;
}

int ip_add(int ip, std::vector<unsigned int> *iplist){
  std::vector<unsigned int>::const_iterator iter;
  for(iter = iplist->begin(); iter != iplist->end(); ++iter){
    if((unsigned int)ip == *iter){
      return 0;
    }
  }
  printf("Found IP: "); print_ip(ip, 0); printf("\n");
  iplist->push_back(ip);
  ipcount++;
  return 1;
}

void dump_read(int fd){
  char buff[100];
  int r = 1;

  while(r > 0){
    r = read(fd, buff, sizeof(buff));
  }
}

static void cork(int fd) {
  int opt = 1;
  setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static void uncork(int fd) {
  int opt = 0;
  setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

void my_write(int fd, void *buff, int len){
  int r;
  // printf("Writing %d bytes to fd=%d\n", len, fd);
  while(len > 0){
    //dump_read(fd);

    r = write(fd, buff, len);
    assert(r != 0);
    if(r < 0){
      switch(errno){
      case EAGAIN: {
	printf("Write buffer full, pausing\n");
	struct pollfd pfd[1];
	pfd[0].fd = fd;
	pfd[0].events = POLLOUT;
	pfd[0].revents = 0;
	poll(pfd, 1, 0);
	assert(pfd[0].revents & POLLOUT);
	continue;
      }
      default:
	perror("Connection aborted!");
	assert(false);
      }
    }
    len -= r;
    buff = &(((char *)buff)[r]);
  }
}

unsigned short get_as_from_path(std::vector<unsigned short> as_path){
  std::vector<unsigned short>::iterator as;
  as = as_path.begin();
  if(as == as_path.end()){
    return 0;
  }
  return *as;
}

unsigned short get_as(ad_list *list){
  int cand = 0;
  for(ad_list::iterator first = list->begin();
      first != list->end(); first++) {
    cand = get_as_from_path(first->path);
    if(cand != 0) {
      return cand;
    }
  }
  return -1;
}

void send_keepalive(int fd){
  BGP_Header p_head;
  memset(&(p_head.marker), 0xff, 16);
  p_head.len = htons(BGP_HEADER_SIZE);
  p_head.type = 4;//KEEPALIVE
  my_write(fd, &p_head, BGP_HEADER_SIZE);
}

int compare_ip_prefix(unsigned int ip, unsigned int prefix, int plen){
  ip >>= 32-plen;
  prefix >>= 32-plen;

  for(; plen > 0; plen--){
    if(ip&0x1 != prefix&0x1) return 0;
    ip >>= 1;
    prefix >>= 1;
  }
  return 1;
}

int check_exceptions(Advertisement ad){
//  if(ad.path.size() == 0){
//    //printf("Exception failed: Empty ASPATH\n");
//    return 1;
//  }
//  if(*(ad.path.begin()) != myas){
//    //printf("Exception failed: ASPATH starting with another AS\n");
//    return 1;
//  }
  if(compare_ip_prefix(cornellip, ad.prefix, ad.plen)){
    //printf("Exception failed: Advertising a cornell prefix\n");
    return 1;
  }
  return 0;
}

void send_ad(Advertisement ad, int fd){
  cork(fd);
  BGP_Header p_head;
  BGP_Update_Announce p_update;
  unsigned short temp;
  unsigned int temp2;
  std::vector<unsigned short>::const_iterator iter;
  
  memset(&(p_head.marker), 0xff, 16);
  p_head.type = 2;//UPDATE

  if(ad.type){
    //withdraw
    p_head.len = htons(BGP_HEADER_SIZE + sizeof(unsigned short) * 2 + (ad.plen+7)/8 + 1);
    my_write(fd, &p_head, BGP_HEADER_SIZE);
    temp = htons((ad.plen+7)/8 + 1);
    my_write(fd, &temp, sizeof(unsigned short));
    my_write(fd, &(ad.plen), sizeof(char));
    temp2 = htonl(ad.prefix);
    my_write(fd, &temp2, (ad.plen+7)/8);
    temp = 0;
    my_write(fd, &temp, sizeof(unsigned short));
  } else {
    //update
    if(check_exceptions(ad)) return;

    p_update.withdrawn_len = 0;
    p_update.origin_fl = 0x40;//well known, short attribute
    p_update.origin_type = 1;
    p_update.origin_len = 1;
    p_update.nexthop_fl = 0x40;//well known, short attribute
    p_update.nexthop_type = 3;
    p_update.nexthop_len = 4;
    p_update.path_fl = 0x40;//well known short attribute
    p_update.path_type = 2;
    p_update.path_segment = 2;//AS_SEQUENCE;
    
    p_update.community_fl = 0x40;//well known short attribute
    p_update.community_type = 8;//COMMUNITIES
    p_update.community_len = 4;
    p_update.community = htonl(ad.community);
    
    p_update.path_segment_len = (char)ad.path.size();
    p_update.origin = ad.originflags;
    p_update.nexthop = htonl(myip);
    p_update.path_len = p_update.path_segment_len * 2 + 2;
    p_update.attr_len = htons(p_update.path_segment_len * 2 + (BGP_UPDATE_SIZE - 4));

    p_head.len = htons(BGP_HEADER_SIZE + BGP_UPDATE_SIZE + p_update.path_segment_len * 2 + (ad.plen+7)/8 + 1);

    my_write(fd, &p_head, BGP_HEADER_SIZE);
    my_write(fd, &p_update, BGP_UPDATE_SIZE);
    for(iter = ad.path.begin(); iter != ad.path.end(); ++iter){
      temp = htons(*iter);
      my_write(fd, &temp, sizeof(short));
    }
    my_write(fd, &(ad.plen), sizeof(char));
    temp2 = htonl(ad.prefix);
    my_write(fd, &temp2, (ad.plen+7)/8);
  }
  uncork(fd);
}

void send_minisock_ad(Advertisement ad, int fd){
  int len, len2;
  Flow f;

  if(ad.type){
    len = BGP_HEADER_SIZE + sizeof(unsigned short) * 2 + (ad.plen+7)/8 + 1;
  } else {
    if(check_exceptions(ad)){
      return;
    }
    len = BGP_HEADER_SIZE + BGP_UPDATE_SIZE + ad.path.size() * 2 + (ad.plen+7)/8 + 1;
  }
  len2 = len + sizeof(Flow) + sizeof(int);

  if(ad.destination > 0){
    f.to.addr.s_addr = htonl(ad.destination);
  } else {
    f.to.addr.s_addr = htonl(destip);
  }
  f.to.port = htons(destport);
  if(ad.nexthop <= 1){
    print_ip(ad.prefix, 0); printf("/%d\n", ad.plen);
    assert(!"Bad prefix!");
  }
  f.from.addr.s_addr = htonl(ad.nexthop);
  f.from.port = htons(myport);

  my_write(fd, &len2, sizeof(int));
  my_write(fd, &len2, sizeof(int));
  my_write(fd, &f, sizeof(Flow));
  my_write(fd, &len, sizeof(int));

  send_ad(ad, fd);
}

int last_dump_send_time;

void send_dump(ad_list *list, int fd){
  std::vector<Advertisement>::const_iterator iter;
  int count = 0;

  myas = get_as(list);

  for(iter = list->begin(); iter != list->end(); ++iter){
    count ++;
    if(count % 20000 == 0){
      printf("sending keepalive!\n");
      send_keepalive(fd);
      //sleep(1);
    }
    //usleep(10000);

    if(0) {
      if(count % 5000 == 1){
        printf("%d / %d : ", count, pathcount); print_ip(iter->prefix, 0); printf("/%d\n", iter->plen);
      }
    }
    send_ad(*iter, fd);
    last_dump_send_time = (*iter).time;
    //assert(fsync(fd) == 0);
  }
  printf("Dump is done, sent %d\n", count);
}

int list_contains(std::vector<unsigned int> *list, unsigned int var){
  std::vector<unsigned int>::const_iterator iter = list->begin();
  
  for(; iter != list->end(); ++iter){
    if(*iter == var) return 1;
  }
  return 0;
}

int add_ad(ad_db *database, Advertisement ad){
  if(ipeers){
    if(ad.nexthop == me){
      if(!ad.type){
        if((ad.path.size() == 0) || (get_as_from_path(ad.path) != myas)){
          if(!list_contains(ipeers, ad.destination)){
            ipeers->push_back(ad.destination);
            printf("Found iBGP Peer: "); print_ip(ad.destination, 0); 
            if(ad.path.size() > 0){
              printf(" (AS %d)", get_as_from_path(ad.path));
            }
            printf("\n");
          }
        }
      }
    }
  }
  
  if(display_p != 0){
    if((ad.prefix == display_p)&&(ad.plen == display_p_len)){
      std::vector<unsigned short>::iterator iter;
      printf("(");print_ip(ad.nexthop, 0);
      printf("->");print_ip(ad.destination, 0);
      printf("): ");
      if(ad.type){
        printf("Withdrawn!\n");
      } else {
        for(iter = ad.path.begin(); iter != ad.path.end(); ++iter){
          printf(" [%d]", *iter);
        }
        printf("\n");
      }
    }
  }

  if(write_fd < 0){
    ad_db::iterator entry = database->find(ad.nexthop);
    std::vector<unsigned short>::const_iterator iter;
    std::map<unsigned int,FILE *>::iterator file;
    

    if(entry == database->end()){
      database->insert(ad_db::value_type(ad.nexthop, new(ad_list)));
      entry = database->find(ad.nexthop);
      assert(entry != database->end());
      if(filelist){
        filelist->insert(std::map<unsigned int,FILE *>::value_type(ad.nexthop, open_ipdump(ad.nexthop, "a")));
      }
    }
    pathcount++;
    
    if(filelist){
      file = filelist->find(ad.nexthop);
      assert(file != filelist->end());
      
      fprintf(file->second, "AS_PATH:");
      for(iter = ad.path.begin(); iter != ad.path.end(); ++iter){
	fprintf(file->second, " %d", *iter);
      }
      fprintf(file->second, "\nSTATUS: %d\n", ad.metric);  
      fprintf(file->second, "NEXT_HOP: %d.%d.%d.%d\n", 
	      (ad.nexthop >> (24))&0xff, (ad.nexthop >> (16))&0xff, 
	      (ad.nexthop >> (8))&0xff, (ad.nexthop)&0xff);
      fprintf(file->second, "%s: %d.%d.%d.%d/%d\n", 
	      ad.type?"WITHDRAWN":"ANNOUNCED",
	      (ad.prefix >> (24))&0xff, (ad.prefix >> (16))&0xff, 
	      (ad.prefix >> (8))&0xff, (ad.prefix)&0xff, ad.plen);
    }  
    
    entry->second->push_back(ad);
    return 0;
  } else {
    if(!ad.type){
      //withdraws don't have paths.
      myas = get_as_from_path(ad.path);
    }
    if(destip == 0){
      send_ad(ad, write_fd);
    } else {
      //XXX serve the grassroots ad here too.
      send_minisock_ad(ad, write_fd);
    }
    return 1;
  }
  return 0;
}

ad_db *read_showipbgp(FILE *input, int best_only, std::vector<unsigned int> *iplist){
  ad_db *dump = NULL;
  int len;
  char *line;
  int line_count = 0;
  int path_count = 0;
  Advertisement ad;

  if(write_fd < 0){
    dump = new ad_db();
  }

  ad.originflags = 1;
  ad.type = 0;
  ad.destination = 0;
  ad.community = 0;
  ad.time = 0;

  while(!feof(input)){
    line = my_fgetln(input, &len);
    
    line_count ++;
    if((len <= 61)||(line[0] != '*')){ //make sure the line is complete
      //the input file places a * before every advertisement
      //everything else is commentary
      continue;
    }
    path_count ++;
	
    //printf("Path %d; len : %d\n", path_count, len);
	
    //extract the network (characters 3-19 inclusive) if present
    //(we can cheat... if char 3 is a " ", we know there's no prefix here
    if(line[3] != ' '){
      unsigned char tmp;
      ad.prefix = extract_prefix(&(line[3]), MIN(17,len-3), &(tmp));
      ad.plen = (char)tmp;
    }
		
    //the prefix might be omitted on some lines... in this case we
    //use the most recently seen prefix.  We want to create an ad
    //for the "best", denoted by a > at char 1.  Everything else we can
    //safely discard
    if(line[1] != '>'){
      if(best_only) continue;
    }
		
    //now we get the next hop
    ad.nexthop = extract_ip(&(line[22]), MIN(15,len-22));
    if(iplist != NULL){
      ip_add(ad.nexthop, iplist);
    }

    //and the metric
    ad.metric = extract_num(&(line[37]), MIN(10,len-37));
		
    //and finally the path
    ad.path = extract_path(&(line[63]), len-63, &(ad.originflags));
    //ad.path.insert(ad.path.begin(), as);
		
    //and now store the path
    add_ad(dump, ad);
    //break;
  }

  return dump;
}

ad_db *read_dump(FILE *file, std::vector<unsigned int> *iplist, ad_db *dump){
  Advertisement ad;
  int len;
  char *line, *param;
  int found = 0;

  ad.originflags = 1;
  ad.type = 0;
  ad.destination = 0;
  ad.community = 0;
  ad.time = 0;
  me = 0;

  if(write_fd < 0 && dump == NULL){
    dump = new ad_db();
  }

  char *orig_line = NULL;
  while(!feof(file)){
    if(orig_line != NULL) {
      free(orig_line);
      orig_line = NULL;
    }
    if(fast_test) {
      if(dump->size() > 20000) {
        printf("fast dump, exiting\n");
        break;
      }
    }
    line = my_fgetln(file, &len);
    orig_line = strdup(line);
    
    if(find_param(line, &param)){
      if(strlen(line) <= 0){
        continue;
      }
      found = 1;
      if(strcmp(line, "PREFIX") == 0){
        ad.prefix = extract_prefix(param, strlen(param), &(ad.plen));
      } else if((strcmp(line, "NEXT_HOP") == 0)||((strcmp(line, "FROM") == 0))) {
        ad.nexthop = extract_ip(param, strlen(param));
        if(iplist != NULL){
          ip_add(ad.nexthop, iplist);
        }
      } else if(strcmp(line, "STATUS") == 0) {
        ad.metric = extract_num(param, strlen(param));
      } else if(strcmp(line, "AS_PATH") == 0){
        ad.path = extract_path(param, strlen(param), &(ad.originflags));
      } else if((strcmp(line, "WITHDRAWN") == 0)||(strcmp(line, "WITHDRAW") == 0)) {
        ad.prefix = extract_prefix(param, strlen(param), &(ad.plen));
        found = 0;
        ad.type = 1;
        //if(add_ad(dump, ad)) break;
        add_ad(dump, ad); 
        ad.type = 0;
      } else if((strcmp(line, "ANNOUNCED") == 0)||(strcmp(line, "ANNOUNCE") == 0)) {
        ad.prefix = extract_prefix(param, strlen(param), &(ad.plen));
        found = 0;
        ad.type = 0;
        //if(add_ad(dump, ad)) break;
        add_ad(dump, ad);
      } else if(strcmp(line, "SEGMENT_DONE") == 0) {
        printf("Completed transmitting segment: %s\n", param);
        if(found){
          found = 0;
          //if(add_ad(dump, ad)) break;
          add_ad(dump, ad);
          ad.type = 0;
        }
        break;
      } else if(strcmp(line, "TEXT_FILE") == 0) {	
        FILE *tmp;
        printf("Opening text sub-file : '%s'\n", param);
        tmp = fopen(param, "r");
        if(tmp){
          read_dump(tmp, iplist, dump);
          fclose(tmp);
        } else {
          perror("Can't open file");
        }
        found = 0;
      } else if(strcmp(line, "IPBGP_FILE") == 0) {	
        FILE *tmp;
        printf("Opening ibgp sub-file : '%s'\n", param);
        tmp = fopen(param, "r");
        if(tmp){
          read_showipbgp(tmp, 0, iplist);
          fclose(tmp);
        } else {
          perror("Can't open file");
        }
        found = 0;
      } else if(strcmp(line, "SENT_TO") == 0) {
        ad.nexthop = me;
        ad.destination = extract_ip(param, strlen(param));
      } else if(strcmp(line, "RECEIVED_FROM") == 0) {
        ad.destination = me;
        ad.nexthop = extract_ip(param, strlen(param));
      } else if(strcmp(line, "ME") == 0) {
        me = extract_ip(param, strlen(param));
      } else if(strcmp(line, "COM") == 0) {
        printf("%s\n", param);
      } else if(strcmp(line, "USERWAIT") == 0) {
        printf("%s\n[press any key to continue]", param);
        getchar();
      } else if(strcmp(line, "COMMUNITY") == 0) {
        if(strncmp(param, "0x", 2) == 0){
          sscanf(param, "0x%x", &ad.community);
        } else {
          ad.community = atoi(param);
        }
      } else if(strcmp(line, "TIME") == 0) {
        char *time_start = orig_line+6;
        //2009-1-5 00:10:30
#if 0
        for(int i=0; i < 1; i++) {
          time_start = strchr(time_start, ' ');
          if(time_start == NULL) {
            goto bad_time;
          }
          // printf("T[%d] '%s'", i, time_start);
          time_start++;
        }
#endif
        // printf("Str '%s'", time_start);
        ad.time = -1;
        if(time_start != NULL) {
          struct tm tm;
          char *rem;
          //if((rem = strptime(time_start, "%H:%M:%S", &tm)) != NULL) {
          if((rem = strptime(time_start, "%Y-%m-%d %H:%M:%S", &tm)) != NULL) {
            //printf("TimeStart = %s, Rem = '%s'\n", time_start,rem);
            ad.time = mktime(&tm);
            // printf("Time = %u\n", ad.time);
          } else {
            goto bad_time;
          }
        }
      bad_time: ;
      }
    } else {
      if(found){
        found = 0;
        //if(add_ad(dump, ad)) break;
        add_ad(dump, ad);
        ad.type = 0;
      }
    }
  }
  
  return dump;
}

struct mrt_header {
        uint32_t time;
        uint16_t type;
        uint16_t subtype;
        uint32_t length;
} __attribute__((packed));

struct msg_table_hdr {
        uint16_t viewno;
        uint16_t seqnum;
        in_addr_t prefix;
        uint8_t prefixlen;
        uint8_t status;
        uint32_t originated;
        in_addr_t peerip;
        uint16_t source_as;
        uint16_t attr_len;
} __attribute__((packed));

//typedef vector<bgp_attribute> bgp_attributes;

#define MRT_MSG_TABLE_DUMP (12)
#define MRT_AFI_IP (1)
#define MRT_ATTR_FLAG_EXTLEN (0x10)

#define MRT_BGP_ATTR_ORIGIN                   ( 1 )
#define MRT_BGP_ATTR_AS_PATH                  ( 2 )
#define MRT_BGP_ATTR_NEXT_HOP                 ( 3 )
#define MRT_BGP_ATTR_MULTI_EXIT_DISC  ( 4 )
#define MRT_BGP_ATTR_LOCAL_PREF               ( 5 )
#define MRT_BGP_ATTR_ATOMIC_AGGREGATE ( 6 )
#define MRT_BGP_ATTR_AGGREGATOR               ( 7 )
#define MRT_BGP_ATTR_COMMUNITIES              ( 8 )
/*
#sub BGP_ATTR_ORIGINATOR_ID()   { 9 }
#sub BGP_ATTR_CLUSTER_LIST()            { 10 }
##sub BGP_ATTR_DPA()                            { 11 }
#sub BGP_ATTR_ADVERTISER()              { 12 }
##sub BGP_ATTR_RCID_PATH()              { 13 }
*/
#define MRT_BGP_ATTR_MP_REACH_NLRI    ( 14 )
#define MRT_BGP_ATTR_MP_UNREACH_NLRI  ( 15 )
#define MRT_BGP_ATTR_EXT_COMMUNITIES  ( 16 )

int num_as_set = 0;

void parse_attributes(uint8_t *attr_pkt, int all_attr_len, Advertisement *ad) {
        int i = 0;
        while(i < all_attr_len) {
                if(all_attr_len - i < 2) {
                        printf("not enough space left for attribute header\n");
                        break;
                }
                // (flags, type) = (C C)
                // ext: n/a
                // non-ext: C/a
                uint8_t flags, type;
                flags = attr_pkt[i];
                type = attr_pkt[i + 1];
                int attr_len = 0;
                i += 2;
                if(flags & MRT_ATTR_FLAG_EXTLEN) {
                        uint16_t _len;
                        _len = *(uint16_t*) (attr_pkt + i);
                        i+= 2;
                        attr_len = ntohs(_len);
                        printf("ext len %d\n", attr_len);
                        return;
                } else {
                        uint8_t _len;
                        _len = attr_pkt[i];
                        i += 1;
                        attr_len = _len;
                }
        /*
          y ad.prefix &ad.prefixlen
          y? ad.nexthop ip_add(ad.nexthop, iplist);
          y ad.metric
          n? ad.path &ad.originflags
          n? ad.destination
          n? ad.community
        */
                switch(type) {
                case MRT_BGP_ATTR_AS_PATH: {
                        for(int j = 0; j < attr_len; ) {
                                // AS_SEQUENCE == 2
                                uint8_t type = attr_pkt[i + j],
                                        length = attr_pkt[i + j + 1];
                                j += 2 + 2 * length;
                                uint16_t *seq = (uint16_t *)(attr_pkt + i + 2);
                                if(type != 2) {
                                  if(length != 1) {
                                    static int limit = 0;
                                    if(limit < 5) {
                                      printf("as path only properly handles as sequence (type = %d, set len = %d)\n", type, length);
                                      limit++;
                                    }
                                    num_as_set++;
                                  }
                                }
                                for(int k = 0; k < length; k++) {
                                        ad->path.push_back(ntohs(seq[k]));
                                }
                        }
                        break;
                }
                case MRT_BGP_ATTR_NEXT_HOP:
                        assert(attr_len == 4);
                        ad->nexthop = ntohl(*(in_addr_t *)(attr_pkt + i));
                        break;
                case MRT_BGP_ATTR_COMMUNITIES:
                        // perl zebra script handles this, but bgpdump.cc doesn't appear to do the right thing
                        break;
                case MRT_BGP_ATTR_ORIGIN:
                case MRT_BGP_ATTR_MULTI_EXIT_DISC:
                case MRT_BGP_ATTR_LOCAL_PREF:
                case MRT_BGP_ATTR_ATOMIC_AGGREGATE:
                case MRT_BGP_ATTR_AGGREGATOR:
                case MRT_BGP_ATTR_MP_REACH_NLRI:
                case MRT_BGP_ATTR_MP_UNREACH_NLRI:
                        break;
                case MRT_BGP_ATTR_EXT_COMMUNITIES:
                        // perl ver of zebra script doesn't handle this
                default:
                        printf("unknown BGP attribute %d\n", type);
                        break;
                }
                i += attr_len;
        }
}

void str_localtime(char *buf, time_t time) {
        struct tm *tm = localtime(&time);
        strftime(buf, 80, "%F %T", tm);
}

char *str_ip(in_addr_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        return inet_ntoa(addr);
}

ad_db *read_rib_dump(FILE *file, std::vector<unsigned int> *iplist){
#define READ_BUF_SIZE (16384)
        uint8_t buf[READ_BUF_SIZE * 2]; // always read_buf_size; allocate extra at the end in case start_offset != 0
        int start_offset = 0;
        ad_db *dump = new ad_db();
        while(1) {
                int read_len = fread(buf + start_offset, 1, READ_BUF_SIZE, file);
                int buf_len = start_offset + read_len;
                int i = 0;
                start_offset = 0;
                while(i < buf_len) {
                        if((buf_len - i) < (int) sizeof(mrt_header)) {
                                goto incomplete;
                        }
                        mrt_header hdr;
                        memcpy(&hdr, buf + i, sizeof(hdr));
                        hdr.time = ntohl(hdr.time);
                        hdr.type = ntohs(hdr.type);
                        hdr.subtype = ntohs(hdr.subtype);
                        hdr.length = ntohl(hdr.length);

                        if( (buf_len - i) < (int)sizeof(mrt_header) + (int)hdr.length) {
                        incomplete:
                                memcpy(buf, buf + i, buf_len - i);
                                start_offset = buf_len - i;
                                break;
                        }

                        uint8_t *pkt = buf + i + sizeof(hdr);
                        i += sizeof(hdr) + hdr.length;
                        switch(hdr.type) {
                        case MRT_MSG_TABLE_DUMP: {
                                if(hdr.subtype != MRT_AFI_IP) {
                                        printf("unknown msg table subtype %d\n", hdr.subtype);
                                        break;
                                }
                                msg_table_hdr thdr;
                                if(hdr.length < sizeof(thdr)) {
                                        printf("msg table packet too short!\n");
                                        break;
                                }

                                // my ($viewno, $seq_num, $prefix, $prefixlen, $status, $originated, $peerip, $source_as, $attributes) 
                                //n n a4 C C N a4 n n/a
                                memcpy(&thdr, pkt, sizeof(thdr));
                                thdr.viewno = ntohs(thdr.viewno);
                                thdr.seqnum = ntohs(thdr.seqnum);
                                thdr.originated = ntohl(thdr.originated);
                                thdr.source_as = ntohs(thdr.source_as);
                                thdr.attr_len = ntohs(thdr.attr_len);
                                if(thdr.attr_len > hdr.length - sizeof(thdr)) {
                                        printf("too many attrs for mrt packet!\n");
                                        break;
                                }
                                if(thdr.attr_len < hdr.length - sizeof(thdr)) {
                                        printf("Warning: table attr_len < mrt packet len!\n");
                                }
                                Advertisement ad;
                                ad.originflags = 1;
                                ad.type = 0;
                                ad.destination = 0;
                                ad.community = 0;
                                ad.time = hdr.time;

                                /*
                                  y ad.prefix &ad.prefixlen
                                  y? ad.nexthop ip_add(ad.nexthop, iplist);
                                  y ad.metric
                                  n? ad.path &ad.originflags
                                  n? ad.destination
                                  n? ad.community
                                 */
                                ad.prefix = ntohl(thdr.prefix);
                                ad.plen = thdr.prefixlen;
                                ad.nexthop = ntohl(thdr.peerip);
                                ad.metric = thdr.status;
                                parse_attributes(pkt + sizeof(thdr), thdr.attr_len, &ad);
                                add_ad(dump, ad);

                                if(0) {
                                        // print out AD contents
                                        char time_str[80];
                                        str_localtime(time_str, ad.time);
                                        printf("TIME: %s\n", time_str);
                                        printf("TYPE: MSG_TABLE_DUMP/AFI_IP\n");
                                        printf("VIEW: %d  SEQUENCE: %d\n", thdr.viewno, thdr.seqnum);
                                        printf("PREFIX: %s/%d\n", str_ip(ad.prefix), ad.plen);
                                        time_t t = thdr.originated;
                                        printf("STATUS: %d  ORIGINATED: %s", ad.metric, ctime(&t));
                                        printf("FROM: %s AS%d\n", str_ip(thdr.peerip), thdr.source_as);

                                        printf("AS_PATH: ");
                                        for(unsigned j=0; j < ad.path.size(); j++) {
                                                printf("%d ", ad.path[j]);
                                        }
                                        printf("\n");
                                        printf("NEXT_HOP: %s\n", str_ip(ad.nexthop));
                                        printf("\n");
                                }

                                if(fast_test) {
                                  static int ad_count = 0;
                                  if(ad_count++ > 10000) {
                                    printf("last ad\n");
                                    goto last_entry;
                                  }
                                }
                                break;
                        }
                        default:
                                printf("Unknown MRT type %d\n", hdr.type);
                        }
                }
                if(read_len < READ_BUF_SIZE) {
                        if(start_offset != 0) {
                                printf("Last mrt chunk was incomplete! (%d left)\n", 
                                       start_offset);
                        }
                        break;
                }
        }
 last_entry:
        return dump;

#undef READ_BUF_SIZE
}

ad_db *read_dump(FILE *file, std::vector<unsigned int> *iplist){
  return read_dump(file, iplist, NULL);
}

ad_db *read_generic_file(FILE *f, std::vector<unsigned int> *iplist, int file_type){
  switch(file_type){
  case 0:
  case 1:
    return read_showipbgp(f, file_type, iplist);
    break;
  case 2:
    return read_dump(f, iplist);
    break;
  case 3:
    return read_rib_dump(f, iplist);
    break;
  }

  return NULL;
}

ad_db *read_generic_file(FILE *f, std::vector<unsigned int> *iplist) {
  return read_generic_file(f, iplist, source_file_type);
}

void send_open(unsigned short as, int fd){
  printf("Opening with AS %d\n", (int) as);
  cork(fd);
  BGP_Header p_head;
  BGP_Open p_open;
  
  memset(&(p_head.marker), 0xff, 16);
  p_head.len = htons(BGP_HEADER_SIZE+BGP_OPEN_SIZE);
  p_head.type = 1;//OPEN
  p_open.version = 4;
  p_open.asid = htons(as);
  p_open.holdtime = htons(BGP_TIMEOUT);
  p_open.bgpident = htonl(myip);
  p_open.optlen = 0;
  
  my_write(fd, &p_head, BGP_HEADER_SIZE);
  my_write(fd, &p_open, BGP_OPEN_SIZE);
  
  p_head.len = htons(BGP_HEADER_SIZE);
  p_head.type = 4;//KEEPALIVE
  my_write(fd, &p_head, BGP_HEADER_SIZE);
  uncork(fd);
}

void usage(char *app){
  printf ("usage: \n%s -d DUMPFILE [options]\n", app);
  printf ("%s -t PLAINTEXT [options]\n", app);
  printf ("%s -s IP [options]\n", app);
  printf ("%s -b BGPFILE [options]\n", app);
  printf ("%s -r BGPFILE(RIB-only) [options]\n", app);
  printf ("  -o      : Output plaintext for all component sources to ip.src\n");
  printf ("  -s IP   : Serve the BGP Database originated by IP.  \n");
  printf("             Optionally precede with -t or -d to specify a file\n");
  printf ("  -p PORT : Serve BGP Database on port PORT\n");
  printf ("  -u      : Same as -o, except concatenate output to updates/ip.src\n");
  printf ("  -n IP   : Serve remote sniffer trace to an nbgp monitor monitoring IP\n");
  printf ("  -i AS   : Detect iBGP peers (specifying my as)\n");
  printf ("  -v IP/n : View all advertisements for this prefix\n");
  exit(0);
}

ad_list *get_list(ad_db *db, unsigned int ip){
  ad_db::iterator entry = db->find(ip);
  
  if(entry == db->end()) {
    return NULL;
  }
  return entry->second;
}

int init_server(unsigned short port){
  int serv;
  struct sockaddr_in saddr;

  serv = socket(AF_INET, SOCK_STREAM, 0);
	
  if(serv < 0){
    perror("Error: Unable to initialize server socket");
    exit(1);
  }
	
  int one = 1;
  if (setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
    perror("warning: setsockopt");
	
  bzero((char *)&saddr, sizeof(struct sockaddr_in));
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(port);
  saddr.sin_family = AF_INET;
	
  if(bind(serv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to bind socket");
    exit(1);
  }
	
  if(listen(serv, 10) < 0){
    perror("Error: Unable to configure server socket for listening");
    exit(1);
  }

  return serv;
}

void serve_nexus(FILE *dump){ 
  int serv, client;
  int len;
  struct sockaddr_in addr;
  std::vector<unsigned int> iplist;
  pid_t is_parent = 1;
  pid_t last_child = 0;
  int childstat;
  
  serv = init_server(myport);
  
  while(is_parent){
    printf("Waiting for connection on port %d...\n", myport);
    
    len = sizeof(struct sockaddr_in);
    if((client = accept(serv, (struct sockaddr *)&addr, (socklen_t *)&len)) < 0){
      perror("Error: Failed to accept\n");
      exit(1);
    }

    printf("Connection open\n");
    
    if(last_child){
      kill(last_child, SIGQUIT);
      waitpid(last_child, &childstat, 0);
    }
    fseek(dump, 0, SEEK_SET);
    
    is_parent = fork();
    last_child = is_parent;
    //printf("forked: %d\n", is_parent); 
    //if(is_parent){detach(is_parent);}
    //detach?
  }
  
  //fcntl(client, F_SETFL, O_NONBLOCK);
  write_fd = client; //tell read_dump to write directly to write_fd
  //if we're in here, destip != 0, and so read_dump will write nbgp compatible
  //output
  read_generic_file(dump, &iplist);

  printf("Done with dump; sleeping\n");

  while(1) {
    char buff[500];
    if(read(client, buff, sizeof(buff)) <= 0){
      break;
    }
  }
  
  printf("Connection closed.  Quitting.\n");
}

ad_db update_dumps;
volatile int g_fsm_state = 0;
volatile int seq_send_limit = 0;

void sig_advance_fsm(int v) {
  printf("%lf: USR2 Dump stats and advance FSM\n", doubleTime());
  printf("%d=>%d\n", g_fsm_state, g_fsm_state + 1);
  g_fsm_state += 1;
  seq_send_limit++;
  print_all();
}

void wait_until(double target_time) {
  double delta = target_time - doubleTime();
  if(delta > 0) {
    struct timespec spec, rem;
    spec.tv_sec = (time_t)floor(delta);
    const int N = 1000000000;
    spec.tv_nsec = (long int)(N * (delta - spec.tv_sec));
    if(spec.tv_nsec >= N) {
      spec.tv_nsec -= N;
      spec.tv_sec++;
    }
    while(nanosleep(&spec, &rem) != 0) {
      assert(errno == EINTR);
      spec = rem;
    }
  }
}

void send_updates(unsigned int ip, int fd);

void run_fsm(unsigned int ip, int fd) {
#if 0
  int last_sent_seq = 0;
  while(1) {
    sleep(1); // signal should wake us up from sleep
    if(doubleTime() - last_keepalive_time > 1.0) {
      send_keepalive(fd);
      last_keepalive_time = doubleTime();
    }
    while(last_sent_seq < seq_send_limit) {
      printf("%lf: Sending update %d\n", doubleTime(), last_sent_seq);
      assert(last_sent_seq == seq_send_limit - 1);
      send_ad(*iter, fd);
      ++last_sent_seq;
      ++iter;
      if(iter == update_list->end()) {
        goto done;
      }
    }
  }
 done:
  ;
#else
  // always send at integer ticks
  while(g_fsm_state == 0) {
    printf("%lf: waiting for fsm kick\n", doubleTime());
    sleep(1);
  }
  fflush(stdout);
  send_updates(ip, fd);

#endif
}

void send_updates(unsigned int ip, int fd) {
  ad_list *update_list;
  if((update_list = get_list(&update_dumps, ip)) == NULL){
    printf("No updates for ip!\n");
    exit(-1);
  }

  std::vector<Advertisement>::const_iterator iter;
  // for(iter = update_list->begin(); iter != list->end(); ++iter){
  double last_keepalive_time = 0.0;

  wait_until(floor(doubleTime()) + 1);

  int skip_count = 0;
  for(iter = update_list->begin(); (*iter).time < last_dump_send_time; ++iter) {
    skip_count++;
  }
  fprintf(stderr, "Skipped %d update entries\n", skip_count);

  int first_trace_second = 0;
  fprintf(stderr, "Total amount = %d\n", update_list->size());
  while(iter != update_list->end()) {
    if(doubleTime() - last_keepalive_time > 1.0) {
      send_keepalive(fd);
      last_keepalive_time = doubleTime();
    }

    double start_time = doubleTime();
    // send out all in this tick

    int send_count = 0;
    printf("%lf: Sending out\n", doubleTime());
#undef PING
    int trace_second;
    for( trace_second = (*iter).time; iter != update_list->end() &&
           (*iter).time == trace_second; ++iter, ++send_count) {
      if(first_trace_second == 0) {
        first_trace_second = trace_second;
      }
      send_ad(*iter, fd);
    }
    printf("%lf: Sent out %d at trace tick %d \n", doubleTime(), send_count, trace_second - first_trace_second);

    wait_until(floor(start_time) + 1);
    double curr_time = doubleTime();
    if(curr_time - start_time > 1.1) {
      printf("XXXXX Trace played back too slowly! delta = %lf\n", curr_time - start_time);
    }
    fflush(stdout);

    static int tick_count = 0;
    if(fast_test && tick_count++ > 20) {
      printf("Fast test: terminating after 20 ticks\n");
      break;
    }
  }
  printf("Done with trace\n");
  fflush(stdout);
}

int main(int argc, char **argv){
        myip = ntohl(inet_addr("128.84.227.47"));
        cornellip = ntohl(inet_addr("128.84.227.47"));
  FILE *dump = NULL;
  std::vector<unsigned int> iplist;
  int opt;
  int dump_file = 0;
  ad_db *RIB;
  ad_list *srv_list;
  int serv, client;
  int ip = 0;
  int ip_str[4];
  struct sockaddr_in saddr, addr;
  int len;
  pthread_t reader;
  std::vector<string> update_filenames;
  bool single_step = false;

  signal(SIGINT, sig_break);
  signal(SIGUSR2, sig_advance_fsm);
  signal(SIGPIPE, sigpipe);
  atexit(print_all);

  while((opt = getopt(argc, argv, "?d:t:os:p:un:b:i:v:r:fU:SA")) >= 0) {
    switch(opt){
    case 'd':
      if(dump) usage(argv[0]);
      dump_file = 1;
      dump = open_dump(optarg);
      break;
    case 't':
      if(dump) usage(argv[0]);
      dump = fopen(optarg, "r");
      break;
    case 'r':
      if(dump) usage(argv[0]);
      dump_file = 1;
      // xxx use bzopen for better mem footprint?;
      dump = fopen(optarg, "r");
      source_file_type = 3;
      break;
    case 'U': /* "Update"  */ {
      char buf[80];
      FILE *update_spec = fopen(optarg, "r");
      while(fgets(buf, sizeof(buf), update_spec) != NULL) {
        *strchr(buf, '\n') = '\0';
        FILE *t = fopen(buf, "r");
        if(t == NULL) {
          printf("Could not open %s from specfile!\n", buf);
        }
        fclose(t);
        update_filenames.push_back(buf);
      }
      break;
    }
    case 'S': // Single step
      single_step = true;
      break;
    case 'u':
      ip_update = 1;
      break;
    case 'o':
      filelist = new std::map<unsigned int, FILE *>();
      break;
    case 'p':
      myport = atoi(optarg);
      break;
    case 's':
      sscanf(optarg, "%d.%d.%d.%d", &(ip_str[0]), &(ip_str[1]), &(ip_str[2]), &(ip_str[3]));
      ip = ((ip_str[0] & 0xff) << 24) | ((ip_str[1] & 0xff) << 16) |
	((ip_str[2] & 0xff) <<  8) | ((ip_str[3] & 0xff) <<  0);
      if(!dump) { dump = open_ipdump(ip, "r"); }
      break;
    case 'n':
      sscanf(optarg, "%d.%d.%d.%d", &(ip_str[0]), &(ip_str[1]), &(ip_str[2]), &(ip_str[3]));
      destip = ((ip_str[0] & 0xff) << 24) | ((ip_str[1] & 0xff) << 16) |
	((ip_str[2] & 0xff) <<  8) | ((ip_str[3] & 0xff) <<  0);
      break;
    case 'b':
      if(dump) usage(argv[0]);
      source_file_type = 0;
      dump = fopen(optarg, "r");
      break;
    case 'i':
      printf("Scanning for iBGP peers\n");
      myas = atoi(optarg);
      ipeers = new std::vector<unsigned int>();
      break;
    case 'v':
      display_p = extract_prefix(optarg, strlen(optarg), &display_p_len);
      printf("Showing all advertisements for ");print_ip(display_p, 0);printf("/%d\n", display_p_len);
      break;
    case 'f':
      fast_test = 1;
      printf("Running fast test\n");
      break;
    case '?':
    default:
      if(opt != '?') printf("Unknown option: -%c\n", opt);
      usage(argv[0]);
    }
  }

  if(!dump) {
    printf("You must specify a file\n");
    usage(argv[0]);
  }

  if(destip != 0){
    serve_nexus(dump);
    exit(0);
  }

  RIB = read_generic_file(dump, &iplist);
  
  if(ipeers) { 
    exit(0);
  }
  
  printf("Finished loading: %d paths over %d sources, %d AS set > 1\n", pathcount, ipcount, num_as_set);
  
  // if we're not serving, we're done here
  if(ip == 0) {
          printf("Statistics from load:\n");
          printf("List contents: ");
          for(ad_db::iterator i = RIB->begin(); i != RIB->end(); i++) {
                  struct in_addr addr;
                  addr.s_addr = i->first;
                  if(0) {
                  printf("IP=%s: AS=%d, len=%d\n", 
                         inet_ntoa(addr), get_as(i->second), i->second->size());
                  } else { // for AS db
                    addr.s_addr = ntohl(addr.s_addr);
                    printf("%s %d\n", inet_ntoa(addr), get_as(i->second));
                  }
          }
          exit(0);
  }

  ip_update = 0;

  if((srv_list = get_list(RIB, ip)) == NULL){
    printf("I don't have an RIB for that source IP\n");
    printf("Source IP: "); print_ip(ip, 0); printf("\n");
    exit(1);
  }

  printf("RIB length is %d\n", srv_list->size());
  
  printf("Creating BGP Server on port %d for AS %d\n", myport, get_as(srv_list));
  serv = socket(AF_INET, SOCK_STREAM, 0);
	
  if(serv < 0){
    perror("Error: Unable to initialize server socket");
    exit(1);
  }
	
  int one = 1;
  if (setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
    perror("warning: setsockopt");
	
  bzero((char *)&saddr, sizeof(struct sockaddr_in));
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(myport);
  saddr.sin_family = AF_INET;
	
  if(bind(serv, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0){
    perror("Error: Unable to bind socket");
    exit(1);
  }
	
  if(listen(serv, 10) < 0){
    perror("Error: Unable to configure server socket for listening");
    exit(1);
  }

  std::vector<unsigned int> update_iplist;
  printf("Loading update files\n");
  for(size_t i=0; i < update_filenames.size(); i++) {
    FILE *fp = open_dump(update_filenames[i].c_str());
    read_dump(fp, &update_iplist, &update_dumps);
    printf("Read '%s'\n", update_filenames[i].c_str());
  }
  std::vector<Advertisement>::const_iterator iter;
  int last_trace_second = 0;
int update_count = 0;
  printf("Doing integrity check on update list\n");
  ad_list *update_list = get_list(&update_dumps, ip);
  int num_distinct_ticks = 0;
  for(iter = update_list->begin(); iter != update_list->end(); ++iter) {
    assert(last_trace_second <= (*iter).time);
    if(last_trace_second != (*iter).time) {
      num_distinct_ticks++;
    }
    last_trace_second = (*iter).time;
    update_count++;
  }
  printf("Done with loading, %d total updates, %d ticks\n", update_count, num_distinct_ticks);
  fflush(stdout);

  printf("Waiting for connection on port %d...\n", myport);
  
  len = sizeof(struct sockaddr_in);
  if((client = accept(serv, (struct sockaddr *)&addr, (socklen_t *)&len)) < 0){
    perror("Error: Failed to accept\n");
    exit(1);
  }
  
  //fcntl(client, F_SETFL, O_NONBLOCK);
  
  pthread_create(&reader, NULL, (void* (*)(void*))read_packet_proc, (void *)client);

  short AS_num = get_as(srv_list);

  printf("Sending open\n");
  send_open(AS_num, client);
  printf("%lf: Sending data dump\n", doubleTime());
  send_dump(srv_list, client);
  printf("%lf: Done with data dump\n", doubleTime());
  fflush(stdout);
  fsync(fileno(stdout));
  fclose(dump);

  if(update_filenames.size() == 0) {
    write_fd = client; //tell read_dump to read directly to write_fd
    ip_update = 1; //tell open_ipdump to open update files
    dump = open_ipdump(ip, "r");

    while(1){
      printf("Sending keepalive\n");
      send_keepalive(client);
      if(dump)
        read_generic_file(dump,&iplist);
      sleep(hold_time);
    }
  } else {
    run_fsm(ip, client);
  }
}
