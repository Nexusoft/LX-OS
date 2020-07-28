#include <iostream>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include "../../../include/util/common.h" 
#include "burst.h"

void usage(char *app){
  printf ("usage: %s [-p port] [-t timeout] [-a AS] input\n", app);
}

char *my_fgetln(FILE *f, int *len){
  static char ret[500];
  *len = 0;

  do {
    ret[*len] = fgetc(f);
    (*len)++;
    assert(*len < 500);
    //printf("read: %c %d\n", ret[*len], ret[*len]);
  } while((!feof(f))&&(ret[(*len)-1] != '\n'));
  //printf("done\n");
  return ret;
}

unsigned int extract_ip(char *dat, unsigned int len){
  unsigned int curr, ip, i;
  curr = 0; ip = 0;
	
  for(i = 0; i < len; i++){
    switch(dat[i]){
    case '1': case '2': case '3': case '4': case '5':	
    case '6': case '7': case '8': case '9': case '0':
      curr *= 10;
      curr += (dat[i] - '0');
      break;
    default:
      i = len;
    case '.':
      ip <<= 8;
      ip += curr&0xFF;
      curr = 0;
      break;
    }		
  }
  return ip;
}

unsigned int extract_prefix(char *dat, unsigned int len, unsigned short *plen){
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
	
  *originflags = 0;
	
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
      *originflags |= 0x1;
      curr = 0;
      break;
    default:
      i = len;
      break;
    }
  }

  return path;
}

int main(int argc, char **argv){
  std::vector<Advertisement> ads;
  FILE *input;
  char *inputfile = NULL;
  int timeout = 60, port = 179;
  unsigned short as = 42;
  char c;
  char *line;
  int len;
  Advertisement ad;
  int line_count = 0, path_count = 0;
  int serv, client;
  struct sockaddr_in saddr, addr;
  BGP_Header p_head;
  BGP_Open p_open;
  BGP_Update p_update;
  int sleeptime = 3;
  //int maintain;
	
  while((c = getopt(argc, argv, "p:t:a:s:")) != -1){
    switch(c){
    case 'p':port = atoi(optarg); break;
    case 't':timeout = atoi(optarg); break;
    case 'a':as = (unsigned short)atoi(optarg); break;
    case 's':sleeptime = atoi(optarg); break;
    default: printf("%d\n", c);usage(argv[0]);
    }
  }
	
  if (optind < argc-1) usage(argv[0]);
  if (optind == argc-1)
    inputfile = argv[optind];
	
  if((input = fopen(inputfile, "r")) == NULL){
    perror("Error opening input file");
    exit(0);
  }
	
  printf("Loading input file\n");
  
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
      unsigned short tmp;
      ad.prefix = extract_prefix(&(line[3]), MIN(17,len-3), &(tmp));
      ad.plen = (char)tmp;
    }
		
    //the prefix might be omitted on some lines... in this case we
    //use the most recently seen prefix.  We want to create an ad
    //for the "best", denoted by a > at char 1.  Everything else we can
    //safely discard
    if(line[1] != '>'){
      continue;
    }
		
    //now we get the next hop
    ad.nexthop = extract_ip(&(line[20]), MIN(15,len-20));

    //and the metric
    ad.metric = extract_num(&(line[35]), MIN(10,len-35));
		
    //and finally the path
    ad.path = extract_path(&(line[61]), len-61, &(ad.originflags));
    ad.path.insert(ad.path.begin(), as);
		
    //and now store the path
    ads.push_back(ad);
    //break;
  }
	
  printf("\t...loaded %d/%d lines of paths including %d best paths\n", path_count, line_count, (int)ads.size());

  printf("Creating BGP Server\n");
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

  while(1){
    printf("Waiting for connection...\n");
    len = sizeof(struct sockaddr_in);
    if((client = accept(serv, (struct sockaddr *)&addr, (socklen_t *)&len)) < 0){
      perror("Error: Failed to accept\n");
       exit(1);
    }
    
    printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
    
    memset(&(p_head.marker), 0xff, 16);
    p_head.len = htons(BGP_HEADER_SIZE+BGP_OPEN_SIZE);
    p_head.type = 1;//OPEN
    p_open.version = 4;
    p_open.asid = htons(as);
    p_open.holdtime = htons(timeout);
    p_open.bgpident = htonl((128<<24)||(84<<16)||(223<<8)||101);
    p_open.optlen = 0;
    
    write(client, &p_head, BGP_HEADER_SIZE);
    write(client, &p_open, BGP_OPEN_SIZE);
    
    p_head.len = htons(BGP_HEADER_SIZE);
    p_head.type = 4;//KEEPALIVE
    write(client, &p_head, BGP_HEADER_SIZE);
    
    sleep(sleeptime);
    
    printf("Commencing burst...\n");
    
    std::vector<Advertisement>::const_iterator iter;
    std::vector<unsigned short>::const_iterator iter2;
    
    p_head.type = 2;//UPDATE
    p_update.withdrawn_len = 0;
    //p_update.attr_len//variable
    p_update.origin_fl = 0x40;//well known, short attribute
    p_update.origin_type = 1;
    p_update.origin_len = 1;
    //p_update.origin//variable
    p_update.nexthop_fl = 0x40;//well known, short attribute
    p_update.nexthop_type = 3;
    p_update.nexthop_len = 4;
    //p_update.nexthop//variable
    p_update.path_fl = 0x40;//well known short attribute
    p_update.path_type = 2;
    //p_update.path_len//variable
    p_update.path_segment = 2;//AS_SEQUENCE;
    
    unsigned short temp;
    unsigned int temp2;
    
    for(iter = ads.begin(); iter != ads.end(); ++iter){
      ad = *iter;
      
      p_update.origin = ad.originflags&0x01 ? 0 : 1;
      p_update.nexthop = htonl(ad.nexthop);
      p_update.path_segment_len = 2 * (char)ad.path.size();
      p_update.path_len = p_update.path_segment_len + 2;
      p_update.attr_len = htons(p_update.path_segment_len + 16);
      p_head.len = htons(BGP_HEADER_SIZE + BGP_UPDATE_SIZE + p_update.path_segment_len + (ad.plen+7)/8 + 1);
      //printf("size: %u, %u, %u, %u\n", p_head.len, (int)ad.path.size(), p_update.path_len, ad.plen);
      write(client, &p_head, BGP_HEADER_SIZE);
      write(client, &p_update, BGP_UPDATE_SIZE);
      for(iter2 = ad.path.begin(); iter2 != ad.path.end(); ++iter2){
	temp = htons(*iter2);
	write(client, &temp, sizeof(short));
      }
      write(client, &(ad.plen), sizeof(char));
      temp2 = htonl(ad.prefix);
      write(client, &temp2, (ad.plen+7)/8);
    }
    close(client);
  } //repeat ad infinitum
}
