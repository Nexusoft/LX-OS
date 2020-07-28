#include <iostream>
#include <getopt.h>
#include <vector>
#include <map>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <map>

#include "../../../include/enc/openssl_compat.h"
#include "../../../include/util/common.h"
#include "../../../include/nbgp/grassroots.h"

static int verbose = 0;

void usage(char *appname){
  printf("usage: %s infile outfile\n", appname);
  exit(0);
}

int load_prefix(char *buff, Grassroots::IP_ADDR *prefix, Grassroots::IP_MASKLEN *prefixlen){
  char *slash = strstr(buff, "/");
  if((!slash) || (*slash != '/')){ return 0; }
  *slash = '\0';
  slash++;
  *prefix = inet_addr(buff);
  *prefixlen = atoi(slash);
  return 1;
}


void load_db(Grassroots *grassroots_db, char *fname){
  FILE *infile;
  std::map<Grassroots::AS_ID,Grassroots::HASH *> as_claims;
  std::map<Grassroots::AS_ID,Grassroots::HASH *>::iterator as_info;
  char buff[100];
  
  if(strcmp("^", fname) == 0){
    infile = stdin;
  } else {
    infile = fopen(fname, "r");
  }
  if(!infile){
    printf("Can't open %s\n", fname);
    exit(1);
  }
  
  while(!feof(infile)){
    Grassroots::IP_ADDR prefix;
    Grassroots::IP_MASKLEN prefix_len;
    Grassroots::AS_ID as;
    
    if(fscanf(infile, "%hd %99s", &as, buff) < 2) {
      continue;
    }
    if(!load_prefix(buff, &prefix, &prefix_len)){
      printf("skipping: %s\n", buff);
      continue;
    }
    as_info = as_claims.find(as);
    if(as_info == as_claims.end()){
      Grassroots::KEY *k = new Grassroots::KEY(OK_privkey_create());
      Grassroots::HASH *h = grassroots_db->load_key(k);
      grassroots_db->start_batch(h);
      if(verbose) { 
        printf("Creating key for : %d = ", as); 
        h->print(stdout);
        printf("\n");
      }
      as_claims[as] = h;
      as_info = as_claims.find(as);
      assert(as_info != as_claims.end());
    }
    grassroots_db->preclaim(as_info->second, as, prefix, prefix_len);
  }
  grassroots_db->sign_all();
  for(as_info = as_claims.begin(); as_info != as_claims.end(); ++as_info){
    grassroots_db->end_batch(as_info->second);
  }
}
void export_db(Grassroots *grassroots_db, char *fname){
  grassroots_db->export_db(fname);
}
void import_db(Grassroots *grassroots_db, char *fname){
  grassroots_db->import_db(fname);
}

int main(int argc, char **argv){
  Grassroots *grassroots_db = new Grassroots(19401);
  int opt;
  
  while((opt = getopt(argc, argv, "vl:e:i:")) >= 0){
    switch(opt){
      case 'v':
        verbose = 1;
        break;
      case 'l':
        load_db(grassroots_db, optarg);
        break;
      case 'e':
        export_db(grassroots_db, optarg);
        break;
      case 'i':
        import_db(grassroots_db, optarg);
        break;
      case '?':
      default:
        usage(argv[0]);
    }
  }
  return 0;
}


