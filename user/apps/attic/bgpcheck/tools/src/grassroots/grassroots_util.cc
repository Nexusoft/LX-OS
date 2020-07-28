#include <iostream>
#include <getopt.h>
#include <vector>
#include <map>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <assert.h>

#include "../../../include/util/common.h"
#include "grassroots_util.h"

std::map<AS,ASInfo> as_claims;

void PrefixTrie::put(Prefix &p, AS &owner, int depth, Grassroots::RawData *enc_cred){
  int bit = p.getbit(depth);
  if(bit < 0){
    owners.push_back(owner);
    if(enc_cred){
      enc_credentials.push_back(enc_cred);
    }
  } else {
    if(next[bit] == NULL){
      next[bit] = new PrefixTrie(this, bit);
    }
    next[bit]->put(p, owner, depth+1, enc_cred);
  }
}
PrefixTrie *PrefixTrie::get(Prefix &p, int depth){
  int bit = p.getbit(depth);
  if(bit < 0){
    return this;
  } else {
    if(next[bit] == NULL){
      return NULL;
    }
    return next[bit]->get(p, depth+1);
  }
}
void PrefixTrie::buildCredentialTree(Grassroots::Delegation *parent_creds, Grassroots::KEY *owner, Grassroots *grassroots_db){
  Grassroots::Delegation *my_creds, *delegated_creds = NULL;
  std::vector<AS>::iterator prefix_owner;
  Grassroots::KEY *first_key = NULL;
  
  for(prefix_owner = owners.begin(); prefix_owner != owners.end(); ++prefix_owner){
    std::map<AS,ASInfo>::iterator as_entry = as_claims.find(*prefix_owner);
    assert(as_entry != as_claims.end());
//    Grassroots::AS_ID as = *prefix_owner;
        
    if(first_key == NULL){
      first_key = as_entry->second.key;
      if(parent_creds){
        parent_creds = new Grassroots::Delegation(parent_creds);
        parent_creds->redelegate(owner, first_key);
        parent_creds->subdivide(owner, htonl(addr), depth);
      }
    }
    
    if(parent_creds == NULL){
      my_creds = new Grassroots::Delegation(htonl(addr), depth, *prefix_owner, first_key);
    } else {
      assert(owner);
      my_creds = new Grassroots::Delegation(parent_creds);
      my_creds->assign(first_key, *prefix_owner);
    }
    
    assert(my_creds->validate(grassroots_db));
    credentials.push_back(my_creds);
    
    //my_creds->print();
    //printf(" <= %d (%d)\n", *prefix_owner, as);
    
    if(delegated_creds == NULL){
      delegated_creds = my_creds;
    }
  }
  if(delegated_creds == NULL){
    delegated_creds = parent_creds;
    first_key = owner;
  } else {
    assert(grassroots_db->install_delegation(delegated_creds) >= 0);
    if(parent_creds) {
      //This isn't our parent's delegation, its a copy delegated to first_key
      delete parent_creds; 
    }
  }
  assert((owners.size() <= 0) || first_key);
  
  if(next[0]){
    next[0]->buildCredentialTree(delegated_creds, first_key, grassroots_db);
  }
  if(next[1]){
    next[1]->buildCredentialTree(delegated_creds, first_key, grassroots_db);
  }
}
void PrefixTrie::exportCredentialTree(FILE *f, Grassroots *grassroots_db){
  std::vector<AS>::iterator as_i;
  std::vector<Grassroots::Delegation *>::iterator delegation_i;
  assert(owners.size() == credentials.size());
  
  if(owners.size() > 0){
    print_ip(addr, 0); printf("/%d : (%d owners)", depth, (int)owners.size());
  }
  assert(owners.size() == credentials.size());
  
  for(as_i = owners.begin(), delegation_i = credentials.begin(); as_i != owners.end(); ++as_i){
    assert(delegation_i != credentials.end());
    Grassroots::Delegation *delegation = *delegation_i;
    Grassroots::RawData *data = delegation->encode();
    AS as = *as_i;
    printf(" [%d:%d]", as, (int)delegation->entries.size());
    
    fwrite(&addr, sizeof(Grassroots::IP_ADDR), 1, f);
    fwrite(&depth, sizeof(Grassroots::IP_MASKLEN), 1, f);
    fwrite(&as, sizeof(AS), 1, f);
    data->output(f);
    if(1){
      data->ptr = 0;
      Grassroots::Delegation *delegation_tmp = new Grassroots::Delegation(data);
      if(delegation_tmp->entries.size() != delegation->entries.size()){
        fprintf(stderr, "Failed to pre-verify delegation (not all entries transfered): "); delegation_tmp->print(); printf("\n");
        assert(0);
      }
      if(!delegation_tmp->validate(grassroots_db)){
        fprintf(stderr, "Failed to pre-verify delegation (validation failed): "); delegation_tmp->print(); printf("\n");
        assert(0);
      }
      delete delegation_tmp;
    }
    
    delete data;
    ++delegation_i;
  }
  if(owners.size() > 0){
    printf("\n");
  }
  
  if(next[0]){
    next[0]->exportCredentialTree(f, grassroots_db);
  }
  if(next[1]){
    next[1]->exportCredentialTree(f, grassroots_db);
  }
}

Grassroots::RawData *PrefixTrie::get_enc_cred(AS source){
  std::vector<AS>::iterator owner_it;
  std::vector<Grassroots::RawData *>::iterator cred_it = enc_credentials.begin();
  
  assert(owners.size() == enc_credentials.size());
  
  for(owner_it = owners.begin(); owner_it != owners.end(); ++owner_it){
    assert(cred_it != enc_credentials.end());
    
    if(*owner_it == source){
      return *cred_it;
    }
    
    ++cred_it;
  }
  
  return NULL;
}

PrefixTrie *load_prefix_trie(FILE *f){
  Grassroots::IP_ADDR prefix;
  Grassroots::IP_MASKLEN prefixlen;
  AS as;
  Grassroots::RawData *data;
  PrefixTrie *root = new PrefixTrie();
  int cnt = 0;
  
  printf("Loading prefix delegation table...\n");
  
  while(!feof(f)){
    Prefix p;
    if(fread(&prefix, sizeof(Grassroots::IP_ADDR), 1, f) != 1) break;
    if(fread(&prefixlen, sizeof(Grassroots::IP_MASKLEN), 1, f) != 1) break;
    if(fread(&as, sizeof(AS), 1, f) != 1) break;
    data = new Grassroots::RawData(f);
    p.prefix = htonl(prefix);
    p.prefixlen = prefixlen;
    root->put(p, as, data);
    {
      data->ptr = 0;
      Grassroots::Delegation *d = new Grassroots::Delegation(data);
      data->ptr = 0;
      delete d;
    }
    cnt++;
  }
  
  printf("   ... done (%d prefix records loaded)\n", cnt);
  
  return root;
}
