#include <iostream>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../include/nbgp/bgpcheck.h"
#include "../include/nbgp/policy_specification.h"
#include "../include/util/common.h"

static unsigned int debug_log_prefix = 
//  inet_addr("38.116.192");
  inet_addr("6.1.0.0");
static int debug_log_prefix_depth = 
//  25;
  16;

//#define DEBUG_LOG_PREFIX(prefix_name, prefix_depth) ( ((unsigned int)prefix_name == debug_log_prefix)&&((int)prefix_depth == debug_log_prefix_depth))
#define DEBUG_LOG_PREFIX(prefix_name, prefix_depth)  (0)

///////////////////////////// Utility Functions

void bc_log_prefix(char *prefix, int depth){
  debug_log_prefix = ntohl(inet_addr(prefix));
  debug_log_prefix_depth = depth;
}

void bc_log_prefix_end(){
  debug_log_prefix = 0;
  debug_log_prefix_depth = -1;
}

int bc_read_bgp_packet(PIPE_TYPE buffer, bgp_packet *p){
  int data;

  buffer->error = 0;

  data = bgp_read_packet(buffer, p);

  if(buffer->error){
    //exit(1);
    return -1;
  }
  return data;
}

unsigned short bc_get_topbit(unsigned int prefix){
  unsigned short topbit = (short)((prefix >> ((sizeof(unsigned int) * 8) - 1)) & 0x01);
  
  assert((topbit == 0)||(topbit == 1));
  return topbit;
}
unsigned int bc_next_prefix(unsigned int prefix){
  return prefix << 1;
}
unsigned short bc_path_contains(unsigned short prefix, bgp_as_path *path){
  bgp_as_path *p;
  int i;

  for(p = path; p != NULL; p = p->next){
    for(i = 0; i < p->len; i++){
      if(prefix == p->list[i]){
        return 1;
      }
    }
  }
  
  return 0;
}

bgp_as_path *bc_get_dest_path(bgp_packet *packet){
  if(packet->type != 2){
    return NULL;
  }
  return packet->contents.UPDATE.as_path;
}

bgp_ipmaskvec *bc_get_dest_vec(bgp_packet *packet, int ad){
  bgp_ipmaskvec *v;

  if(packet->type != 2){
    return NULL;
  }

  v = packet->contents.UPDATE.destv;
  
  while((v != NULL) && (ad > 0)){
    v = v->next;
    ad--;
  }

  return v;
}

///////////////////////////// BC_Database_Entry

BC_Database_Entry::BC_Database_Entry(BC_Database_Entry *parent, int bit) : 
  ad_list()
{
  //ad_list already initialized
  next[0] = next[1] = NULL;
  forwards = NULL;
  forwards_size = 0;
  
#ifdef INCLUDE_BGP_DB_PREFIX
  if(parent == NULL){
    p_prefix = 0;//we're the root
    p_depth = 0;
  } else {
    p_prefix = parent->p_prefix | ((bit & 0x01) << (31 - parent->p_depth));
    p_depth = parent->p_depth + 1;
  }
#endif
}

BC_Database_Entry *BC_Database_Entry::get(unsigned int prefix, int length){
  return get(prefix, length, 0);
}
BC_Database_Entry *BC_Database_Entry::get(unsigned int prefix, int length, int create){
  unsigned short topbit = bc_get_topbit(prefix);
#ifdef INCLUDE_BGP_DB_PREFIX
  assert(length + p_depth <= 32);
#endif
  
  if(length <= 0){
    return this;
  }
  
  if(create && !next[topbit]){
#ifdef INCLUDE_BGP_DB_PREFIX
    assert(p_depth <= 32);
#endif
    next[topbit] = new BC_Database_Entry(this, topbit);
  }
  
  if(next[topbit]){ 
    return next[topbit]->get(bc_next_prefix(prefix), length-1, create);
  }
  return this;
}

BC_Database_Entry::~BC_Database_Entry(){
  if(next[0] != NULL){
    delete next[0];
  }
  if(next[1] != NULL){
    delete next[1];
  }
  bc_adverts::iterator iter;
  for(iter = ad_list.begin(); iter != ad_list.end(); ++iter){
    BC_Advertisement *ad = *iter;
    assert(ad);
    ad->ref_down();
  }
}


//Aggregation ugliness.  
//If called on a prefix n, this function will store the listed advertisement
//everywhere in the prefix space below n EXCEPT the specified prefix.
//This is used when a subset of n is withdrawn (implicitly or explicitly).
void BC_Database_Entry::subdivide(unsigned int prefix, int length, BC_Advertisement *ad){
  unsigned short topbit = bc_get_topbit(prefix);
  
  if(length <= 0){
    return;
  }
  
  //store the ad one level down along the path we're NOT traversing.
  ad->ref_up();
  store(~prefix, 1, ad);
  
  //we don't need to bother trying to recurse if the next iteration is just
  //going to return immediately.
  if(length == 1) {
    return;
  }
  
  if(!next[topbit]){
#ifdef INCLUDE_BGP_DB_PREFIX
    assert(p_depth <= 32);
#endif
    next[topbit] = new BC_Database_Entry(this, topbit);
  }
  
  next[topbit]->subdivide(bc_next_prefix(prefix), length-1, ad);
}

void BC_Database_Entry::store(unsigned int prefix, int length, BC_Advertisement *ad){
  unsigned short topbit = bc_get_topbit(prefix);

  assert(length <= 32);
  assert(length + p_depth <= 32);
  assert(ad != NULL);

  
  if(length == 0) { //store the ad
    //first off, are we overwriting something that currently exists?
    std::vector<BC_Advertisement *>::iterator old_iter = contains(ad);
    if(old_iter != ad_list.end()){
      BC_Advertisement *old = *old_iter;
      if(DEBUG_LOG_PREFIX(p_prefix, p_depth)){
        printf("Store removing old path: ");old->print_path();printf(" (");bgp_print_ip(old->as_ip);printf(")\n");
      }
      assert(old);
      ad_list.erase(old_iter); //erase is insufficient.  still need to free the pointer
      old->ref_down();
    }
    ad_list.push_back(ad); //the new ad is automatically created as live.
    if(DEBUG_LOG_PREFIX(p_prefix, p_depth)){
      printf("\t");print(0, 0);
    }
  } /* length == 0 */ else {
    if(!next[topbit]){
#ifdef INCLUDE_BGP_DB_PREFIX
      assert(p_depth <= 32);
#endif
      next[topbit] = new BC_Database_Entry(this, topbit);
    }
    next[topbit]->store(bc_next_prefix(prefix), length-1, ad);
  }
}

std::vector<BC_Advertisement *>::iterator BC_Database_Entry::contains(BC_Advertisement *ad){
  std::vector<BC_Advertisement *>::iterator iter;
  
  assert(ad != NULL);
  
  for(iter = ad_list.begin(); iter != ad_list.end(); ++iter){
    BC_Advertisement *otherad = *iter;
    assert(otherad);
//    if(otherad->equals(ad)){
//      break;
//    }
    if((otherad->as_id == ad->as_id) && (otherad->as_ip == ad->as_ip)){
      break;
    }
  }
  return iter;
}

void BC_Database_Entry::lookup(unsigned int prefix, int length, bc_adverts *ret){
  unsigned short topbit = bc_get_topbit(prefix);
  std::vector<BC_Advertisement *>::iterator iter;

#ifdef INCLUDE_BGP_DB_PREFIX  
  assert(length + p_depth <= 32);
#endif
  
  if(length > 0){
    if(next[topbit]){
      next[topbit]->lookup(bc_next_prefix(prefix), length -1, ret);
    }
#ifdef DISALLLOW_DEAGGREGATION
    return;
#endif
  }
  
  for(iter = ad_list.begin(); iter != ad_list.end(); ++iter){
    BC_Advertisement *ad = *iter;
    assert(ad);
    ret->push_back(ad);
  }
}

int BC_Database_Entry::withdraw(unsigned int prefix, int length, unsigned short as_id, unsigned int as_ip){
  unsigned short topbit = bc_get_topbit(prefix);
  std::vector<BC_Advertisement *>::iterator iter;
  static BC_Advertisement ad;
  
  if((length > 0) && (next[topbit])){
    //We first go down to the deepest point in the trie and try to withdraw. 
    //If the levels below us haven't been able to withdraw this particular prefix, then the withdraw
    // might have been a partial-prefix withdrawal, in which case the actual ad the withdraw was
    // intended for might be at this level.  
    if(next[topbit]->withdraw(bc_next_prefix(prefix), length-1, as_id, as_ip)){
      return 1;
    }
  }
  
//  if(DEBUG_LOG_PREFIX(p_prefix, p_depth)){
//    printf("tracking withdraw");printf(" (");bgp_print_ip(as_ip);printf(")\n");
//  }
  
  ad.as_ip = as_ip;
  ad.as_id = as_id;
  
  iter = contains(&ad);
  if(iter != ad_list.end()){
    BC_Advertisement *ad = *iter;
    assert(ad);
    subdivide(prefix, length, ad);//this'll make copies of ad.
    ad_list.erase(iter); //erase is insufficient.  still need to free the pointer
    ad->ref_down();
    return 1;
  }
  
  return 0;
}

void BC_Database_Entry::print(unsigned int prefix, int length){
  print(prefix, length, 0, 0);
}
void BC_Database_Entry::print(unsigned int prefix, int length, unsigned int curr_prefix, unsigned int curr_length){
  unsigned short topbit = bc_get_topbit(prefix);
  std::vector<BC_Advertisement *>::iterator iter;

  if(ad_list.size() > 0){
    printf("Ad list for : "); bgp_print_ip(curr_prefix); printf("/%d : \n", curr_length);

    for(iter = ad_list.begin(); iter != ad_list.end(); ++iter){
      BC_Advertisement *ad = *iter;
      assert(ad);
      printf("  ");
      ad->print_path();
      printf(" (");bgp_print_ip(ad->as_ip); printf(")");
      printf("\n");
    }
  } else {
    //printf("Ad list for : "); bgp_print_ip(p_prefix); printf("/%d : (empty)\n", p_depth);
  }
  
  if(length > 0){
    if(next[topbit]){
      next[topbit]->print(bc_next_prefix(prefix), length-1, curr_prefix | (topbit << (31-curr_length)), curr_length+1);
    }
  }
}

void BC_Database_Entry::forward(unsigned int prefix, int length, unsigned short as, BC_Path_Store *path){
  unsigned short topbit = bc_get_topbit(prefix);

  assert(length <= 32);
#ifdef INCLUDE_BGP_DB_PREFIX
  assert(length + p_depth <= 32);
#endif

  if(length == 0){
    unsigned short i;
    //step 1: try to put it in place of an old path
    for(i = 0; i < forwards_size; i++){
      if((forwards[i].path != NULL)&&(forwards[i].as == as)){
        forwards[i].path = path;
        return;
      }
    }
    //step 2: try to find a new place for it
    for(i = 0; i < forwards_size; i++){
      if(forwards[i].path == NULL){
        forwards[i].path = path;
        forwards[i].as = as;
        return;
      }
    }
    //step 3: allocate more memory for it
    if(forwards){
      forwards = (BC_Path_Ref *)realloc(forwards, forwards_size * 2 * sizeof(BC_Path_Ref));
      forwards[forwards_size].path = path;
      forwards[forwards_size].as = as;
      if(forwards_size > 1){
        bzero(&(forwards[forwards_size+1]), (forwards_size-1) * sizeof(BC_Path_Ref));
      }
      forwards_size *= 2;
    } else {
      forwards_size = 1;
      forwards = (BC_Path_Ref *)malloc(forwards_size * sizeof(BC_Path_Ref));
      forwards[0].path = path;
      forwards[0].as = 0;
    }
  } /* length == 0 */ else {
    if(!next[topbit]){
#ifdef INCLUDE_BGP_DB_PREFIX
      assert(p_depth <= 32);
#endif
      next[topbit] = new BC_Database_Entry(this, topbit);
    }
    next[topbit]->forward(bc_next_prefix(prefix), length-1, as, path);
  }
}

int BC_Database_Entry::check_forward(unsigned int prefix, int length, unsigned short *aspath){
  unsigned short topbit = bc_get_topbit(prefix);

  if(length == 0){
    int i, j;
    int curr;

    for(curr = 0; curr < forwards_size; curr++){
      if(forwards[curr].path == NULL) continue;
      if(forwards[curr].path->trace_path(aspath)){ return 1; }
    }
    return 0;
  }
  

  if(!next[topbit]){
    return 0;
  }
  return next[topbit]->check_forward(bc_next_prefix(prefix), length-1, aspath);
}

int BC_Database_Entry_Total_Size = 0;
int BC_Database_Entry_Forwards_Size = 0;

int BC_Database_Entry::calc_size(){
  int tot = sizeof(BC_Database_Entry);
  int curr;
  
  BC_Database_Entry_Total_Size += tot;
  
  tot += sizeof(BC_Advertisement *) * ad_list.size();
  
  tot += sizeof(BC_Path_Store *) * forwards_size;
  BC_Database_Entry_Forwards_Size += sizeof(BC_Path_Ref *) * forwards_size;

  if(next[0]){
    tot += next[0]->calc_size();
  }
  if(next[1]){
    tot += next[1]->calc_size();
  }
  return tot;
}

///////////////////////////// BC_Advertisement

BC_Advertisement::BC_Advertisement() :
  communities(), as_path()
{
  as_id          = 0;
  as_ip          = 0;
//  aggregator     = 0;
//  med            = 0;
//  localpref      = 0;
  nexthop        = 0;
  refcnt         = 1;
}

BC_Advertisement::BC_Advertisement(BC_Advertisement *ad) : 
  communities(ad->communities), as_path(ad->as_path)
{
  as_id          = ad->as_id;
  as_ip          = ad->as_ip;
//  aggregator     = ad->aggregator;
//  med            = ad->med;
//  localpref      = ad->localpref;
  nexthop        = ad->nexthop;
  refcnt         = 1;
}

int BC_Advertisement::full_equals(BC_Advertisement *ad){
  assert(ad != NULL);
  assert(this);
  std::vector<unsigned int>::iterator i_iterA, i_iterB;
  std::vector<unsigned short>::iterator s_iterA, s_iterB;
  
  if((as_id != ad->as_id)||(as_ip != ad->as_ip)||
//     (aggregator != ad->aggregator)||
//     (med != ad->med)||
//     (localpref != ad->localpref)||
     (nexthop != ad->nexthop)||
     (communities.size() != ad->communities.size())||
     (as_path.size() != ad->as_path.size())){
    return 0;
  }
  
  
  for(i_iterA = communities.begin(), i_iterB = ad->communities.begin();
      (i_iterA != communities.end())&&(i_iterB != ad->communities.end());
      ++i_iterA, ++i_iterB)
  {
    if(*i_iterA != *i_iterB){
      return 0;
    }
  }
  for(s_iterA = as_path.begin(), s_iterB = ad->as_path.begin();
      (s_iterA != as_path.end())&&(s_iterB != ad->as_path.end());
      ++s_iterA, ++s_iterB)
  {
    if(*s_iterA != *s_iterB){
      return 0;
    }
  }
  return 1;
}
int BC_Advertisement::equals(BC_Advertisement *ad){
  assert(ad != NULL);
  assert(this);
  //printf("(%p:%p)", ad, this);
  return (as_id == ad->as_id)&&(as_ip == ad->as_ip);
}

void BC_Advertisement::load_path(bgp_as_path *path){
  int x;
  as_path.clear();
  while(path != NULL){
    for(x = 0; x < path->len; x++){
      as_path.push_back(path->list[x]);
    }
    path = path->next;
  }
}

unsigned short *BC_Advertisement::dump_path(){
  unsigned short *ret = new unsigned short[as_path.size() + 1];
  int i = 0;
  
  std::vector<unsigned short>::iterator as;
  for(as = as_path.begin(); as != as_path.end(); ++as){
    ret[i] = *as;
    i++;
  }
  ret[i] = 0;
  return ret;
}

int BC_Advertisement::check_path(bgp_as_path *path){
  //checks to see every element in this ad is also in the path.
  std::vector<unsigned short>::iterator element;
    
  for(element = as_path.begin(); element != as_path.end(); ++element){
    //printf("(%d)", *element);
    if(!bc_path_contains(*element, path)){
      return 0;
    }
  }
  
  return 1;
}

void BC_Advertisement::print_path(){
  print_path(stdout);
}
void BC_Advertisement::print_path(FILE *f){
  std::vector<unsigned short>::iterator as;
  for(as = as_path.begin(); as != as_path.end(); ++as){
    fprintf(f, " [%d]", *as);
  }
}

int BC_Advertisement::withdrawn(){
  return 0;
}

void BC_Advertisement::ref_up(){
  refcnt++;
}

void BC_Advertisement::ref_down(){
  refcnt--;
//  if(refcnt <= 0){ delete this; }
}

int BC_Advertisement_Total_Size = 0;
int BC_Advertisement_Communities_Size = 0;
int BC_Advertisement_ASPATH_Size = 0;

int BC_Advertisement::calc_size(){
  int tot = sizeof(BC_Advertisement);
  tot += communities.size() * sizeof(unsigned int);
  BC_Advertisement_Communities_Size += communities.size() * sizeof(unsigned int);
  tot += as_path.size() * sizeof(unsigned short);
  BC_Advertisement_ASPATH_Size += as_path.size() * sizeof(unsigned short);
  
  //tot /= refcnt;
  
  BC_Advertisement_Total_Size += tot;
  
  return tot;
}

//#define ADD_TO_HASH(var) ret = (ret << 1) | (ret >> 31) | (int)var
#define ADD_TO_HASH(var) ret += (int)(var)

unsigned int BC_Advertisement::get_hash(){
  int ret = 0;
  std::vector<unsigned short>::iterator as;
  std::vector<unsigned int>::iterator comm;
  
  //doesn't need to be cryptographically secure, just unique
  ADD_TO_HASH(as_id);
  ADD_TO_HASH(as_ip);
//  ret += aggregator;
//  ret += localpref;
//  ret += med;
  for(as = as_path.begin(); as != as_path.end(); ++as){
    ADD_TO_HASH(*as);
  }
  for(comm = communities.begin(); comm != communities.end(); ++comm){
    ADD_TO_HASH(*comm);
  }
  //ret = ret ^ ((ret << 8) | ((ret >> 24) & 0xff))  ^ ((ret >> 8) | ((ret & 0xff) << 24));
  return ret;
}

#define CMP_VALS_RET(val) if(a-> val < b-> val) return 1; if(b-> val < a-> val) return 0
int BC_Advertisement::LESS::operator()(const BC_Advertisement *a, const BC_Advertisement *b){
  std::vector<unsigned short>::reverse_iterator asA, asB;
  std::vector<unsigned int>::iterator commA, commB;
  
  CMP_VALS_RET(as_id);
  CMP_VALS_RET(as_ip);
  CMP_VALS_RET(as_path.size());  
//  CMP_VALS_RET(aggregator);
//  CMP_VALS_RET(localpref);
//  CMP_VALS_RET(med);
  CMP_VALS_RET(nexthop);
  CMP_VALS_RET(communities.size());
  for(asA = ((BC_Advertisement *)a)->as_path.rbegin(), asB = ((BC_Advertisement *)b)->as_path.rbegin();
      asA != ((BC_Advertisement *)a)->as_path.rend();
      ++asA, ++asB
    ){
    assert(asB != ((BC_Advertisement *)b)->as_path.rend());
    if(*asA < *asB) return 1; if(*asB < *asA) return 0;
  }
  for(commA = ((BC_Advertisement *)a)->communities.begin(), commB = ((BC_Advertisement *)b)->communities.begin();
      commA != ((BC_Advertisement *)a)->communities.end();
      ++commA, ++commB
    ){
    assert(commB != ((BC_Advertisement *)b)->communities.end());
    if(*commA < *commB) return 1; if(*commB < *commA) return 0;
  }
  
  return 0;
}

///////////////////////////// BC_Advertisement_Store

#ifdef BC_ADVERTISEMENT_STORE_MAP
//maps are slow, but they work.
BC_Advertisement *BC_Advertisement_Store::get_and_store(BC_Advertisement *ad){
  std::map<BC_Advertisement *, BC_Advertisement *, BC_Advertisement::LESS>::iterator i;
  
  i = store.find(ad);
  if(i == store.end()){
    BC_Advertisement *dup = new BC_Advertisement(ad);
    store[dup] = dup;
    assert((i = store.find(ad)) != store.end());
  }
  return i->second;
}

int BC_Advertisement_Store::calc_size(){
  std::map<BC_Advertisement *, BC_Advertisement *, BC_Advertisement::LESS>::iterator i;
  int tot = sizeof(BC_Advertisement_Store);
  int cnt = 0;
  
  for(i = store.begin(); i != store.end(); ++i){
    tot += 2*sizeof(BC_Advertisement *) + i->second->calc_size();
    cnt++;
  }
  
  printf("%d advertisements stored: %d bytes\n", cnt, tot);
  
  return tot;
}
#else
//nexus doesn't have a built-in hashmap... time to roll our own;
BC_Advertisement_Store::BC_Advertisement_Store(){
  store = new Entry*[BC_ADVERTISEMENT_HASH_SIZE]; 
  bzero(store, sizeof(Entry *)*BC_ADVERTISEMENT_HASH_SIZE);
  ads = maxheapsize = 0;
} // 1 meg of table doesn't sound too bad

BC_Advertisement *BC_Advertisement_Store::get_and_store(BC_Advertisement *ad){
  unsigned int hash = ad->get_hash() % BC_ADVERTISEMENT_HASH_SIZE;
  Entry *e;
  int cnt = 0;
  for(e = store[hash]; e != NULL; e = e->next){
    if(e->ad->full_equals(ad)){
      return e->ad;
    }
    cnt++;
  }
  e = new Entry();
  e->ad = new BC_Advertisement(ad);
  e->next = store[hash];
  store[hash] = e;
  if(cnt >= maxheapsize){
    maxheapsize = cnt+1;
  }
  ads++;
  adsize += ad->calc_size();
  return e->ad;
}

int BC_Advertisement_Store::calc_size(){
  return BC_ADVERTISEMENT_HASH_SIZE * sizeof(Entry *) + adsize + ads * sizeof(Entry) + sizeof(BC_Advertisement_Store);
}

#endif

///////////////////////////// BC_Path_Store

static Preallocator<BC_Path_Store, 1000> BC_Path_Store_preallocator;

int BC_Path_Store::trace_path(unsigned short *s, int *i){
  if(parent != NULL){
    if(!parent->trace_path(s, i)) return 0;
  } else {
    return 1;
  }
  while(s[*i] != as){
    if(s[*i] == 0) return 0;
    (*i)++;
  }
  (*i)++;
  return 1;
}
int BC_Path_Store::trace_path(unsigned short *s){
  int i = 0;
  return trace_path(s, &i);
}
int BC_Path_Store::calc_size(){
  int tot = sizeof(BC_Path_Store);
  if(child) tot += child->calc_size();
  if(peer) tot += peer->calc_size();
  return tot;
}


///////////////////////////// BC_Database

BC_Database::BC_Database(void) : ad_store() {
  root = new BC_Database_Entry(NULL, 0);
  path_root = NULL;
  size = 0;
}
BC_Database::~BC_Database(void){
  delete root;
  if(path_root) delete path_root;
}
unsigned short BC_Database::verify(unsigned int prefix, int length, bgp_as_path *path, bc_adverts *ret){
  static bc_adverts ads;
  bc_adverts::iterator iter;
  
  ads.clear();
  
  root->lookup(prefix, length, &ads);
  
  for(iter = ads.begin(); iter != ads.end(); ++iter){
    BC_Advertisement *ad = *iter;
    assert(ad);
    if(ad->check_path(path)){
      ret->push_back(ad);
    }
  }
  
  return ret->size();
}
void BC_Database::install(BC_Advertisement *ad, unsigned int p_prefix, int p_depth){
  BC_Advertisement *ad_tmp = ad_store.get_and_store(ad);
  root->store(p_prefix, p_depth, ad_tmp);
}
void BC_Database::parse(bgp_packet *packet, unsigned short source_as, unsigned int source_ip){
  bgp_ipmaskvec *vec;
  
  if(packet->type != 2){ return; } //updates only
  
  vec = packet->contents.UPDATE.withdrawv;
  while(vec){
    if(DEBUG_LOG_PREFIX(ntohl(vec->ip), vec->mask)){
      bgp_print_ip(source_ip);printf(" withdrawing "); bgp_print_ip(vec->ip);printf("/%d\n", vec->mask);
    }
    root->withdraw(vec->ip, vec->mask, source_as, source_ip);
    vec = vec->next;
  }
  
  if(packet->contents.UPDATE.destv){
    static BC_Advertisement ad;
    BC_Advertisement *ad_tmp;
    static std::vector<unsigned short> no_as_hack = std::vector<unsigned short>();
    int x;
    if(no_as_hack.size() < 1){
      no_as_hack.push_back(source_as);
    }
    
    ad.load_path(packet->contents.UPDATE.as_path);
    ad.as_id = source_as;
    ad.as_ip = source_ip;
    
//    ad.aggregator = packet->contents.UPDATE.aggregator;
//    ad.med = packet->contents.UPDATE.med;
//    ad.localpref = packet->contents.UPDATE.preference;
    ad.nexthop = packet->contents.UPDATE.nexthop;
    
    ad.communities.clear();
    for(x = 0; x < packet->contents.UPDATE.num_communities; x++){
      ad.communities.push_back(packet->contents.UPDATE.communities[x]);
    }
    ad_tmp = ad_store.get_and_store(&ad);
    
    vec = packet->contents.UPDATE.destv;
    while(vec){
      ad_tmp->ref_up();
      root->store(vec->ip, vec->mask, ad_tmp);
      vec = vec->next;
      size++;
    }
  }
}

void BC_Database::forward(bgp_packet *packet, unsigned short source_as){
  bgp_ipmaskvec *vec;
  vec = packet->contents.UPDATE.withdrawv;
  while(vec){
    root->forward(vec->ip, vec->mask, source_as, NULL);
    vec = vec->next;
  }
  vec = packet->contents.UPDATE.destv;
  BC_Path_Store *path = store_path(packet->contents.UPDATE.as_path);
  while(vec){
    root->forward(vec->ip, vec->mask, source_as, path);
    vec = vec->next;
  }
}
int BC_Database::check_forward(unsigned int prefix, int prefixlen, unsigned short *aspath){
  return root->check_forward(prefix, prefixlen, aspath);
}
  
  
void BC_Database::print_potentials(unsigned int prefix, int length){
  bc_adverts ads;
  bc_adverts::iterator iter;
  root->lookup(prefix, length, &ads);
  
  printf("Potential advertisements for : "); bgp_print_ip(prefix); printf("/%d\n", length);
  
  for(iter = ads.begin(); iter != ads.end(); ++iter){
    printf("   ( ");
    BC_Advertisement *ad = *iter;
    assert(ad);
    ad->print_path();
    printf("  )");
  }
  printf("\n");
}
void BC_Database::print_path(unsigned int prefix, int length){
  root->print(prefix, 24);
}

BC_Path_Store *BC_Database::store_path(bgp_as_path *path){
  int i = 0;
  BC_Path_Store **curr = &path_root;
  BC_Path_Store *parent = NULL;
  
  while(1){
    if(*curr == NULL){
      *curr = BC_Path_Store_preallocator.create();
      (*curr)->as = path->list[i];
      (*curr)->parent = parent;
    }
    if((*curr)->as == path->list[i]){
      i++;
      if(i >= path->len){
        path = path->next;
      }
      if(path == NULL){
        return *curr;
      }
      parent = *curr;
      curr = &(*curr)->child;
    } else {
      curr = &(*curr)->peer;
    }
  }
  assert(!"this line should never be reached");
  return NULL;
}

BC_Path_Store *BC_Database::store_path(bgp_as_path *path, int i, BC_Path_Store **curr, BC_Path_Store *parent){
  if(*curr == NULL){
    *curr = BC_Path_Store_preallocator.create();
    (*curr)->as = path->list[i];
    (*curr)->parent = parent;
  }
  if((*curr)->as == path->list[i]){
    i++;
    if(i >= path->len){
      path = path->next;
    }
    if(path == NULL){
      return *curr;
    }
    return store_path(path, i, &(*curr)->child, *curr);
  } else {
    return store_path(path, i, &(*curr)->peer, parent);
  }
}
//BC_Path_Store *BC_Database::store_path(bgp_as_path *path){
//  return store_path(path, 0, &path_root, NULL);
//}

int BC_Database::calc_size(){
  BC_Database_Entry_Total_Size = 0;
  printf("%d prefixes stored; %d advertisements stored, max heapdepth %d\n", size, ad_store.ads, ad_store.maxheapsize);
  return root->calc_size() + ad_store.calc_size() + (path_root?path_root->calc_size():0) + sizeof(BC_Database);
}

///////////////////////////// BC_Checker

BC_Checker::BC_Checker(BC_Database *_db, unsigned short _as_id, unsigned int _as_ip, unsigned short _my_as){
  db = _db;
  as_id = _as_id;
  as_ip = _as_ip;
  my_as = _my_as;
  
  packet = NULL;
  
  dummy.mask = 0;
  dummy.ip = 0;
  
  policy = NULL;
  next_policy = NULL;
  ds_inc = NULL;
  ds_out = NULL;
}
BC_Checker::~BC_Checker(){
  //nothing to see here.
}

int BC_Checker::detect_loops(){
  bgp_as_path *path;
  int started = 0;
  int j;
  
  for(path = packet->contents.UPDATE.as_path; path != NULL; path = path->next){
    for(j = 0; j < path->len; j ++){
      if(started){
        if(path->list[j] == my_as){
          return 1;
        }
      } else {
        //we're allowed to place ourselves at the head of the path
        //as many times as we want
        if(path->list[j] != my_as){
          started = 1;
        }
      }
    }
  }
  
  return 0;
}

int BC_Checker::load_packet(bgp_packet *_packet){
  assert(packet == NULL);
  packet = _packet;

  if(packet->type != 2) {
    return 0;
    ads_left = 0;
  }
  
  if(ds_out == NULL) { ds_out = debug_get_stateptr("CHECKER_OUT"); }
  debug_start_timing(ds_out);
  ads_checked = 0;
  
  reset_ads();
  
  //Run a simple set of validity checks on the AS_PATH
  //We only need to do this once per packet and then only
  //if the packet actually contains any ads.
  
  if(ads_left > 0){
    if(packet->contents.UPDATE.as_path == NULL) return -1;
    //the first chunk of the AS_PATH must be sequential by BGP4
    if(packet->contents.UPDATE.as_path->type != 2) return -2;
    if(as_id != my_as){ //certain rules only apply to eBGP sessions
      //the path has to have a size
      if(packet->contents.UPDATE.as_path->len < 1) return -3;
      //and we have to occupy the first step in that path
      if(packet->contents.UPDATE.as_path->list[0] != my_as) return -4;
    }

    if(detect_loops()) return -5;
  }

  return 0;
}
int BC_Checker::ads_remaining(){
  return ads_left;
}
void BC_Checker::reset_ads(){
  bgp_ipmaskvec *temp;

  if(packet == NULL) return;
  if(packet->type != 2) return;
  temp = dummy.next = packet->contents.UPDATE.destv;
  prefix = &dummy;
  ads_left = 0;
  while(temp != NULL){
    ads_left++;
    temp = temp->next;
  }
  
}
int BC_Checker::check_next_ad(){
  static bc_adverts ads;
  bc_adverts::iterator iter;
  short ret;
  
  ads.clear();
  
  if(ads_left <= 0) return -2;
  if(prefix->next == NULL){
    printf("Error in check_next_ad().  %d ads left, but we're out of prefixes\n", ads_left);
    bgp_print_packet(packet);
    assert(0);
  }
  skip_next_ad();
  ads_checked++;
  
  if(prefix->mask > 32){
    bgp_print_packet(packet);
    assert(!"Packet with a prefix that's considerably longer than it should be");
  }
  
  if(db->verify(prefix->ip, (unsigned int)prefix->mask, packet->contents.UPDATE.as_path, &ads) > 0){
    if(policy){
      Policy_Question question;
      
      question.outgoing = packet;
      question.prefix = prefix->ip;
      question.p_len = prefix->mask;
      question.dest_ip = as_ip;
      question.dest_as = as_id;
      
      ret = -2; //this WILL be overwritten
      
      for(iter = ads.begin(); iter != ads.end(); iter++){
        question.incoming = iter;
        ret = policy->ask(&question);
        if((ret > 0) && (next_policy != NULL)){
          force_policy_swap(next_policy);
          iter = ads.begin();
          question.incoming = iter;
          ret = policy->ask(&question);
        }
        if(ret <= 0){
          //if policy says this ad could have generated the outgoing
          //then we're done here
          return 0;
        }
      }
      //if policy rejects every potential ad, then we have an ad that 
      //violates policy, but not safety.
      return ret;
    }
  } else { 
    //if no ads satisfy the safety constraints, the packet is bad.
    return -1;
  }
  return 0;
}
void BC_Checker::skip_next_ad(){
  if(ads_left <= 0) return;
  assert(prefix->next != NULL);
  prefix = prefix->next;
  ads_left--;
}
unsigned int BC_Checker::last_prefix(){
  if(prefix)
    return prefix->ip;
  else
    return 0;
}
int BC_Checker::last_prefix_len(){
  if(prefix)
    return prefix->mask;
  else
    return 0;
}
void BC_Checker::free_packet(){
  bgp_cleanup_packet(packet);
  free(packet);
  if(packet) debug_stop_timing(ds_out, 1);
  packet = NULL;
}
void BC_Checker::cleanup_packet(){
  bgp_cleanup_packet(packet);
  if(packet) debug_stop_timing(ds_out, 1);
  packet = NULL;
}
void BC_Checker::finish_packet(){
  if(packet) debug_stop_timing(ds_out, 1);
  packet = NULL;
}
void BC_Checker::parse_incoming(bgp_packet *_packet){
  if(ds_inc == NULL) { ds_inc = debug_get_stateptr("CHECKER_INC"); }
  debug_start_timing(ds_inc);
  db->parse(_packet, as_id, as_ip);
  debug_stop_timing(ds_inc, 1);
}
void BC_Checker::print_potentials(){
  db->print_potentials(last_prefix(), last_prefix_len());
}
void BC_Checker::print_path(){
  db->print_path(last_prefix(), last_prefix_len());
}
Policy_Grouping *BC_Checker::set_policy(Policy_Grouping *_policy){
  if(policy){
    next_policy = _policy;
  } else {
    policy = _policy;
  }
  return _policy;
}
Policy_Grouping *BC_Checker::set_policy(Policy_Specification *_policy){
  Policy_Grouping *grouping = new Policy_Grouping();
  
  grouping->add(_policy);
  
  return set_policy(grouping);
}
void BC_Checker::force_policy_swap(Policy_Grouping *_policy){
  assert(_policy != NULL);
  if(next_policy == _policy){
    assert(policy);
    delete policy;
    policy = next_policy;
    next_policy = NULL;
  }
}
int BC_Checker::policy_pending(){
  return next_policy == NULL;
}
