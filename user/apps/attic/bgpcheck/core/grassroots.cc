#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <vector>
#include <sys/types.h>
#include <unistd.h>

#include "../include/nbgp/grassroots.h"
#include "../include/enc/openssl_compat.h"
#include "../include/util/common.h"

#define GR_OBJECT_KNOWNKEY      2
#define GR_OBJECT_OWNER         3

int force_read(void *ptr, int len, FILE *f){
  int rlen = 0;
  int lastr =  0;
  unsigned char *op = (unsigned char *)ptr;
  
  while((rlen < len) && (!feof(f))){
    lastr = fread(&(op[rlen]), 1, 1, f);
    if(lastr < 0){
      return lastr;
    }
    if(lastr){
    }
    rlen += lastr;
  }
  return rlen;
}


///////////////////////////////////// Grassroots::OwnerRecord


Grassroots::OwnerRecord::OwnerRecord(Grassroots::KEY *_owner) : as_delegs(), key_delegs(), sign_blocked(0) {
  owner = _owner;
  sig = NULL;
  sign();
}
Grassroots::OwnerRecord::OwnerRecord(Grassroots::RawData *data) : as_delegs(), key_delegs(), sign_blocked(0) {
  uint32_t buffer;
  
  for(data->load(&buffer); buffer > 0; buffer--){
//    printf("a) %d\n", buffer);
    as_delegs.push_back(ASDelegation(data));
  }
  for(data->load(&buffer); buffer > 0; buffer--){
//    printf("b) %d\n", buffer);
    key_delegs.push_back(KeyDelegation(data));
  }
  for(data->load(&buffer); buffer > 0; buffer--){
//    printf("c) %d\n", buffer);
    claims.push_back(PrefixClaim(data));
  }
  {
    data->load(&buffer);
    unsigned char *keybuff = new unsigned char[buffer];
    data->load(keybuff, buffer);
    Grassroots::RawData *keydata = new Grassroots::RawData();
    keydata->data = keybuff;
    keydata->size = buffer;
    owner = new Grassroots::KEY(keydata);
    delete keydata;
  }
  {
    sig = new Grassroots::RawData();
    data->load(&buffer);
    sig->size = buffer;
    sig->data = new unsigned char[sig->size];
    data->load(sig->data, sig->size);
  }
}

Grassroots::OwnerRecord::~OwnerRecord() {
  delete owner;
  if(sig) delete sig;
}

void Grassroots::OwnerRecord::start_batch(){
  sign_blocked = 1;
}
void Grassroots::OwnerRecord::finish_batch(){
  sign_blocked = 0;
  sign();
}

void Grassroots::OwnerRecord::sign(){
  if(sign_blocked) return;

  Grassroots::RawData *sigdata = gen_sigdata();
  
  assert(owner); 
  sig = owner->sign(sigdata);
  
  delete sigdata;
}
int Grassroots::OwnerRecord::verify(){
  Grassroots::RawData *sigdata = gen_sigdata();
  int ret;
  
  ret = owner->verify(sigdata, sig);
  
  delete sigdata;
  return ret;
}
void Grassroots::OwnerRecord::export_record(Grassroots::RawData *d){
  std::vector<Grassroots::OwnerRecord::ASDelegation>::iterator as;
  std::vector<Grassroots::OwnerRecord::KeyDelegation>::iterator key;
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator claim;
  uint32_t buffer;
  
  buffer = as_delegs.size();
  d->append(&buffer);
  for(as = as_delegs.begin(); as != as_delegs.end(); ++as){
    as->export_record(d);
  }
  buffer = key_delegs.size();
  d->append(&buffer);
  for(key = key_delegs.begin(); key != key_delegs.end(); ++key){
    key->export_record(d);
  }
  buffer = claims.size();
  d->append(&buffer);
  for(claim = claims.begin(); claim != claims.end(); ++claim){
    claim->export_record(d);
  }
  {
    Grassroots::RawData *keydata = owner->export_pub();
    buffer = keydata->size;  
    d->append(&buffer);
    d->append(keydata->data, keydata->size);
    delete keydata;
  }
  {
    buffer = sig->size;
    d->append(&buffer);
    d->append(sig->data, sig->size);
  }
}
void Grassroots::OwnerRecord::add_as_delegation(Grassroots::AS_ID _as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  as_delegs.push_back(Grassroots::OwnerRecord::ASDelegation(_as, _prefix, _prefix_len));
  add_claim(_prefix, _prefix_len); //this will call sign
}
void Grassroots::OwnerRecord::add_key_delegation(Grassroots::HASH *_key, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  Grassroots::HASH *key = new Grassroots::HASH();
  _key->cpy(key);
  key_delegs.push_back(KeyDelegation(key, _prefix, _prefix_len));
  sign();
}
void Grassroots::OwnerRecord::add_claim(Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator i;
  for(i = claims.begin(); i != claims.end(); ++i){
    if((i->prefix == _prefix) && (i->prefix_len == _prefix_len)){
      return;
    }
  }
  claims.push_back(Grassroots::OwnerRecord::PrefixClaim(_prefix, _prefix_len));
  sign();
}
Grassroots::RawData *Grassroots::OwnerRecord::gen_sigdata(){
  std::vector<Grassroots::OwnerRecord::ASDelegation>::iterator as;
  std::vector<Grassroots::OwnerRecord::KeyDelegation>::iterator key;
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator claim;
  Grassroots::RawData *data = new Grassroots::RawData(20);
  
  for(as = as_delegs.begin(); as != as_delegs.end(); ++as){
    as->export_record(data);
  }
  for(key = key_delegs.begin(); key != key_delegs.end(); ++key){
    key->export_record(data);
  }
  for(claim = claims.begin(); claim != claims.end(); ++claim){
    claim->export_record(data);
  }
  
  return data;
}
int Grassroots::OwnerRecord::calc_size(){
  int tot = (1024/8)*2 + sizeof(Grassroots::OwnerRecord) + sizeof(Grassroots::KEY);
  tot += sizeof(Grassroots::OwnerRecord::PrefixClaim) * claims.size();
  tot += sizeof(Grassroots::OwnerRecord::ASDelegation) * as_delegs.size();
  tot += sizeof(Grassroots::OwnerRecord::KeyDelegation) * key_delegs.size();
  tot += sig->size;
  tot += sizeof(Grassroots::RawData);
  return tot;
}
void Grassroots::OwnerRecord::print(){
  std::vector<Grassroots::OwnerRecord::ASDelegation>::iterator as;
  std::vector<Grassroots::OwnerRecord::KeyDelegation>::iterator key;
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator claim;
  Grassroots::HASH *h;
  
  h = owner->get_hash();
  h->print();
  delete h;
  
  printf(": ");
  for(claim = claims.begin(); claim != claims.end(); ++claim){
    printf(" [ I own ");print_ip(claim->prefix, 1);printf("/%d ]", claim->prefix_len);
  }
  for(key = key_delegs.begin(); key != key_delegs.end(); ++key){
    printf(" [ ");key->key->print();
    printf(" on ");print_ip(key->prefix, 1);printf("/%d ]", key->prefix_len);
  }
  for(as = as_delegs.begin(); as != as_delegs.end(); ++as){
    printf(" [ %d on ", as->as);print_ip(as->prefix, 1);printf("/%d ]", as->prefix_len);
  }

  printf("\n");
  
}

int Grassroots::OwnerRecord::check_auth(Grassroots::HASH *key, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  std::vector<Grassroots::OwnerRecord::KeyDelegation>::iterator i;
  
  for(i = key_delegs.begin(); i != key_delegs.end(); ++i){
    if( (i->prefix_len <= prefix_len) &&
        ( (i->prefix_len == 0) ||
          ((i->prefix_len >> (32-i->prefix_len)) == (prefix_len >> (32-i->prefix_len)))
        ) &&
        i->key->eq(key)){
        return 1;
    }
  }
  return 0;
}

int Grassroots::OwnerRecord::check_auth(Grassroots::AS_ID as, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  std::vector<Grassroots::OwnerRecord::ASDelegation>::iterator i;
  
  for(i = as_delegs.begin(); i != as_delegs.end(); ++i){
    if( (i->prefix_len <= prefix_len) &&
        ( (i->prefix_len == 0) ||
          ((i->prefix_len >> (32-i->prefix_len)) == (prefix_len >> (32-i->prefix_len)))
        ) &&
        (i->as == as)){
        return 1;
    }
  }
  return 0;
}
int Grassroots::OwnerRecord::check_auth(bgp_as_path *path, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  std::vector<Grassroots::OwnerRecord::ASDelegation>::iterator i;
  int j;
  bgp_as_path *pathentry;
  
  if(path == NULL) return 0;
  
  for(i = as_delegs.begin(); i != as_delegs.end(); ++i){
    if( (i->prefix_len <= prefix_len) &&
        ( (i->prefix_len == 0) ||
          ((i->prefix_len >> (32-i->prefix_len)) == (prefix_len >> (32-i->prefix_len)))
      )){
        for(pathentry = path; pathentry != NULL; pathentry = pathentry->next){
          for(j = 0; j < pathentry->len; j ++){
            if(pathentry->list[j] == i->as){
              return 1;
            }
          }
        }
      }
    
  }
  return 0;
}

///////////////////////////////////// Grassroots::OwnerRecord::PrefixClaim

Grassroots::OwnerRecord::PrefixClaim::PrefixClaim(Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len) : 
  prefix(_prefix), prefix_len(_prefix_len) {}
Grassroots::OwnerRecord::PrefixClaim::PrefixClaim(Grassroots::RawData *d){
  d->load(&prefix);
  d->load(&prefix_len);
}

void Grassroots::OwnerRecord::PrefixClaim::export_record(Grassroots::RawData *d){
  d->append(&prefix);
  d->append(&prefix_len);
}

///////////////////////////////////// Grassroots::OwnerRecord::ASDelegation

Grassroots::OwnerRecord::ASDelegation::ASDelegation(Grassroots::AS_ID _as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len) : 
  as(_as), prefix(_prefix), prefix_len(_prefix_len) {}
Grassroots::OwnerRecord::ASDelegation::ASDelegation(Grassroots::RawData *d){
  d->load(&as);
  d->load(&prefix);
  d->load(&prefix_len);
}

void Grassroots::OwnerRecord::ASDelegation::export_record(Grassroots::RawData *d){
  d->append(&as);
  d->append(&prefix);
  d->append(&prefix_len);
}

///////////////////////////////////// Grassroots::OwnerRecord::KeyDelegation

Grassroots::OwnerRecord::KeyDelegation::KeyDelegation(Grassroots::HASH *_key, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len) : 
  key(_key), prefix(_prefix), prefix_len(_prefix_len) {}
Grassroots::OwnerRecord::KeyDelegation::KeyDelegation(Grassroots::RawData *d){
  key = new Grassroots::HASH();
  key->load(d);
  d->load(&prefix);
  d->load(&prefix_len);
}

void Grassroots::OwnerRecord::KeyDelegation::export_record(Grassroots::RawData *d){
  key->append(d);
  d->append(&prefix);
  d->append(&prefix_len);
}

///////////////////////////////////// Grassroots::RawData
Grassroots::RawData::RawData() : 
  data(NULL), size(0), buffsize(0), ptr(0) {}
Grassroots::RawData::RawData(int basesize) : 
  data(new unsigned char[basesize]), size(0), buffsize(basesize), ptr(0) {}
Grassroots::RawData::RawData(unsigned char *_data, int _size) : 
  size(_size), buffsize(_size), ptr(0) { 
  data = new unsigned char[size];
  memcpy(data, _data, size);
}
Grassroots::RawData::RawData(FILE *f) : 
  data(NULL), size(0), buffsize(0), ptr(0) {
  input(f);
}

Grassroots::RawData::~RawData() {
  if(data != NULL) delete data;
}

Grassroots::RawData *Grassroots::RawData::clone(void){
  return new RawData(this->data, this->size);
}
void Grassroots::RawData::reset(){
  size = ptr = 0;
}
void Grassroots::RawData::append(unsigned char *indata, int insize){
  if(insize <= 0) return;
  if((ptr + insize) > buffsize){
    buffsize = (ptr+insize) * 4;
    unsigned char *tmpdata = new unsigned char[buffsize];
    memcpy(tmpdata, data, size);
    delete data;
    data = tmpdata;
  }
  memcpy(&(data[ptr]), indata, insize);
  ptr += insize;
  if(size < ptr){
    size = ptr;
  }
}
int Grassroots::RawData::load(unsigned char *outdata, int outsize){
  if((outsize+ptr) > size){ return -1; }
  memcpy(outdata, &(data[ptr]), outsize);
  ptr += outsize;
  return 0;
}

int Grassroots::RawData::input(FILE *f){
  reset();
  uint32_t rd_size;
  if(force_read(&rd_size, sizeof(uint32_t), f) < (int)sizeof(uint32_t)) return -1;
  size = rd_size;
  if(size > buffsize){
    if(data){
      delete data;
    }
    data = new unsigned char[size * 3];
    buffsize = size * 3;
  }
  if(force_read(data, size, f) < size) return -1;
  return 0;
}
void Grassroots::RawData::output(FILE *f){
  fwrite(&size, sizeof(uint32_t), 1, f);
  fwrite(data, size, 1, f);
}
///////////////////////////////////// Grassroots::HASH

Grassroots::HASH::HASH() : hash(NULL) {}
Grassroots::HASH::HASH(unsigned char *data, int len) : hash(NULL) {
  load(data, len);
}
Grassroots::HASH::~HASH() {
  if(hash){
    delete hash;
  }
}

void Grassroots::HASH::load(unsigned char *data, int len){
  if(hash) delete hash;

  unsigned char buff[EVP_MAX_MD_SIZE];
  EVP_MD_CTX ctx;
  
  assert(EVP_DigestInit(&ctx, EVP_sha1()));
  assert(EVP_DigestUpdate(&ctx, data, len));
  assert(EVP_DigestFinal(&ctx, buff, &size));

  hash = new unsigned char[size];
  memcpy(hash, buff, size);
}

int Grassroots::HASH::eq(const Grassroots::HASH *cmp){
  return memcmp(this->hash, cmp->hash, size) == 0;
}
void Grassroots::HASH::cpy(Grassroots::HASH *dst){
  if((dst->hash == NULL) || (size != dst->size)){
    if(dst->hash != NULL) delete dst->hash;
    dst->hash = new unsigned char[size];
    dst->size = size;
  }
  memcpy(dst->hash, hash, size);
}
void Grassroots::HASH::print(FILE *f){
  int x;
  fprintf(f, "{");
  for(x = 0; x < 5; x++){
    fprintf(f, "%02x",hash[x]);
  }
  fprintf(f, "}");
}


void Grassroots::HASH::append(Grassroots::RawData *data){
  data->append(&size);
  data->append(hash, size);
}
void Grassroots::HASH::load(Grassroots::RawData *data){
  uint32_t tempsize;
  
  data->load(&tempsize);
  if((hash == NULL) || (tempsize != size)){
    if(hash != NULL) delete hash;
    size = tempsize;
    hash = new unsigned char[size];
  }
  data->load(hash, size);
}
int Grassroots::HASH::calc_size(){
  return size + sizeof(Grassroots::HASH);
}

size_t Grassroots::HASH::SHRINK::operator()(const HASH *val){
  unsigned int x;
  size_t ret = 0;
  unsigned char top;
  
  //XOR the bits down into to a size_t by rotating
  for (x = 0; x < val->size; x++){
    top = (ret >> ((sizeof(size_t) - 1) * 8)) & 0xff;
    ret <<= 8;
    ret |= top ^ val->hash[x];
  }
  return ret;
}
int Grassroots::HASH::EQUALS::operator()(const HASH *a, const HASH *b){
  return ((HASH*)a)->eq(b);
}
int Grassroots::HASH::LESS::operator()(const HASH *a, const HASH *b){
  //a !< a
  //a < b          ->  b !< a
  //a < b < c      ->  a < c
  //a == b, b == c ->  a == c
  return (a->size == b->size) && (memcmp(a->hash, b->hash, a->size) < 0);
}

///////////////////////////////////// Grassroots::KEY

Grassroots::KEY::KEY(time_t _discovered, EVP_PKEY *_key) :
  discovered(_discovered), key(_key), priv_text(NULL), pub_text(NULL) { }
Grassroots::KEY::KEY(EVP_PKEY *_key) :
  discovered(0), key(_key), priv_text(NULL), pub_text(NULL) 
{ 
  discovered = time(NULL); 
}
Grassroots::KEY::KEY(Grassroots::RawData *raw) :
  discovered(0), key(NULL), priv_text(NULL), pub_text(NULL) 
{
  if(*((char *)raw->data) == 1) {
    key = OK_pubkey_import((char *)(raw->data+1), raw->size-1);
    //we base the key's signature off of this public text.  Consequently, it's necessary
    //to keep a copy of it around so we have a canonnical version.
    pub_text = raw->clone();
  } else {
    key = OK_privkey_import((char *)(raw->data+1), raw->size-1);
    priv_text = raw->clone();
  }
  discovered = time(NULL);
}
Grassroots::KEY::KEY(Grassroots::KEY *old) {
  key = OK_privkey_dup(old->key);
  discovered = old->discovered;
  if(old->pub_text) pub_text = old->pub_text->clone();
    else pub_text = NULL;
  if(old->priv_text) priv_text = old->priv_text->clone();
    else priv_text = NULL;
}
Grassroots::KEY::~KEY(){
  EVP_PKEY_free(key);
  if(pub_text) delete pub_text;
  if(priv_text) delete priv_text;  
}
Grassroots::HASH *Grassroots::KEY::get_hash(void){
  HASH *hash;
  int s;
  Grassroots::RawData *data = export_pub();

  hash = new Grassroots::HASH(data->data, data->size);

  delete data;
  return hash;
}
Grassroots::RawData *Grassroots::KEY::sign(Grassroots::RawData *data){
  unsigned char *ret;
  unsigned int retlen = EVP_PKEY_size(key);
  EVP_MD_CTX ctx;
  
  assert(EVP_SignInit(&ctx, EVP_sha1()));
  assert(EVP_SignUpdate(&ctx, data->data, data->size));
  ret = new unsigned char[retlen];
  assert(EVP_SignFinal(&ctx, ret, &retlen, key));
  
  return new RawData(ret, retlen);
}
int Grassroots::KEY::verify(Grassroots::RawData *data, Grassroots::RawData *sig){
  EVP_MD_CTX ctx;
  int ret;
  
  assert(EVP_VerifyInit(&ctx, EVP_sha1()));
  assert(EVP_VerifyUpdate(&ctx, data->data, data->size));
  assert((ret = EVP_VerifyFinal(&ctx, sig->data, sig->size, key)) >= 0);
  EVP_MD_CTX_cleanup(&ctx);
  
  return ret;
}
Grassroots::RawData *Grassroots::KEY::export_pub(){
  if(!pub_text){
    char *data;
    int len;
    char one = 1;
    
    len = OK_pubkey_export(key, &data);
    pub_text = new Grassroots::RawData();
    pub_text->append(&one);
    pub_text->append((unsigned char *)data, len);
    delete data;
  }
  
  return pub_text->clone();
}
Grassroots::RawData *Grassroots::KEY::export_priv(){
  if(!priv_text){
    char *data;
    int len;
    char zero = 0;
    
    len = OK_privkey_export(key, &data);
    priv_text = new Grassroots::RawData();
    priv_text->append(&zero);
    priv_text->append((unsigned char *)data, len);
    delete data;
  }

  return priv_text->clone();
}

///////////////////////////////////// Grassroots::OwnerTrie

Grassroots::OwnerTrie::OwnerTrie() {
  next[0] = next[1] = NULL;
  owner = NULL;
}

void Grassroots::OwnerTrie::import(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  assert(depth <= 32);
  assert(depth <= prefix_len);
  
  if(depth >= prefix_len){
    assert(!owner);
    owner = _owner;
  } else {
    if(!next[nextbit]){
      next[nextbit] = new OwnerTrie();
    }
    
    next[nextbit]->import(_owner, prefix, prefix_len, depth+1);
  }
}
void Grassroots::OwnerTrie::import(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  import(_owner, prefix, prefix_len, 0);
}
Grassroots::OwnerRecord *Grassroots::OwnerTrie::validate(Grassroots::OwnerRecord **_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  Grassroots::OwnerRecord *ret = NULL, *temp = NULL;
  assert(depth <= 32);
  assert(_owner);

  if(*_owner && owner && (owner != *_owner)){
    Grassroots::HASH *mykey = owner->owner->get_hash();
    if(!(*_owner)->check_auth(mykey, prefix, depth)){
      delete mykey;
      return owner;
    }
    delete mykey;
  }

  if(owner){
    temp = *_owner;
    *_owner = owner;
  }
  
  if(depth < prefix_len){
    if(next[nextbit]){
      ret = next[nextbit]->validate(_owner, prefix, prefix_len, depth+1);
    }
  } else {
    if(next[0]){
      ret = next[0]->validate(_owner, prefix, prefix_len, depth+1);
    }
    if(next[1] && (ret == NULL)){
      prefix = ntohl(prefix);
      prefix |= 1 << (31-depth);
      prefix = htonl(prefix);
      ret = next[1]->validate(_owner, prefix, prefix_len, depth+1);
    }
  }
  if(temp && (ret == NULL)){ 
    //if ret != null, that means a conflict has occured, and the conflicting owner is stored in ret.
    *_owner = temp;
  }
  return ret;
}
Grassroots::OwnerRecord *Grassroots::OwnerTrie::validate(Grassroots::OwnerRecord **conflict, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  assert(prefix_len <= 32);
  assert(conflict);
  *conflict = NULL;
  return validate(conflict, prefix, prefix_len, 0);
}
Grassroots::OwnerRecord *Grassroots::OwnerTrie::validate(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  Grassroots::OwnerRecord *_conflict_dummy = NULL;
  return validate(&_conflict_dummy, prefix, prefix_len);
}

//Two possible return values:
//1: (NULL)              Insertion was a success.
//2: (conflictingowner)  Insertion failed because the OwnerRecord returned has a claim to the prefix and 
//                         hasn't delegated sub-ownership to this owner.
Grassroots::OwnerRecord *Grassroots::OwnerTrie::claim(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  assert(prefix_len <= 32);
  Grassroots::OwnerRecord *conflictA, *conflictB;
  import(_owner, prefix, prefix_len);
  conflictA = validate(&conflictB, prefix, prefix_len);
  if(conflictA == NULL) return NULL;
  if(conflictA == _owner) return conflictB;
  if(conflictB == _owner) return conflictA;
  
  //The claim is going to fail because either the parent or a child of the insertion is bad.  If this
  //isn't the case, then we're inserting into a database that wouldn't otherwise pass validation.
  //That's the case if we've reached here.
  
  assert(!"Claim failed due to an inconsistent database!");
  return NULL;
}

// returns 0 for non-claimed prefix
// returns -1 for unauthorized 
// returns 1 for authorized
// >= 0 signifies an effective success
int Grassroots::OwnerTrie::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  int ret = 0;
  assert(depth <= 32);
  assert(depth <= prefix_len);
  
  if(depth < prefix_len){
    if(!next[nextbit]){
      ret = 0;
    } else {
      ret = next[nextbit]->validate_advertisers(prefix, prefix_len, path, depth+1);
    }
  }
  
  if(ret == 0){
    if(!owner){
      return 0;
    } else {
      if(owner->check_auth(path, prefix, prefix_len)){
        return 1;
      }
      return -1;
    }
  } else {
    return ret;
  }

  assert(!"This line should never be reached");
}
int Grassroots::OwnerTrie::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  int ret = 0;
  assert(depth <= 32);
  assert(depth <= prefix_len);
  
  if(depth < prefix_len){
    if(!next[nextbit]){
      ret = 0;
    } else {
      ret = next[nextbit]->validate_advertisers(prefix, prefix_len, advertisers, depth+1);
    }
  }
  
  if(ret == 0){
    if(!owner){
      return 0;
    } else {
      std::vector<Grassroots::AS_ID>::iterator i;
      
      for(i = advertisers->begin(); i != advertisers->end(); ++i){
        if(owner->check_auth(*i, prefix, prefix_len)){
          return 1;
        }
      }
      return -1;
    }
  } else {
    return ret;
  }

  assert(!"This line should never be reached");
}
int Grassroots::OwnerTrie::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path){
  assert(prefix_len <= 32);
  return validate_advertisers(prefix, prefix_len, path, 0);
}
int Grassroots::OwnerTrie::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers){
  assert(prefix_len <= 32);
  return validate_advertisers(prefix, prefix_len, advertisers, 0);
}
int Grassroots::OwnerTrie::calc_size(){
  int tot = sizeof(Grassroots::OwnerTrie);
  if(next[0]) tot += next[0]->calc_size();
  if(next[1]) tot += next[1]->calc_size();
  return tot;
}
Grassroots::OwnerRecord *Grassroots::OwnerTrie::find_owner(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  Grassroots::OwnerRecord *ret = NULL;
  assert(depth <= 32);
  assert(depth <= prefix_len);
  
  if((depth < prefix_len) && (next[nextbit])){
    ret = next[nextbit]->find_owner(prefix, prefix_len, depth+1);
  }
  if(!ret){
    ret = owner;
  }
  return ret;
}
Grassroots::OwnerRecord *Grassroots::OwnerTrie::find_owner(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  assert(prefix_len <= 32);
  return find_owner(prefix, prefix_len, 0);
}

//debug functions only 
void Grassroots::OwnerTrie::force_claim(Grassroots::OwnerRecord *_owner, Grassroots::AS_ID as, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth){
  int nextbit = (ntohl(prefix) >> (31-depth)) & 0x01;
  assert(depth <= 32);
  assert(depth <= prefix_len);
  if(depth >= prefix_len){
    if(!owner){
      owner = _owner;
    }
    owner->add_as_delegation(as, prefix, prefix_len);
    return;
  }
  
  if(!next[nextbit]){
    next[nextbit] = new OwnerTrie();
  }
  next[nextbit]->force_claim(_owner, as, prefix, prefix_len, depth+1);
}
void Grassroots::OwnerTrie::build_sigtree(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len){
  assert(prefix_len <= 32);
  
  if(owner){
    if(_owner == owner){
      //prune the tree a bit.  No need to include reflexive delegations.
      owner = NULL;
    } else {
      if(_owner) {
        Grassroots::HASH *h = owner->owner->get_hash();
        _owner->add_key_delegation(h, prefix, prefix_len);
        delete h;
      }
      _owner = owner;
    }
  }
  
  if(next[0]){
    next[0]->build_sigtree(_owner, prefix, prefix_len+1);
  }
  if(next[1]){
    prefix = ntohl(prefix);
    prefix |= 1 << (31-prefix_len);
    prefix = htonl(prefix);
    next[1]->build_sigtree(_owner, prefix, prefix_len+1);
  }
}

///////////////////////////////////// Grassroots

Grassroots::HASH *Grassroots::load_key(Grassroots::KEY *inkey){
  Grassroots::KEY *key = new Grassroots::KEY(inkey);
  Grassroots::HASH *hash = key->get_hash();
  key_db[hash] = new Grassroots::OwnerRecord(key);
  changed = 1;
  return hash;
}
Grassroots::KEY *Grassroots::find_key(Grassroots::HASH *hash){
  KeyDB::iterator i = key_db.find(hash);
  if(i == key_db.end()){ return NULL; }
  else { return i->second->owner; }
}

void Grassroots::grant(Grassroots::HASH *owner, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  KeyDB::iterator i = key_db.find(owner);
  assert(i != key_db.end());
  Grassroots::OwnerRecord *r = i->second;
  r->add_key_delegation(owner, _prefix, _prefix_len);
}
void Grassroots::claim(Grassroots::HASH *owner, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  KeyDB::iterator i = key_db.find(owner);
  assert(i != key_db.end());
  Grassroots::OwnerRecord *r = i->second;
  r->add_claim(_prefix, _prefix_len);
  iproot->claim(r, _prefix, _prefix_len);
}
void Grassroots::assign(Grassroots::AS_ID advertiser, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  Grassroots::OwnerRecord *r = iproot->find_owner(_prefix, _prefix_len);
  assert(r);
  r->add_as_delegation(advertiser, _prefix, _prefix_len);
  iproot->claim(r, _prefix, _prefix_len);
}

//begin debug functions
void Grassroots::preclaim(Grassroots::HASH *owner, Grassroots::AS_ID as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len){
  KeyDB::iterator i = key_db.find(owner);
  assert(i != key_db.end());
  Grassroots::OwnerRecord *r = i->second;
  iproot->force_claim(r, as, _prefix, _prefix_len, 0);  
}
void Grassroots::sign_all(){
  iproot->build_sigtree(NULL, 0, 0);
}
//end debug functions
void Grassroots::start_batch(HASH *owner){
  KeyDB::iterator i = key_db.find(owner);
  assert(i != key_db.end());
  i->second->start_batch();
}
void Grassroots::end_batch(HASH *owner){
  KeyDB::iterator i = key_db.find(owner);
  assert(i != key_db.end());
  i->second->finish_batch();
}

int Grassroots::export_db_if_changed(char *filename){
  if(changed){ return export_db(filename); }
  return 0;
}

int Grassroots::export_db(char *filename){
  // XXX - This should done via the overlay
  FILE *dbfile = fopen(filename, "w+");
  Grassroots::RawData *tempbuff = new Grassroots::RawData(20);
  Grassroots::KeyDB::iterator i;
  int cnt = 0;
  int bytes = 0;
  
  for(i = key_db.begin(); i != key_db.end(); ++i){
    tempbuff->reset();
    i->second->export_record(tempbuff);
    tempbuff->output(dbfile);
    cnt++;
    if(cnt % 1000 == 0) printf("\t%d records written\n", cnt);
    bytes += tempbuff->ptr + sizeof(uint32_t);
  }
  
  printf("   Finished Export: %d ownership records (%d bytes)\n", cnt, bytes);
  delete tempbuff;
  fclose(dbfile);
  changed = 0;

  return 0;
}
int Grassroots::import_db_novalidate(char *filename){
  // XXX - This should done via the overlay
  FILE *dbfile = fopen(filename, "r");
  Grassroots::OwnerRecord *r;
  Grassroots::HASH *h;
  Grassroots::RawData *tempbuff = new Grassroots::RawData(20);
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator i;
  int cnt = 0;
  int bytes = 0;
  
  while(tempbuff->input(dbfile) >= 0){
    cnt++;
    bytes += tempbuff->ptr + sizeof(uint32_t);
    r = new OwnerRecord(tempbuff);
    //r->print();
    h = r->owner->get_hash();
    key_db[h] = r;
    for(i = r->claims.begin(); i != r->claims.end(); ++i){
      iproot->import(r, i->prefix, i->prefix_len);
    }
    if(cnt % 1000 == 0) printf("\t%d records read\n", cnt);
  }
  
  printf("   Finished Import: %d ownership records (db is %d bytes)\n", cnt, calc_size());
  changed = 0;
  delete tempbuff;
  fclose(dbfile);
  
  return 0;
}
int Grassroots::import_db(char *filename){
  // XXX - This should done via the overlay
  FILE *dbfile = fopen(filename, "r");
  Grassroots::OwnerRecord *r;
  Grassroots::HASH *h;
  Grassroots::RawData *tempbuff = new Grassroots::RawData(20);
  std::vector<Grassroots::OwnerRecord::PrefixClaim>::iterator i;
  int cnt = 0;
  int bytes = 0;
  
  while(tempbuff->input(dbfile) >= 0){
    cnt++;
    bytes += tempbuff->ptr + sizeof(uint32_t);
    r = new OwnerRecord(tempbuff);
    //r->print();
    h = r->owner->get_hash();
    key_db[h] = r;
    for(i = r->claims.begin(); i != r->claims.end(); ++i){
      iproot->import(r, i->prefix, i->prefix_len);
    }
    if(cnt % 1000 == 0) printf("\t%d records read\n", cnt);
  }
  printf("   Finished loading db, validating all records\n");
  assert(iproot->validate(0, 0) == NULL);
  
  printf("   Finished Import: %d ownership records (db is %d bytes)\n", cnt, calc_size());
  changed = 0;
  delete tempbuff;
  fclose(dbfile);
  
  return 0;
}
int Grassroots::bootstrap(){
  changed = 1;
  return 0;
}
int Grassroots::calc_size(){
  int tot = iproot->calc_size() + sizeof(Grassroots);
  Grassroots::KeyDB::iterator i;
  
  for(i = key_db.begin(); i != key_db.end(); ++i){
    tot += i->first->calc_size();
    tot += i->second->calc_size();
  }
  
  return tot;
}

int Grassroots::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path){
  return iproot->validate_advertisers(prefix, prefix_len, path);
}
int Grassroots::validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers){
  return iproot->validate_advertisers(prefix, prefix_len, advertisers);
}
