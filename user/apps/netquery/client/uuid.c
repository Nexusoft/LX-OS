#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <nq/queue.h>
#include <nq/netquery.h>
#include <nq/util.hh>
#include <nq/gcmalloc.h>
#include <nq/net.h>
#include <nq/garbage.h>

#define NQ_RSA_KEYSIZE 1024
#define NQ_RSA_EXPONENT 3

#define SEQUENTIAL_UUIDS

////////////////////////////// GLOBAL TYPES
NQ_UUID NQ_uuid_error;
NQ_UUID NQ_uuid_null;
NQ_Principal NQ_principal_null;
NQ_Principal NQ_default_owner;

static Queue *uuidpool;

NQ_UUID_Table *uuid_table;

////////////////////////////// INITIALIZATION
void NQ_UUID_init(){
  NQ_Principal *p;
  uuid_table = NQ_UUID_Table_new();

  bzero(&NQ_uuid_error, sizeof(NQ_UUID));
  bzero(&NQ_uuid_null, sizeof(NQ_UUID));
  uuidpool = queue_new();
  
  printf("Creating default owner...");
  p = NQ_Principal_create();
  memcpy(&NQ_default_owner, p, sizeof(NQ_Principal));
  printf("done\n");
}
void NQ_UUID_cleanup(){
}

////////////////////////////// NQ_UUID

// BAAAAAAAAH... Why doesn't OpenSSL have this?
// ok... let's hack some shit together.
int EVP_PKEY_eq(EVP_PKEY *a, EVP_PKEY *b){
  return 1;
  RSA *ra = EVP_PKEY_get1_RSA(a), *rb = EVP_PKEY_get1_RSA(b);
  
  return  // RSA PubKey consists of the exponent e and the modulus n.
    (ra)&&(rb)&&
    BN_cmp(ra->n, rb->n)&&
    BN_cmp(ra->e, rb->e);
}

int NQ_Host_eq(NQ_Host a, NQ_Host b){
  return (a.addr == b.addr)&&(a.port == b.port);
}

void NQ_Principal_build_hash(NQ_Principal *principal, unsigned char *data, unsigned int len){
  unsigned int dummylen = EVP_MAX_MD_SIZE;
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();

  if(data == NULL){
    len = NQ_Principal_export(principal, &data);
  }

  memset(principal->key.hash, 0, sizeof(principal->key.hash));
  EVP_DigestInit(ctx, EVP_sha1());
  EVP_DigestUpdate(ctx, data, len);
  EVP_DigestFinal(ctx, principal->key.hash, &dummylen);
  assert(dummylen < EVP_MAX_MD_SIZE);
  EVP_MD_CTX_destroy(ctx);
  principal->key.hash_len = dummylen;
}

NQ_Principal *NQ_Principal_from_RSA(RSA *newkey) {
  NQ_Principal *principal = malloc(sizeof(NQ_Principal));
  bzero(principal, sizeof(NQ_Principal));
  principal->home = NQ_Net_get_localhost();
  principal->references = 1;
  
  principal->id = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(principal->id, newkey);
    
  NQ_Principal_build_hash(principal, NULL, 0);
  
  principal = NQ_Principal_add(principal);

  return principal;
}

NQ_Principal *NQ_Principal_create(void){
  RSA *newkey = 
    RSA_generate_key(NQ_RSA_KEYSIZE, NQ_RSA_EXPONENT, NULL, NULL);
  
  return NQ_Principal_from_RSA(newkey);
}

typedef struct NQ_Principal_Query {
  EVP_PKEY *pkey;
  NQ_Host host;
} NQ_Principal_Query;

void NQ_Principal_reserve(NQ_Principal *principal){
  principal->references++;
}

int NQ_Principal_print_hash(NQ_Principal *p){
  printf("(");
  print_hex(p->key.hash, p->key.hash_len);
  printf(")");
  return 0;
}

int NQ_Principal_export_hash(NQ_Principal *principal, unsigned char **data){
  *data = principal->key.hash;
  return principal->key.hash_len;
}


NQ_Principal *NQ_Principal_import_hash(unsigned char *data, unsigned int len){
  NQ_Principal *ret = NQ_Principal_find(data, len);
  if(ret) { NQ_Principal_reserve(ret);}
  return ret;
}

struct BIO_Stat {
  int read_amt;
};

static long bio_callback(BIO *b, int oper, const char *argp,
                         int argi, long argl, long retvalue) {
  struct BIO_Stat *stat = (struct BIO_Stat *)b->cb_arg;
  // printf("callback %x, %x %x %ld\n", oper, BIO_CB_READ, BIO_CB_RETURN, retvalue);
  if( oper == (BIO_CB_READ|BIO_CB_RETURN) || oper == (BIO_CB_GETS|BIO_CB_RETURN) ) {
    stat->read_amt += retvalue;
    //printf("add %d\n", stat->read_amt);
  }
  return retvalue;
}

NQ_Principal *NQ_Principal_import(unsigned char *data, int len, int *read_amount){
  BIO *mem_b = BIO_new_mem_buf(data, len);

  struct BIO_Stat stat;
  memset(&stat, 0, sizeof(stat));
  BIO_set_callback(mem_b, bio_callback);
  BIO_set_callback_arg(mem_b, &stat);

  NQ_Host principal_home;
  EVP_PKEY *pubkey;
  NQ_Principal *principal;
  BIO_read(mem_b, &principal_home, sizeof(principal_home));
  pubkey = PEM_read_bio_PUBKEY(mem_b, NULL, NULL, NULL);
  if(!pubkey){
    printf("Failure importing principal %p %d, principal home ", data, len); NQ_Host_print(principal_home); printf("\n");
    BIO_free(mem_b);
    return NULL;
  }
  if(read_amount != NULL) {
    *read_amount = stat.read_amt;
  }
  
  principal = malloc(sizeof(NQ_Principal));
  bzero(principal, sizeof(NQ_Principal));
  principal->home = principal_home;
  principal->id = pubkey;
  principal->references = 1;
  NQ_Principal_build_hash(principal, data, len);

  principal = NQ_Principal_add(principal);
  
  BIO_free(mem_b);
  return principal;
}

int NQ_Principal_export(NQ_Principal *principal, unsigned char **data){
  char *retptr;
  int retlen;
  BIO *mem_b = BIO_new(BIO_s_mem());
  
  //home is already in network byte order
  BIO_write(mem_b, &principal->home, sizeof(principal->home));
  PEM_write_bio_PUBKEY(mem_b, principal->id);
  
  retlen = BIO_get_mem_data(mem_b, &retptr);
  *data = malloc(retlen);
  memcpy(*data, retptr, retlen);
  
  BIO_free(mem_b);
  return retlen;
}

int NQ_Principal_eq(NQ_Principal *a, NQ_Principal *b){
  return 
    NQ_Host_eq(a->home, b->home) &&
    EVP_PKEY_eq(a->id, b->id); 
}

int NQ_UUID_print(NQ_UUID *a){
  printf("[");print_hex((unsigned char *)a->id, sizeof(a->id));printf(":%d@",a->type);NQ_Host_print(a->home);printf("]");
  return 0;
}
int NQ_UUID_eq(NQ_UUID *a, NQ_UUID *b){
  int ret = (memcmp(a->id, b->id, UUIDBITS) == 0) && (a->type == b->type) && NQ_Host_eq(a->home, b->home);
  if(ret){ NQ_stat.uuid_eq_yes++; } else { NQ_stat.uuid_eq_no++; }
  return ret;
}
int NQ_UUID_clr(NQ_UUID *a){
  bzero(a, sizeof(NQ_UUID));
  return 0;
}
int NQ_UUID_cpy(NQ_UUID *dst, NQ_UUID *src){
  memcpy(dst, src, sizeof(NQ_UUID));
  return 0;
}

#define C(X,N) (a->X < b->X) ? (-1) : ((a->X > b->X) ? (1) : (N))
int NQ_UUID_cmp(NQ_UUID *a, NQ_UUID *b) {
  return C(home.addr,
	   C(home.port,
	     C(type, 
	       memcmp(a->id, b->id, sizeof(a->id)))));

}

int NQ_UUID_eq_err(NQ_UUID *uuid){
  return (memcmp(uuid->id, NQ_uuid_null.id, UUIDBITS) == 0) && (uuid->type == NQ_uuid_null.type);
}
void *NQ_UUID_lookup_helper(NQ_UUID value, NQ_UUID_ref **ref){
  NQ_UUID_ref *ret = NQ_UUID_Table_find(uuid_table, &value);
  if(ref) *ref = ret;
  if(ret){
    if(ret->id.type == NQ_UUID_TRANSACTION && ret->val != NULL) {
      NQ_Transaction_Real_get((NQ_Transaction_Real *)ret->val);
    }
    return ret->val;
  }
//  printf("UUID Lookup has no ref: ");NQ_UUID_print(&value);printf("\n");
  return NULL;
}
NQ_UUID NQ_UUID_localized_null(NQ_Host host){
  NQ_UUID ret;
  bzero(&ret, sizeof(NQ_UUID));
  ret.home = host;
  return ret;
}

void NQ_UUID_insert_helper(NQ_UUID_ref *ref) {
  NQ_UUID_Table_insert(uuid_table, &ref->id, ref);
}

void *NQ_UUID_lookup(NQ_UUID value){
  return NQ_UUID_lookup_helper(value, NULL);
}
void *NQ_UUID_lookup_trans(NQ_Transaction transaction, NQ_UUID value){
  NQ_UUID_ref *ref;
  void *ret;
  ret = NQ_UUID_lookup_helper(value, &ref);
  if(NQ_Transaction_subseteq(ref->transaction, transaction)) return ret;
  else return NULL;
}

typedef struct UUID_Iterator_Wrapper {
  NQ_Transaction transaction;
  NQ_UUID_Type type;
  PFany iterator;
  void *userdata;
} UUID_Iterator_Wrapper;

static void iterator_wrapper_fn(NQ_UUID_ref *entry, UUID_Iterator_Wrapper *w){
  if((w->type == NQ_UUID_ANY) || (entry->id.type == w->type)){
    if(NQ_Transaction_subseteq(entry->transaction, w->transaction)){
      w->iterator(entry, w->userdata);
    }
  }
}

void NQ_UUID_each_helper(NQ_Transaction transaction, NQ_UUID_Type type, PFany iterator, void *userdata) {
  UUID_Iterator_Wrapper wrapper = {
    .transaction = transaction,
    .type = type,
    .iterator = iterator,
    .userdata = userdata,
  };
  NQ_UUID_Table_each(uuid_table, transaction, type, (PFany) iterator_wrapper_fn, (void *)&wrapper);
}

typedef struct {
  NQ_Transaction transaction;
  PFany call;
  void *userdata;
} NQ_UUID_iterator;

static void NQ_UUID_each_iterator(NQ_UUID_ref *entry, NQ_UUID_iterator *iterator){
  if(NQ_Transaction_subseteq(entry->transaction, iterator->transaction)){
    iterator->call(entry->val, iterator->userdata);
  }
}

void NQ_UUID_each(NQ_Transaction transaction, NQ_UUID_Type type, PFany call, void *userdata){
  NQ_UUID_iterator iterator = { transaction, call, userdata };
  NQ_UUID_each_helper(transaction, type, (PFany)&NQ_UUID_each_iterator, &iterator);
}

void NQ_UUID_dump_print(NQ_UUID_ref *entry, void *dummy){
  NQ_UUID_print(&entry->id);printf(" = %p\n", entry->val);
}

void NQ_UUID_dump(NQ_Transaction transaction, NQ_UUID_Type type){
  printf("\n\n");
  NQ_UUID_each_helper(transaction, type, (PFany)&NQ_UUID_dump_print, NULL);
  printf("\n\n");
}

void NQ_UUID_dump_all(){
  NQ_UUID_dump(NQ_uuid_error, NQ_UUID_ANY);
}

int nextid = 0;

NQ_UUID NQ_UUID_alloc_trans(NQ_Transaction transaction, void *reference, NQ_UUID_Type type){
  NQ_UUID_ref *oldref;
  int i;
  NQ_UUID_ref *ret = NULL;
  void *_ret;
  
  if(queue_dequeue(uuidpool, &_ret)){
    ret = malloc(sizeof(NQ_UUID_ref));
    bzero(ret, sizeof(NQ_UUID_ref));
    ret->id.home = NQ_Net_get_localhost();
    
    while(1){ //can generate these non-probabalistically, but eh.
#ifdef SEQUENTIAL_UUIDS
      int thisid = nextid;
      nextid++;
      for(i = 0; i < UUIDBITS; i++){
        ret->id.id[i] = thisid & 0xff;
        thisid >>= 8;
      }
#else
      for(i = 0; i < UUIDBITS; i++){
        ret->id.id[i] = (unsigned char)(rand()%0xff);
      }
#endif
      if(!NQ_UUID_eq(&ret->id, &NQ_uuid_error)){
        if((!NQ_UUID_lookup_helper(ret->id, &oldref))&&(!oldref)){
          break;
        }
      }
    }
//    printf("prepending: ");NQ_UUID_print(&ret->id);printf("\n");
  } else {
    ret = _ret;
//    printf("reusing: ");NQ_UUID_print(&ret->id);printf("\n");
  }
  ret->val = reference;
  ret->id.type = type;

  NQ_UUID_insert_helper(ret);
  memcpy(&ret->transaction, &transaction, sizeof(NQ_Transaction));

  return ret->id;
}

NQ_UUID NQ_UUID_alloc(void *reference, NQ_UUID_Type type){
  return NQ_UUID_alloc_trans(NQ_uuid_error, reference, type);
}

int NQ_UUID_finalize(NQ_UUID value){
  NQ_UUID_ref *ref;
  if(NQ_UUID_lookup_helper(value, &ref)){
    NQ_UUID_clr(&ref->transaction);
    return 0;
  }
  return -1;
}

void *NQ_UUID_release(NQ_UUID value){
  NQ_UUID_ref *ref;
  void *ret = NULL;
  if(NQ_UUID_lookup_helper(value, &ref)){
#ifdef NQ_REUSE_UUIDS
    NQ_UUID_Table_delete(uuid_table, &value);
    queue_append(uuidpool, ref);
#endif
    ret = ref->val;
    // refcnt for transaction is passed to caller process on return

    ref->val = NULL;
    if(ref->gc_ref){
      NQ_GC_deregister(ref->gc_ref);
      ref->gc_ref = NULL;
    }
    NQ_UUID_clr(&ref->transaction);
  }
  return ret;
}

