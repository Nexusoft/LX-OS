#ifndef NETQUERY_UUID_H_SHIELD
#define NETQUERY_UUID_H_SHIELD

#include <stdint.h>
#include <openssl/evp.h>

//UUIDBITS should be divisible by 4
#define UUIDBITS 20
//#define NQ_REUSE_UUIDS

typedef enum { NQ_UUID_TRANSACTION, NQ_UUID_TUPLE, NQ_UUID_ATTRIBUTE, NQ_UUID_TRIGGER, NQ_UUID_TRIGGER_REMOTE, NQ_UUID_ANY } NQ_UUID_Type;
typedef struct NQ_Host {
  uint32_t addr; // network byte order
  uint16_t port; // host byte order
} __attribute__((packed)) NQ_Host;

int NQ_Host_eq(NQ_Host a, NQ_Host b);

typedef struct NQ_Principal_Key {
  int hash_len;
  unsigned char hash[EVP_MAX_MD_SIZE];
} NQ_Principal_Key;

struct Principal;

typedef struct NQ_Principal {
  struct NQ_Principal *next, *prev;
  NQ_Host home;
  int references;
  EVP_PKEY *id;
  NQ_Principal_Key key;
#ifdef __cplusplus
  operator Principal ();
#endif
} NQ_Principal;

NQ_Principal *NQ_Principal_create();
NQ_Principal *NQ_Principal_from_RSA(RSA *rsa);

NQ_Principal *NQ_Principal_import(unsigned char *data, int len, int *read_amount);
int NQ_Principal_export(NQ_Principal *principal, unsigned char **data);
void NQ_Principal_delete(NQ_Principal *principal); //decrement the principal's refcount
void NQ_Principal_reserve(NQ_Principal *principal); //increment the principal's refcount
NQ_Principal *NQ_Principal_import_hash(unsigned char *data, unsigned int len);
int NQ_Principal_export_hash(NQ_Principal *principal, unsigned char **data);
int NQ_Principal_print_hash(NQ_Principal *p);
void NQ_Principal_print_allhashes();

// If NQ_UUID is changed, be sure to change tspace_marshall/unmarshall() and 
// namespace __gnu_cxx { template<> struct hash<NQ_UUID> }
typedef struct NQ_UUID {
  NQ_Host home;
  char id[UUIDBITS];
  NQ_UUID_Type type;
}  __attribute__((packed)) NQ_UUID;

typedef NQ_UUID NQ_Transaction;

typedef struct NQ_UUID_ref {
  struct NQ_UUID_ref *next, *prev;
  NQ_UUID id;
  NQ_Transaction transaction;
  void *val;
  void *gc_ref;
} NQ_UUID_ref;

extern NQ_UUID NQ_uuid_error;
extern NQ_UUID NQ_uuid_null;
extern NQ_Principal NQ_default_owner;
extern NQ_Principal NQ_principal_null;

//Initialize the UUID tracking system.
void NQ_UUID_init();
void NQ_UUID_cleanup();

//UUID management functions
int NQ_UUID_eq(NQ_UUID *a, NQ_UUID *b);
int NQ_UUID_eq_err(NQ_UUID *uuid);
int NQ_UUID_clr(NQ_UUID *a);
int NQ_UUID_cpy(NQ_UUID *dst, NQ_UUID *src);
int NQ_UUID_cmp(NQ_UUID *a, NQ_UUID *b);
NQ_UUID NQ_UUID_localized_null(NQ_Host host);

//Allocate a UUID to refer to an object of the specified type
NQ_UUID NQ_UUID_alloc(void *reference, NQ_UUID_Type type);

//Allocate a UUID as above, but in a transactional context.  (call finalize to remove the context)
NQ_UUID NQ_UUID_alloc_trans(NQ_Transaction transaction, void *reference, NQ_UUID_Type type);

//obtain the value referenced by a given UUID
void *NQ_UUID_lookup(NQ_UUID value);

//look up a UUID reference in the current transactional context
void *NQ_UUID_lookup_trans(NQ_Transaction transaction, NQ_UUID value); 

//commit a transactionally allocated UUID reference
int NQ_UUID_finalize(NQ_UUID value); 

//free a UUID reference.  This will place the UUID reference back in the pool if NQ_REUSE_UUIDS is defined
void *NQ_UUID_release(NQ_UUID value);

int NQ_Principal_eq(NQ_Principal *a, NQ_Principal *b);

void NQ_UUID_each(NQ_Transaction transaction, NQ_UUID_Type type, PFany iterator, void *userdata);

int NQ_UUID_print(NQ_UUID *a);
void NQ_UUID_dump(NQ_Transaction transaction, NQ_UUID_Type type);
void NQ_UUID_dump_all();

#endif
