#ifndef NBGP_GRASSROOTS_H_SHIELD
#define NBGP_GRASSROOTS_H_SHIELD

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <time.h>
#include <map>
#include <vector>
#include <arpa/inet.h>
#include "../nbgp/bgp.h"

//#define HASH_SIZE (EVP_MAX_MD_SIZE+1)
//bla.  This value changes with different versions of SSL.
#define HASH_SIZE (65)

class Grassroots {
 public:
  
  typedef unsigned short AS_ID;
  typedef uint32_t IP_ADDR;   //stored in network byte order
  typedef unsigned char IP_MASKLEN;
  
  Grassroots(AS_ID _as) : 
    key_db(), iproot(new OwnerTrie()), myas(_as), changed(0) {}
  
  struct RawData {
    RawData();
    RawData(int basesize);
    RawData(unsigned char *_data, int _size);
    RawData(FILE *f);
    ~RawData();
    
    unsigned char *data;
    int size;
    int buffsize;
    int ptr;
    
    RawData *clone(void);
    void reset();
    void append(unsigned char *indata, int insize);
    template <class T> void append(T *indata){
      append((unsigned char *)indata, sizeof(T));
    }
    int load(unsigned char *outdata, int outsize);
    template <class T> int load(T *outdata){
      return load((unsigned char *)outdata, sizeof(T));
    }
    
    int input(FILE *f);
    void output(FILE *f);
  };
  
  struct HASH {
    HASH();
    HASH(unsigned char *data, int len);
    ~HASH();
    
    void load(unsigned char *data, int len);
    
    int eq(const HASH *cmp);
    void cpy(HASH *dst);
    void print(FILE *f);
    void print() {print(stdout);}
    void append(Grassroots::RawData *data);
    void load(Grassroots::RawData *data);
    int calc_size();
    
    struct SHRINK { size_t operator()(const HASH *val); };
    struct EQUALS { int operator()(const HASH *a, const HASH *b); };
    struct LESS { int operator()(const HASH *a, const HASH *b); };

   protected:
    unsigned char *hash;
    uint32_t size;

  };
  
  struct KEY {
    KEY(time_t _discovered, EVP_PKEY *_key);
    KEY(Grassroots::KEY *old);
    KEY(EVP_PKEY *_key);
    KEY(Grassroots::RawData *_raw);
    ~KEY();

    Grassroots::HASH *get_hash(void);
    Grassroots::RawData *sign(Grassroots::RawData *data);
    int verify(Grassroots::RawData *data, Grassroots::RawData *sig);
    
    Grassroots::RawData *export_pub();
    Grassroots::RawData *export_priv();

    time_t discovered;
    EVP_PKEY *key;
    Grassroots::RawData *priv_text;
    Grassroots::RawData *pub_text;
  };
  
  Grassroots::HASH *load_key(Grassroots::KEY *key);
  Grassroots::KEY *find_key(Grassroots::HASH *hash);
    
  int export_db_if_changed(char *filename);
  int export_db(char *filename);
  int import_db(char *filename);
  int bootstrap();
  
  int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path);
  int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers);
  
  //delegation manipulation functions
  void grant(Grassroots::HASH *owner, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
  void claim(Grassroots::HASH *owner, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
  void assign(Grassroots::AS_ID advertiser, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
  void start_batch(Grassroots::HASH *owner);
  void end_batch(Grassroots::HASH *owner);
  
  //debug functions
  void preclaim(Grassroots::HASH *owner, Grassroots::AS_ID as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
  void sign_all();
  int calc_size();
  int import_db_novalidate(char *filename);
  
 private:
  
  struct OwnerRecord {
    OwnerRecord(Grassroots::KEY *_owner);
    OwnerRecord(Grassroots::RawData *data);
    ~OwnerRecord();
    
    void start_batch();
    void finish_batch();
    void sign();
    int verify();
    void export_record(Grassroots::RawData *d);
    void add_as_delegation(Grassroots::AS_ID _as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
    void add_key_delegation(Grassroots::HASH *_key, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
    void add_claim(Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
    Grassroots::RawData *gen_sigdata();
    int calc_size();
    void print();
    int check_auth(Grassroots::HASH *key, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    int check_auth(Grassroots::AS_ID as, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    int check_auth(bgp_as_path *path, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    
    struct PrefixClaim {
      PrefixClaim(Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
      PrefixClaim(Grassroots::RawData *d);
      
      void export_record(Grassroots::RawData *d);
      
      Grassroots::IP_ADDR prefix;
      Grassroots::IP_MASKLEN prefix_len;
    };
    
    struct ASDelegation {
      ASDelegation(Grassroots::AS_ID _as, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
      ASDelegation(Grassroots::RawData *d);
      
      void export_record(Grassroots::RawData *d);
      
      Grassroots::AS_ID as;
      Grassroots::IP_ADDR prefix;
      Grassroots::IP_MASKLEN prefix_len;
    };
    struct KeyDelegation {
      KeyDelegation(Grassroots::HASH *_key, Grassroots::IP_ADDR _prefix, Grassroots::IP_MASKLEN _prefix_len);
      KeyDelegation(Grassroots::RawData *d);
      
      void export_record(Grassroots::RawData *d);
      
      Grassroots::HASH *key;
      Grassroots::IP_ADDR prefix;
      Grassroots::IP_MASKLEN prefix_len;
    };
    
    std::vector<ASDelegation> as_delegs;
    std::vector<KeyDelegation> key_delegs;
    std::vector<PrefixClaim> claims;
    Grassroots::KEY *owner;
    
    int sign_blocked;
    Grassroots::RawData *sig;
  };
  
  typedef std::map< Grassroots::HASH*, 
                    Grassroots::OwnerRecord*, 
                    Grassroots::HASH::LESS> KeyDB;
  
  struct OwnerTrie {
    OwnerTrie *next[2];
    Grassroots::OwnerRecord *owner;
    
    OwnerTrie();
    
    int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path);
    int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers);
    Grassroots::OwnerRecord *claim(Grassroots::OwnerRecord *d, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    int calc_size();
    Grassroots::OwnerRecord *find_owner(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    void import(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    Grassroots::OwnerRecord *validate(Grassroots::OwnerRecord **conflict, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    Grassroots::OwnerRecord *validate(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    
    //debug functions
    void force_claim(Grassroots::OwnerRecord *_owner, Grassroots::AS_ID as, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth);
    void build_sigtree(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len);
    
   private:
    int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, bgp_as_path *path, int depth);
    int validate_advertisers(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, std::vector<Grassroots::AS_ID> *advertisers, int depth);
    OwnerRecord *claim(OwnerRecord *d, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth, int authed);
    Grassroots::OwnerRecord *find_owner(Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth);
    void import(Grassroots::OwnerRecord *_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth);
    Grassroots::OwnerRecord *validate(Grassroots::OwnerRecord **_owner, Grassroots::IP_ADDR prefix, Grassroots::IP_MASKLEN prefix_len, int depth);
  };
  
  Grassroots::KeyDB key_db;
  Grassroots::OwnerTrie *iproot;
  
  Grassroots::AS_ID myas;
  int changed;
};



#endif
