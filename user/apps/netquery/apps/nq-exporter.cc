#include <stdio.h>
#include <string>
#include <set>
#include <map>
#include <algorithm>
#include <iterator>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include <nq/net.h>
#include <nq/uuid.h>
#include <nq/site.hh>
#include <nq/marshall.hh>
#include <nq/attribute.h>
#include <nq/util.hh>
#include <iostream>
#include <fstream>
#include <vector>

#include <nq/site.hh>
#include <openssl/pem.h>

#ifndef __LINUX__
extern "C" {
#include <nexus/generaltime.h>
#include <nexus/vkey.h>
#include <nexus/KernelFS.interface.h>
};
#endif // __LINUX__

enum ParserType {
  PARSE_NEXUS,
  PARSE_LINUX,
};

ParserType g_parser_type = PARSE_NEXUS;

using namespace std;

#define SKIP(X) do { std::cerr << "Not doing " << #X << "\n"; } while(0)
#define THROW(X) do { std::cerr << "Throwing \"" << X << "\"\n"; throw X; } while(0)

X509 *pem2x509(const unsigned char *pem, int len){
  BIO *tmp = BIO_new_mem_buf((unsigned char *)pem, len);
  X509 *ret = PEM_read_bio_X509(tmp, NULL, NULL, NULL);
  BIO_free(tmp);
  return ret;
}

X509 *pem2x509(const DataBuffer &d){
  return pem2x509(vector_as_ptr(d), d.size());
}

static inline void read_file_all(const char *filename, DataBuffer *d) {
  const int CHUNK_SIZE = 1024;
  cerr << "Reading from " << filename << "\n";
  ifstream ifs(filename);
  if(!ifs.good()) {
    cerr << "Could not open " << filename << "\n";
    THROW("Could not open file!\n");
  }
  while(!ifs.eof()) {
    d->resize(d->size() + CHUNK_SIZE);
    ifs.read((char *)&*(d->end() - CHUNK_SIZE), CHUNK_SIZE);
    int amount = ifs.gcount();
    d->resize(d->size() - (CHUNK_SIZE - amount));
  }
  ifs.close();
}

NQ_Host data_home;

struct Introspection;
struct Translator;
typedef set<Translator*> TranslatorAggr;
struct Translator {
  Introspection * const introspection;
  const string source_path;
  TranslatorAggr children;

  Translator(Introspection *p, const string &path);
  virtual ~Translator();
  virtual void compute_update(Transaction *t) = 0;
  void add_child(Translator *c);
  void del_child(Translator *c);
};

template <class T> struct TSpaceWriter {
  virtual ~TSpaceWriter() { }
  virtual void apply(Transaction *t, const T &new_val) = 0;
};

struct Introspection {
  TranslatorAggr translators;

  void add(Translator *t) {
    assert(translators.find(t) == translators.end());
    translators.insert(t);
  }
  void del(Translator *t) {
    assert(translators.find(t) != translators.end());
    translators.erase(t);
  }

  void run_all(Transaction *t) {
    vector<Translator *>current(translators.begin(), translators.end());
    set<Translator *> executed;
    while(current.size() > 0) {
      for(vector<Translator *>::iterator i = current.begin();
	  i != current.end(); i++) {
	(*i)->compute_update(t);
	executed.insert(*i);
      }
      vector<Translator *> added;
      back_insert_iterator< vector<Translator *> > back_it (added);
      set_difference(translators.begin(), translators.end(), 
		     executed.begin(), executed.end(), back_it);
      current = added;
    }
  }
};

Translator::Translator(Introspection *p, const string &path) : introspection(p), source_path(path) {
  p->add(this);
}

void Translator::add_child(Translator *c) {
  children.insert(c);
}
void Translator::del_child(Translator *c) {
  children.erase(c);
}
Translator::~Translator() {
  for(TranslatorAggr::iterator i = children.begin(); i != children.end(); i++) {
    delete *i;
  }
}

struct ApplyFunc {
  virtual ~ApplyFunc() { };
  virtual void apply(dirent *e) = 0;
};

bool foreach_file(const string &directory, ApplyFunc *fn) {
  struct dirent *ent;
  DIR *dir = opendir(directory.c_str());
  if(dir == NULL) {
    cerr << "Could not open \"" << directory << "\" directory\n";
    return false;
  }
  while( (ent = readdir(dir)) ) {
    if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
      continue;
    }
    fn->apply(ent);
  }
  closedir(dir);
  return true;
}

/* Set comes from iterating through a directory */
// Currently only supports int filenames
template <typename T, typename P> struct Set : public Translator {
  typedef map<int, T* > ElemMap;
  ElemMap elems;
  P *parent;
  Set(Introspection *p, string path, P *_parent) : Translator(p, path), parent(_parent) {
    // do nothing
  }
  struct ScanDirSet : public ApplyFunc {
    set<int> new_set;
    void apply(dirent *e) {
      char *end;
      int id = strtoul(e->d_name, &end, 10);
      if(end != e->d_name + strlen(e->d_name)) {
	cerr << "Invalid filename " << e->d_name << "\n";
	return;
      }
      new_set.insert(id);
    }
  };
  void compute_update(Transaction *t) {
    ScanDirSet s;
    cerr << "Set: Loading from " << source_path << "\n";
    cerr << "Thread id is " << pthread_self() << "\n";
    foreach_file(source_path, &s);

    set<int> orig_set;
    typename ElemMap::const_iterator i;
    for(i = elems.begin(); i != elems.end(); i++) {
      orig_set.insert(i->first);
    }
    vector<int> added;
    vector<int> removed;

    back_insert_iterator< vector<int> > 
      back_it_added(added),
      back_it_removed (removed);

    set_difference(orig_set.begin(), orig_set.end(), s.new_set.begin(), s.new_set.end(),
		   back_it_removed);
    set_difference(s.new_set.begin(), s.new_set.end(), orig_set.begin(), orig_set.end(),
		   back_it_added);
    for(vector<int>::iterator i = added.begin(); i != added.end(); i++) {
      cerr << "Adding " << source_path << " " << *i << "\n";
      elems[*i] = new T(introspection, source_path, *i, parent);
    }
    for(vector<int>::iterator i = removed.begin(); i != removed.end(); i++) {
      cerr << "Set removal not supported!\n";
    }
  }
};

struct StringValue : public Translator {
  TSpaceWriter<string> *writer;
  StringValue(Introspection *p, const string &path, TSpaceWriter<string> *w ) : 
    Translator(p, path), writer(w) {
  }
  void compute_update(Transaction *t) {
    cerr << "String update, path = " << source_path << "\n";
    DataBuffer d;
    read_file_all(source_path.c_str(), &d);

    d.push_back('\0');
    if( strlen((const char *)vector_as_ptr(d)) != d.size() - 1 ) {
      cerr << "read a non-string blob from reflection\n";
      return;
    }

    string str((const char *)vector_as_ptr(d));
    // cerr << "Writing \"" << str << "\"\n";
    writer->apply(t, str);
  }
};

struct BlobValue : public Translator {
  TSpaceWriter<vector<unsigned char> > *writer;
  BlobValue(Introspection *p, const string &path, TSpaceWriter<vector<unsigned char> > *w ) : 
    Translator(p, path), writer(w) {
  }
  void compute_update(Transaction *t) {
    cerr << "String update, path = " << source_path << "\n";
    DataBuffer d;
    try {
      read_file_all(source_path.c_str(), &d);
    } catch(...) {
      return;
    }

    // cerr << "Writing \"" << str << "\"\n";
    writer->apply(t, d);
  }
};

struct X_IPD;
struct X_IPC_Port : public Translator {
  X_IPD *parent;
  X_IPC_Port(Introspection *p, string parent_path, int id, X_IPD *_parent) : 
    Translator(p, string(parent_path) + "/" + itos(id)),
    parent(_parent) {
  }
  void compute_update(Transaction *t) {
    cerr << "X_IPC_Port::compute_update() not implemented\n";
  }
};

template <class T>
struct TStringWriter : public TSpaceWriter<string> {
  ExtRef<T> ref;
  T_string T::*str;
  TStringWriter(ExtRef<T> r, T_string T::*s) : ref(r), str(s) {
  }
  virtual void apply(Transaction *t, const string &new_val) {
    T *tuple = ref.load(*t);
    // cerr << "Transferring to offset " << (int)&(((T*)0)->*str) << "\n";
    (tuple->*str).store(new_val);
  }
};

template <class T>
struct TBlobWriter : public TSpaceWriter<vector<unsigned char> > {
  ExtRef<T> ref;
  T_blob T::*str;
  TBlobWriter(ExtRef<T> r, T_blob T::*s) : ref(r), str(s) {
  }
  virtual void apply(Transaction *t, const vector<unsigned char> &new_val) {
    T *tuple = ref.load(*t);
    // cerr << "Transferring to offset " << (int)&(((T*)0)->*str) << "\n";
    (tuple->*str).store(new_val);
  }
};

struct X_IPD : public Translator {
public:
  ExtRef<T_ProcessList> parent;
  int id;
  Set<X_IPC_Port, X_IPD> ports;
  StringValue *name;
  BlobValue *hash;

  X_IPD(Introspection *p, string parent_path, int _id, ExtRef<T_ProcessList> *_parent) : 
    Translator(p, parent_path + "/" + itos(_id)),
    parent(*_parent), 
    id(_id),
    ports(p, source_path + string("/user_terms/ports"), this),
    name(NULL), hash(NULL)
  {
    add_child(&ports);
  }

  void compute_update(Transaction *t) {
    cerr << "IPD update, path = " << source_path << " (nop)\n";
    if(name == NULL) {
      cerr << "init new\n";
      assert(Host::get_process(t, parent, id, false) == NULL);
      T_Process *process = Host::get_process(t, parent, id, true);
      assert(process != NULL);

      name = new StringValue(introspection, source_path + string("/name"), 
			    new TStringWriter<T_Process>(ExtRefOf(process), &T_Process::name));
      hash = new BlobValue(introspection, source_path + string("/map/segInfo.hash_value"), 
			     new TBlobWriter<T_Process>(ExtRefOf(process), &T_Process::hash));

      add_child(name);
      add_child(hash);
      process->key.store(itos(id));
    } else {
      // nop
    }
  }
};

#if 0
struct X_NetComp : public Translator {
  X_NetComp(Introspection *p, xxx) : Translator(p), source_path(xxx) {
    assert(0);
  }
  void compute_update(Transaction *t) {
    xxx;
  }
};
#endif

Introspection all_translators;

static bool trust_all(NQ_Tuple tid, KnownClass *obj_class) {
  return true;
}

bool trust_attrval_all(NQ_Attribute_Name *name, NQ_Tuple tid, NQ_Principal *principal) {
	          return true;
}


T_X509 *T_X509_from_pem(Transaction *t, DataBuffer *pem) {
  T_X509 *cert = new T_X509(*t);
  cert->tspace_create();
  pem->push_back('\0');
  cert->val = string( (const char *) vector_as_ptr(*pem) );
  return cert;
}

void ssl_init(void) {
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  SSL_library_init();
  SSL_load_error_strings();
}

DataBuffer *host_crt_pem;
DataBuffer *nsk_crt_pem;
NQ_Principal *host_principal;

#ifndef __LINUX__
VKey *host_vkey;
#endif

#ifndef __LINUX__
void create_host_principal(void) {
  TimeString *starttime = timestring_create(2005, 6, 13, 18, 0, 0);
  TimeString *endtime = timestring_create(2010, 6, 14, 18, 0, 0);

  DataBuffer nsk_ser;
  nsk_crt_pem = new DataBuffer();
  read_file_all("/nfs/nexus.nsk", &nsk_ser);
  read_file_all("/nfs/nexus.nsk.crt", nsk_crt_pem);

  X509 *nsk_crt = pem2x509(*nsk_crt_pem);
  VKey *nsk_vkey = vkey_deserialize( (char *)vector_as_ptr(nsk_ser), nsk_ser.size() );
  if(nsk_vkey == NULL) {
    cerr << "Could not deserialize saved nsk!\n";
    THROW("Bad NSK\n");
  }

  host_vkey = vkey_create(VKEY_TYPE_PAIR, ALG_RSA_SHA1);
  int len = vkey_nsk_certify_key_len(nsk_vkey, host_vkey, starttime, endtime);
  unsigned char *x509_buf = new unsigned char[len];
  memset(x509_buf, 0, len);
  int rv =
    vkey_nsk_certify_key(nsk_vkey, host_vkey, starttime, endtime, (char *)x509_buf, &len);
  if(rv != 0) {
    cerr << "error certifying key!\n";
    exit(-1);
  }
  host_crt_pem = new DataBuffer(x509_buf, len);
  RSA *host_rsa = vkey_openssl_export(host_vkey);
  host_principal = NQ_Principal_from_RSA(host_rsa);

  ofstream olog("/nfs/host-gen.txt");
  olog << "len = " << len << "\n pem len = " << host_crt_pem->size() << "\n";
  olog.close();
  ofstream ofs("/nfs/host_vkey.txt");
  ofs << *host_crt_pem;
  ofs.close();
}
#else
static int password_cb(char *buf,int num,
		       int rwflag,void *userdata)
{
  const char *pass = "foobar";
  if(num < (int) (strlen(pass)+1) )
    return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

void create_host_principal(void) {
  const char *cert_file = "spamfree.crt";
  const char *privkey_file = "spamfree.key";

  host_crt_pem = new DataBuffer();
  read_file_all(cert_file, host_crt_pem);
  // X509 *host_crt = pem2x509(*host_crt_pem);

  // N.B. The certificates do not match properly
  FILE *fp = fopen(privkey_file, "r");
  RSA *host_rsa = PEM_read_RSAPrivateKey(fp, NULL, password_cb, NULL);
  fclose(fp);
  host_principal = 
    NQ_Principal_from_RSA(host_rsa);
}
#endif

void write_host_labels(Transaction *t, Host *host) {
  // Get NSK 
  DataBuffer ca_crt_pem;
  DataBuffer nexusca_crt_pem;
  read_file_all("/nfs/ca.crt", &ca_crt_pem);
  read_file_all("/nfs/nexusca.crt", &nexusca_crt_pem);

  host->composite_element->certificate_chain.
    push_back(T_X509_from_pem(t, host_crt_pem));
#if 0 // privacy CA
  host->composite_element->certificate_chain.
    push_back(T_X509_from_pem(t, &ca_crt_pem));
#endif
  if(nsk_crt_pem != NULL) {
    // Trusted Nexus
    host->composite_element->certificate_chain.
      push_back(T_X509_from_pem(t, nsk_crt_pem));
  }
  // Nexus vetting CA
  host->composite_element->certificate_chain.
    push_back(T_X509_from_pem(t, &nexusca_crt_pem));
}

void exit_usage() {
  cout << "Usage: nqsh <host> <port> \n";
  exit(-1);
}

int main(int argc, char **argv) {
  ssl_init();

  NQ_init(NQ_PORT_ANY);
  NQ_cpp_lib_init();

  int opt;
  while( (opt = getopt(argc, argv, "NL")) != -1) {
    switch(opt) {
    case 'N':
      g_parser_type = PARSE_NEXUS;
      break;
    case 'L':
      g_parser_type = PARSE_LINUX;
      break;
    default:
      cerr << "unknown option!\n";
      assert(0);
    }
  }

  if(argc - optind == 2) {
    data_home.addr = inet_addr(argv[optind]);
    data_home.port = atoi(argv[optind + 1]);
  } else {
    // fallback: Get location from env vars
    if(NQ_getenv_server(&data_home) != 0) {
      exit_usage();
    }
  }

  create_host_principal();

  NQ_publish_principal(host_principal, 
		       (NQ_Host_as_string(NQ_Net_get_localhost()) + "-exporter").c_str() );

  // xxx how to explore netcomp
  // /env/default_ip_switch == port number

  //// Enumerate all ports
  // /ipds/user_terms/ports
  Transaction *t = new Transaction(trust_all, trust_attrval_all, data_home, host_principal);
  Host *host = new Host(*t);
#ifdef __LINUX__
  host->composite_element->common_name = "Linux host";
#else
  host->composite_element->common_name = "Nexus host";
#endif

  switch(g_parser_type) {
  case PARSE_NEXUS: {
#ifdef __NEXUS__
    string prefix("/");
#else
    string prefix("/local/ashieh/fake-terms/");
#endif
    ExtRef<T_ProcessList> process_list_ref = ExtRefOf(host->process_list);
    Set<X_IPD, ExtRef<T_ProcessList> > *ipds;
    ipds = new Set<X_IPD, ExtRef<T_ProcessList> >(&all_translators, prefix + string("ipds"), &process_list_ref);
    // initial state needs to be done in current transaction
    break;
  }
  case PARSE_LINUX: {
    cerr << "Nothing exported beyond the host information (e.g. the local interfaces)\n";
    break;
  }
  }

  NQ_Host localhost = NQ_Net_get_localhost();
  cerr << "Setting endpoint to " << localhost.addr << "\n";
  host->tcp_endpoint->id = IP_TCP(localhost.addr, 0);
  write_host_labels(t, host);
  all_translators.run_all(t);
  t->commit();
 
  NQ_export_host_tid(host);
}
