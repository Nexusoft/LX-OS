#ifndef COMMON_H
#define COMMON_H 

#define MIN(a,b) ({typeof(a) _a=(a); typeof(b) _b=(b); _a<_b?_a:_b;})
#define MAX(a,b) ({typeof(a) _a=(a); typeof(b) _b=(b); _a>_b?_a:_b;})

#define ABS(n) ({typeof(n) _n=(n); _n<0?-_n:_n;})
#define SWAP(a,b) do{typeof(a) _t=(a); (a)=(b); (b)=_t;}while(0)

#define PING() printf("(%d)", __LINE__)

#ifdef __cplusplus

std::string filter_host_port_pair(unsigned int ip, unsigned int port);
std::string ip2str(unsigned int ip);
std::string int2str(int num);
void *offset(void *ptr, int off);
void print_ip(int i, int swaporder);
void fwrite_ip(int i, int swaporder, FILE *f);

template <class T, int C> struct Preallocator {
 public:
  Preallocator() : preallocated(NULL) {}
  
  union ItemLink {
    T item;
    ItemLink *ptr;
  };
  
  T *create(void){
    if(preallocated == NULL){
      preallocated = new ItemLink[C];
      bzero(preallocated, sizeof(Preallocator::ItemLink) * C);
      for(int i = 0; i < C-1; i++){
        preallocated[i].ptr = &(preallocated[i+1]);
      }
    }
    ItemLink *ret = preallocated;
    preallocated = preallocated->ptr;
    ret->ptr = NULL;
    return &ret->item;
  }
  void destroy(T *item){
    ItemLink *myitem = (ItemLink *)item;
    bzero(myitem, sizeof(Preallocator::Item));
    myitem->ptr = preallocated;
    preallocated = myitem;
  }
  
 protected:
  ItemLink *preallocated;
};

#ifndef NOT_NEXUS
struct timeval start_profile(int profiler);
unsigned int stop_profile(struct timeval time);
unsigned int write_profile(char *fname);
#else
struct timeval start_profile();
unsigned int stop_profile(struct timeval time);
#endif

#endif

#endif
